//! Passphrase sources for the CLI. `--password-keychain` is exclusive and checked first, ahead of
//! every other source; without it, the order is --password-stdin (one line) → --password-file →
//! --password-env VAR → $CRYPTO_PASSWORD → the keychain implicitly → interactive prompt (only when
//! stdin is a terminal). Passphrases are NFC-normalised like the desktop app's `SecurePasswordField`.
//! `read_new_passphrase_no_env_fallback` drops the $CRYPTO_PASSWORD step for callers where that
//! variable already holds a different password; the two keychain steps exist only in
//! [`read_passphrase_with_keychain`], because a *new* password never comes out of a keychain.
use crate::error::{AppError, Result};
use clap::Args;
use std::io::{BufRead, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const PASSWORD_ENV: &str = "CRYPTO_PASSWORD";
pub const MIN_PW_LENGTH_ENV: &str = "CRYPTO_MIN_PW_LENGTH";
pub const DEFAULT_MIN_PW_LENGTH: usize = 8;
pub const MAX_PASSWORD_FILE_BYTES: u64 = 5000;

#[derive(Args, Debug, Clone)]
pub struct PasswordArgs {
    /// Read the password from the next line of standard input
    #[arg(long, group = "password-source")]
    pub password_stdin: bool,
    /// Read the password from a file (at most 5000 bytes; one trailing newline is removed)
    #[arg(long, value_name = "FILE", group = "password-source")]
    pub password_file: Option<PathBuf>,
    /// Read the password from the named environment variable (default: CRYPTO_PASSWORD)
    #[arg(long, value_name = "VAR", group = "password-source")]
    pub password_env: Option<String>,
    /// Take the password from the keychain and nowhere else (fails when nothing is stored)
    #[arg(long, group = "password-source")]
    pub password_keychain: bool,
    /// Flag prefix used in error messages, so a `NewPasswordArgs` conversion names `--new-password-*`.
    #[arg(skip = "--password")]
    pub label: &'static str,
}

impl Default for PasswordArgs {
    fn default() -> Self {
        Self {
            password_stdin: false,
            password_file: None,
            password_env: None,
            password_keychain: false,
            label: "--password",
        }
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct NewPasswordArgs {
    /// Read the new password from the next line of standard input
    #[arg(long, group = "new-password-source")]
    pub new_password_stdin: bool,
    /// Read the new password from a file
    #[arg(long, value_name = "FILE", group = "new-password-source")]
    pub new_password_file: Option<PathBuf>,
    /// Read the new password from the named environment variable
    #[arg(long, value_name = "VAR", group = "new-password-source")]
    pub new_password_env: Option<String>,
}

impl From<&NewPasswordArgs> for PasswordArgs {
    fn from(args: &NewPasswordArgs) -> Self {
        Self {
            password_stdin: args.new_password_stdin,
            password_file: args.new_password_file.clone(),
            password_env: args.new_password_env.clone(),
            // A *new* password is never read from the keychain: it is the one being invented.
            password_keychain: false,
            label: "--new-password",
        }
    }
}

/// Abstraction over stdin, environment and terminal prompting so the resolution logic is testable.
pub trait PasswordIo {
    /// One line of stdin including its line ending; `None` at EOF.
    fn read_stdin_line(&mut self) -> std::io::Result<Option<String>>;
    fn env(&self, name: &str) -> Option<String>;
    /// `None` when not interactive.
    fn prompt(&mut self, prompt: &str) -> std::io::Result<Option<String>>;
}

#[derive(Debug, Default)]
pub struct SystemIo;

impl PasswordIo for SystemIo {
    fn read_stdin_line(&mut self) -> std::io::Result<Option<String>> {
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line)?;
        Ok((read > 0).then_some(line))
    }

    fn env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn prompt(&mut self, prompt: &str) -> std::io::Result<Option<String>> {
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }
        rpassword::prompt_password(prompt).map(Some)
    }
}

pub fn normalize_passphrase(raw: &str) -> Zeroizing<String> {
    Zeroizing::new(raw.nfc().collect())
}

/// The canonical **decomposition** (NFD) of `raw` -- the other half of the pair, and the form a
/// vault of format 5 may have been created with.
///
/// Every passphrase this module hands out is NFC, because that is what the desktop app's
/// `SecurePasswordField` produces and what every vault of format 6 and later is wrapped with.
/// Format 5 predates that rule: Cryptomator 1.3 wrapped the masterkey with the characters the
/// operating system put into the password field, which on macOS is NFD -- and format 6 is exactly
/// the migration step that normalised it. `crypto migrate` therefore needs to be able to ask for
/// the decomposed form of what the user typed; nothing else does.
pub fn decompose_passphrase(raw: &str) -> Zeroizing<String> {
    Zeroizing::new(raw.nfd().collect())
}

fn strip_line_ending(mut line: String) -> String {
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    line
}

/// Reads a secret from a file: at most [`MAX_PASSWORD_FILE_BYTES`], valid UTF-8, one trailing line
/// ending removed. `key` names the flag the file came from, so violations surface as a usage error.
pub fn read_secret_file(path: &Path, key: &str) -> Result<Zeroizing<String>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_PASSWORD_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PASSWORD_FILE_BYTES {
        return Err(AppError::InvalidValue {
            key: key.to_string(),
            message: format!("file is larger than {MAX_PASSWORD_FILE_BYTES} bytes"),
        });
    }
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| AppError::InvalidValue {
        key: key.to_string(),
        message: "file is not valid UTF-8".to_string(),
    })?;
    Ok(Zeroizing::new(strip_line_ending(text)))
}

/// Whether `$CRYPTO_PASSWORD` may act as the implicit source when no explicit flag is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultEnv {
    Allowed,
    /// `password change`: the variable already supplied the *current* password, so letting it
    /// supply the new one too would silently keep the old password.
    Denied,
}

impl DefaultEnv {
    /// The `env_fallback` flag of [`AppError::NoPasswordSource`]: does `$CRYPTO_PASSWORD` count here?
    fn is_allowed(self) -> bool {
        self == DefaultEnv::Allowed
    }
}

/// The "no source left" error for this passphrase position, naming the flags that would work.
fn no_source(args: &PasswordArgs, default_env: DefaultEnv) -> AppError {
    AppError::NoPasswordSource {
        label: args.label,
        env_fallback: default_env.is_allowed(),
    }
}

/// Steps 1-4 of the source order: the explicit flags and `$CRYPTO_PASSWORD`. `Ok(None)` means
/// "none of them applies" -- the caller decides what comes next, which is the prompt for
/// [`read_raw`] and the keychain for [`read_passphrase_with_keychain`].
fn read_raw_without_prompt(
    args: &PasswordArgs,
    default_env: DefaultEnv,
    io: &mut dyn PasswordIo,
) -> Result<Option<Zeroizing<String>>> {
    if args.password_stdin {
        return io
            .read_stdin_line()?
            .map(|line| Zeroizing::new(strip_line_ending(line)))
            .map(Some)
            .ok_or_else(|| no_source(args, default_env));
    }
    if let Some(file) = &args.password_file {
        return read_secret_file(file, &format!("{}-file", args.label)).map(Some);
    }
    if let Some(var) = &args.password_env {
        return io
            .env(var)
            .map(Zeroizing::new)
            .map(Some)
            .ok_or_else(|| AppError::InvalidValue {
                key: format!("{}-env", args.label),
                message: format!("environment variable {var} is not set"),
            });
    }
    if default_env == DefaultEnv::Allowed {
        if let Some(value) = io.env(PASSWORD_ENV) {
            return Ok(Some(Zeroizing::new(value)));
        }
    }
    Ok(None)
}

fn read_raw(
    args: &PasswordArgs,
    prompt: &str,
    default_env: DefaultEnv,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    if let Some(raw) = read_raw_without_prompt(args, default_env, io)? {
        return Ok(raw);
    }
    io.prompt(prompt)?
        .map(Zeroizing::new)
        .ok_or_else(|| no_source(args, default_env))
}

/// The keychain half of the passphrase resolution: which provider, for which vault, under which
/// name in the error message.
///
/// The provider is an `Arc` rather than a borrow because every call goes through
/// [`crate::keychain::call`], which moves it onto a worker thread the CLI may stop waiting for.
#[derive(Debug, Clone)]
pub struct KeychainSource<'a> {
    pub keychain: Arc<dyn crate::keychain::Keychain>,
    /// The vault id -- the key the desktop app stores under.
    pub key: &'a str,
    /// The vault's display name (or its id), for the "nothing stored for …" message.
    pub vault_label: &'a str,
}

impl KeychainSource<'_> {
    /// One `load`, under [`crate::keychain::KEYCHAIN_TIMEOUT`]. `Ok(None)` is "nothing stored".
    fn load(&self) -> crate::keychain::KeychainResult<Option<Zeroizing<String>>> {
        // The closure has to be `'static` for the worker thread, so the key is copied in. It is a
        // vault id, not a secret.
        let key = self.key.to_string();
        crate::keychain::call(&self.keychain, move |keychain| keychain.load(&key))
    }

    fn provider(&self) -> &str {
        self.keychain.display_name()
    }
}

/// [`read_passphrase`] with the two keychain steps of the source order.
///
/// `--password-keychain` is the exclusive source: when it is given, it pre-empts every other
/// step below and nothing else is consulted -- a missing entry is
/// [`AppError::KeychainNoEntry`] (exit code 8), never a fall-through to the prompt.
///
/// Without that flag, the order is, first present source wins:
/// 1. `--password-stdin`
/// 2. `--password-file`
/// 3. `--password-env VAR`
/// 4. `$CRYPTO_PASSWORD`
/// 5. the keychain implicitly, when `source()` answers `Some` (i.e. `useKeychain` is on, a
///    provider is supported and `--no-keychain` was not given) **and** an entry exists
/// 6. the interactive prompt
///
/// `$CRYPTO_PASSWORD` deliberately outranks the implicit keychain step: it is the source a script
/// sets on purpose, and it can never open a dialog.
///
/// The implicit step falls through to the prompt for "nothing stored" and for a provider that
/// turns out to be unusable here ([`crate::keychain::KeychainError::Unsupported`]) -- both are
/// indistinguishable from having no keychain at all. Every *other* failure -- a locked keyring, a
/// refused or unanswered dialog, a backend that broke -- is reported (exit code 8) instead:
/// prompting would hide a real problem behind a password the user then has to type by hand.
///
/// `source` is a closure rather than an already-resolved `Option<KeychainSource>`: choosing a
/// keychain provider probes every candidate (`KEYCHAIN_PROBE_TIMEOUT` each on a platform without
/// one built in, e.g. a Secret Service D-Bus connect on Linux), so a caller whose own source
/// answers first -- `--password-stdin` and friends -- must not pay for a provider it will never
/// ask. `source` is therefore called at most once, only when step 1 (`--password-keychain`, if
/// given) or the implicit step 5 is actually reached.
///
/// # Errors
/// [`AppError::KeychainNoEntry`] / [`AppError::Keychain`] (exit code 8) for the keychain steps,
/// [`AppError::NoPasswordSource`] (2) when nothing is left. Whatever `source` itself reports.
pub fn read_passphrase_with_keychain<'a>(
    args: &PasswordArgs,
    prompt: &str,
    source: impl FnOnce() -> Result<Option<KeychainSource<'a>>>,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    if args.password_keychain {
        let Some(source) = source()? else {
            return Err(AppError::Keychain(
                crate::keychain::KeychainError::Unsupported {
                    provider: "keychain".to_string(),
                    hint: "--password-keychain was given, but no keychain is in use here \
                           (--no-keychain, useKeychain=false, or no supported provider)"
                        .to_string(),
                },
            ));
        };
        return match source.load()? {
            Some(passphrase) => Ok(normalize_passphrase(&passphrase)),
            None => Err(AppError::KeychainNoEntry {
                vault: source.vault_label.to_string(),
                provider: source.provider().to_string(),
            }),
        };
    }
    // Everything that is not the keychain, minus the prompt: the prompt is step 6 and has to stay
    // *after* the implicit keychain step.
    if let Some(raw) = read_raw_without_prompt(args, DefaultEnv::Allowed, io)? {
        return Ok(normalize_passphrase(&raw));
    }
    if let Some(source) = source()? {
        match source.load() {
            Ok(Some(passphrase)) => {
                // Not printed: a silent unlock is the point of storing the password. The log line
                // names the vault, never the passphrase.
                log::info!("using the stored password for {}", source.vault_label);
                return Ok(normalize_passphrase(&passphrase));
            }
            // Nothing stored: the ordinary case for a vault whose password was never saved.
            Ok(None) => {}
            // "There is no keychain here after all" -- the same situation as `source` answering
            // `None`.
            Err(err @ crate::keychain::KeychainError::Unsupported { .. }) => {
                log::debug!("no keychain to ask for {}: {err}", source.vault_label);
            }
            Err(err) => return Err(AppError::Keychain(err)),
        }
    }
    io.prompt(prompt)?
        .map(|typed| normalize_passphrase(&Zeroizing::new(typed)))
        .ok_or_else(|| no_source(args, DefaultEnv::Allowed))
}

/// [`read_passphrase_with_keychain`] for the callers that have no keychain to offer -- the daemon,
/// and any command run with `--no-keychain`. `--password-keychain` is then the exit-code-8 error
/// [`read_passphrase_with_keychain`] gives it, never a silently ignored flag.
pub fn read_passphrase(
    args: &PasswordArgs,
    prompt: &str,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    read_passphrase_with_keychain(args, prompt, || Ok(None), io)
}

/// For new passwords: interactive input is asked twice and compared; every source enforces `min_len` characters.
pub fn read_new_passphrase(
    args: &PasswordArgs,
    prompt: &str,
    min_len: usize,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    read_new(args, prompt, min_len, DefaultEnv::Allowed, io)
}

/// Like [`read_new_passphrase`], but `$CRYPTO_PASSWORD` is *not* a source: without an explicit
/// `--new-password-*` flag the passphrase is typed at the prompt (and [`AppError::NoPasswordSource`]
/// without a terminal). Used by `password change`, where the variable holds the current password.
pub fn read_new_passphrase_no_env_fallback(
    args: &PasswordArgs,
    prompt: &str,
    min_len: usize,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    read_new(args, prompt, min_len, DefaultEnv::Denied, io)
}

fn read_new(
    args: &PasswordArgs,
    prompt: &str,
    min_len: usize,
    default_env: DefaultEnv,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    // `vault create` flattens a whole `PasswordArgs`, so clap accepts `--password-keychain` there
    // too. A *new* password is the one being invented; taking it from the keychain is meaningless,
    // and silently ignoring the flag would create the vault with a password the user never chose.
    if args.password_keychain {
        // Not `format!("{}-keychain", args.label)`: for `--new-password-*` callers `args.label` is
        // `--new-password`, but clap only ever defines `--password-keychain` (see
        // `PasswordArgs::password_keychain`'s `#[arg(long, …)]`) -- there is no
        // `--new-password-keychain` to name. Unreachable today (`From<&NewPasswordArgs>` always
        // sets `password_keychain: false`), so this only has to be honest, not exercised.
        return Err(AppError::InvalidValue {
            key: "--password-keychain".to_string(),
            message: "a new password cannot be read from the keychain".to_string(),
        });
    }
    let no_explicit_source =
        !args.password_stdin && args.password_file.is_none() && args.password_env.is_none();
    let interactive =
        no_explicit_source && (default_env == DefaultEnv::Denied || io.env(PASSWORD_ENV).is_none());
    let raw = read_raw(args, prompt, default_env, io)?;
    let passphrase = normalize_passphrase(&raw);
    if passphrase.chars().count() < min_len {
        return Err(AppError::PasswordTooShort(min_len));
    }
    if interactive {
        let confirmation = io
            .prompt("Confirm password: ")?
            .map(|c| normalize_passphrase(&Zeroizing::new(c)))
            .ok_or_else(|| no_source(args, default_env))?;
        if *confirmation != *passphrase {
            return Err(AppError::PasswordMismatch);
        }
    }
    Ok(passphrase)
}

/// `cryptomator.minPwLength` (default 8), overridable with `CRYPTO_MIN_PW_LENGTH`.
pub fn min_password_length() -> usize {
    std::env::var(MIN_PW_LENGTH_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MIN_PW_LENGTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    #[derive(Default)]
    struct FakeIo {
        stdin: VecDeque<String>,
        env: HashMap<String, String>,
        prompts: Option<VecDeque<String>>,
        prompted: Vec<String>,
    }

    impl PasswordIo for FakeIo {
        fn read_stdin_line(&mut self) -> std::io::Result<Option<String>> {
            Ok(self.stdin.pop_front())
        }
        fn env(&self, name: &str) -> Option<String> {
            self.env.get(name).cloned()
        }
        fn prompt(&mut self, prompt: &str) -> std::io::Result<Option<String>> {
            self.prompted.push(prompt.to_string());
            Ok(self.prompts.as_mut().and_then(|p| p.pop_front()))
        }
    }

    fn args(stdin: bool, file: Option<&Path>, env: Option<&str>) -> PasswordArgs {
        PasswordArgs {
            password_stdin: stdin,
            password_file: file.map(Path::to_path_buf),
            password_env: env.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn stdin_source_reads_one_line_without_line_ending() {
        let mut io = FakeIo {
            stdin: VecDeque::from(["first\r\n".to_string(), "second\n".to_string()]),
            ..Default::default()
        };
        assert_eq!(
            *read_passphrase(&args(true, None, None), "p", &mut io).unwrap(),
            "first"
        );
        assert_eq!(
            *read_passphrase(&args(true, None, None), "p", &mut io).unwrap(),
            "second"
        );
        assert!(matches!(
            read_passphrase(&args(true, None, None), "p", &mut io),
            Err(AppError::NoPasswordSource { .. })
        ));
        assert!(io.prompted.is_empty());
    }

    #[test]
    fn file_source_strips_one_trailing_newline_and_normalizes_nfc() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pw");
        std::fs::write(&file, "cafe\u{0301}\n\n").unwrap();
        let mut io = FakeIo::default();
        let pw = read_passphrase(&args(false, Some(&file), None), "p", &mut io).unwrap();
        assert_eq!(
            *pw, "caf\u{00E9}\n",
            "only one newline stripped, NFD composed to NFC"
        );
        std::fs::write(&file, vec![b'a'; MAX_PASSWORD_FILE_BYTES as usize + 1]).unwrap();
        assert!(matches!(
            read_passphrase(&args(false, Some(&file), None), "p", &mut io),
            Err(AppError::InvalidValue { .. })
        ));
    }

    #[test]
    fn env_sources_and_precedence() {
        let mut io = FakeIo {
            env: HashMap::from([
                ("MY_PW".to_string(), "from-var".to_string()),
                (PASSWORD_ENV.to_string(), "from-default".to_string()),
            ]),
            stdin: VecDeque::from(["from-stdin".to_string()]),
            ..Default::default()
        };
        assert_eq!(
            *read_passphrase(&args(false, None, Some("MY_PW")), "p", &mut io).unwrap(),
            "from-var"
        );
        assert_eq!(
            *read_passphrase(&args(false, None, None), "p", &mut io).unwrap(),
            "from-default"
        );
        assert_eq!(
            *read_passphrase(&args(true, None, None), "p", &mut io).unwrap(),
            "from-stdin"
        );
        assert!(matches!(
            read_passphrase(&args(false, None, Some("MISSING")), "p", &mut io),
            Err(AppError::InvalidValue { .. })
        ));
    }

    #[test]
    fn interactive_prompt_is_the_last_resort() {
        let mut io = FakeIo {
            prompts: Some(VecDeque::from(["typed".to_string()])),
            ..Default::default()
        };
        assert_eq!(
            *read_passphrase(&args(false, None, None), "Password: ", &mut io).unwrap(),
            "typed"
        );
        assert_eq!(io.prompted, vec!["Password: ".to_string()]);
        let mut no_tty = FakeIo::default();
        assert!(matches!(
            read_passphrase(&args(false, None, None), "p", &mut no_tty),
            Err(AppError::NoPasswordSource { .. })
        ));
    }

    #[test]
    fn new_passphrase_enforces_length_and_confirmation() {
        let mut io = FakeIo {
            env: HashMap::from([(PASSWORD_ENV.to_string(), "short".to_string())]),
            ..Default::default()
        };
        assert!(matches!(
            read_new_passphrase(&args(false, None, None), "p", 8, &mut io),
            Err(AppError::PasswordTooShort(8))
        ));
        let mut io = FakeIo {
            prompts: Some(VecDeque::from([
                "long-enough-1".to_string(),
                "long-enough-1".to_string(),
            ])),
            ..Default::default()
        };
        assert_eq!(
            *read_new_passphrase(&args(false, None, None), "New password: ", 8, &mut io).unwrap(),
            "long-enough-1"
        );
        assert_eq!(io.prompted.len(), 2);
        let mut io = FakeIo {
            prompts: Some(VecDeque::from([
                "long-enough-1".to_string(),
                "different-123".to_string(),
            ])),
            ..Default::default()
        };
        assert!(matches!(
            read_new_passphrase(&args(false, None, None), "p", 8, &mut io),
            Err(AppError::PasswordMismatch)
        ));
    }

    #[test]
    fn new_passphrase_without_env_fallback_prompts_instead_of_reusing_crypto_password() {
        // `password change`: CRYPTO_PASSWORD already supplied the *current* password, so it must
        // not silently become the new one.
        let mut io = FakeIo {
            env: HashMap::from([(PASSWORD_ENV.to_string(), "current-passphrase".to_string())]),
            prompts: Some(VecDeque::from([
                "typed-new-passphrase".to_string(),
                "typed-new-passphrase".to_string(),
            ])),
            ..Default::default()
        };
        assert_eq!(
            *read_new_passphrase_no_env_fallback(
                &args(false, None, None),
                "New password: ",
                8,
                &mut io
            )
            .unwrap(),
            "typed-new-passphrase"
        );
        assert_eq!(io.prompted, vec!["New password: ", "Confirm password: "]);

        // Without a terminal there is no source at all – nothing is written.
        let mut no_tty = FakeIo {
            env: HashMap::from([(PASSWORD_ENV.to_string(), "current-passphrase".to_string())]),
            ..Default::default()
        };
        assert!(matches!(
            read_new_passphrase_no_env_fallback(&args(false, None, None), "p", 8, &mut no_tty),
            Err(AppError::NoPasswordSource { .. })
        ));

        // Explicit flags keep working, and `read_new_passphrase` keeps the env fallback.
        let mut explicit = FakeIo {
            env: HashMap::from([
                (PASSWORD_ENV.to_string(), "current-passphrase".to_string()),
                ("NEW_PW".to_string(), "explicit-passphrase".to_string()),
            ]),
            ..Default::default()
        };
        assert_eq!(
            *read_new_passphrase_no_env_fallback(
                &args(false, None, Some("NEW_PW")),
                "p",
                8,
                &mut explicit
            )
            .unwrap(),
            "explicit-passphrase"
        );
        assert_eq!(
            *read_new_passphrase(&args(false, None, None), "p", 8, &mut explicit).unwrap(),
            "current-passphrase"
        );
        assert!(explicit.prompted.is_empty());
    }

    #[test]
    fn no_password_source_message_depends_on_the_position() {
        // Current password: $CRYPTO_PASSWORD is one of the sources, and so is --password-keychain.
        let mut no_tty = FakeIo::default();
        let err = read_passphrase(&args(false, None, None), "p", &mut no_tty).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(
                "--password-stdin, --password-file, --password-env or --password-keychain"
            ),
            "{message}"
        );
        assert!(message.contains(&format!("set {PASSWORD_ENV}")));

        // New password of `password change`: the variable holds the *current* password, and there
        // is no `--new-password-keychain` -- a new password is never read from the keychain.
        let new_args = PasswordArgs::from(&NewPasswordArgs::default());
        let mut with_env = FakeIo {
            env: HashMap::from([(PASSWORD_ENV.to_string(), "current-passphrase".to_string())]),
            ..Default::default()
        };
        let err =
            read_new_passphrase_no_env_fallback(&new_args, "p", 8, &mut with_env).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("--new-password-stdin, --new-password-file or --new-password-env"),
            "{message}"
        );
        assert!(
            !message.contains("keychain"),
            "a new password has no keychain flag to name: {message}"
        );
        assert!(
            message.contains(&format!(
                "{PASSWORD_ENV} supplies only the current password"
            )),
            "{message}"
        );
        assert!(
            !message.contains(&format!("set {PASSWORD_ENV}")),
            "{message}"
        );
    }

    #[test]
    fn new_password_args_convert() {
        let new = NewPasswordArgs {
            new_password_stdin: true,
            new_password_file: None,
            new_password_env: Some("X".into()),
        };
        let converted = PasswordArgs::from(&new);
        assert!(converted.password_stdin);
        assert_eq!(converted.password_env.as_deref(), Some("X"));
        assert_eq!(converted.label, "--new-password");
    }

    #[test]
    fn password_groups_are_mutually_exclusive() {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            pw: PasswordArgs,
            #[command(flatten)]
            new: NewPasswordArgs,
        }
        use clap::{CommandFactory, Parser};
        Cli::command().debug_assert();
        assert!(Cli::try_parse_from(["x", "--password-stdin", "--password-env", "V"]).is_err());
        assert!(
            Cli::try_parse_from(["x", "--new-password-stdin", "--new-password-file", "f"]).is_err()
        );
        assert!(Cli::try_parse_from(["x", "--password-stdin", "--new-password-env", "V"]).is_ok());
    }

    /// A keychain that answers from memory, so the source order can be tested without any I/O.
    #[derive(Debug, Default)]
    struct MemKeychain {
        entries: std::sync::Mutex<HashMap<String, String>>,
        fail: Option<crate::keychain::KeychainError>,
    }

    impl MemKeychain {
        fn with(key: &str, passphrase: &str) -> Self {
            let entries = HashMap::from([(key.to_string(), passphrase.to_string())]);
            Self {
                entries: std::sync::Mutex::new(entries),
                fail: None,
            }
        }
        /// A provider that is not usable here at all -- the case that falls through to the prompt.
        fn unsupported() -> Self {
            Self {
                fail: Some(crate::keychain::KeychainError::Unsupported {
                    provider: "Mem".to_string(),
                    hint: "no keyring here".to_string(),
                }),
                ..Default::default()
            }
        }
        /// A keyring that is there but refuses to answer -- the case that must not be hidden.
        fn locked() -> Self {
            Self {
                fail: Some(crate::keychain::KeychainError::Locked {
                    provider: "Mem".to_string(),
                }),
                ..Default::default()
            }
        }
        fn check(&self) -> crate::keychain::KeychainResult<()> {
            match &self.fail {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }
    }

    impl crate::keychain::Keychain for MemKeychain {
        fn java_class_name(&self) -> &'static str {
            "org.example.Mem"
        }
        fn display_name(&self) -> &'static str {
            "Mem"
        }
        fn priority(&self) -> u32 {
            1
        }
        fn is_supported(&self) -> bool {
            self.fail.is_none()
        }
        fn is_locked(&self) -> bool {
            false
        }
        fn store(
            &self,
            key: &str,
            _n: Option<&str>,
            pw: &str,
        ) -> crate::keychain::KeychainResult<()> {
            self.check()?;
            self.entries
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key.to_string(), pw.to_string());
            Ok(())
        }
        fn load(&self, key: &str) -> crate::keychain::KeychainResult<Option<Zeroizing<String>>> {
            self.check()?;
            Ok(self
                .entries
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(key)
                .map(|pw| Zeroizing::new(pw.clone())))
        }
        fn delete(&self, key: &str) -> crate::keychain::KeychainResult<bool> {
            self.check()?;
            Ok(self
                .entries
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(key)
                .is_some())
        }
        fn change(
            &self,
            key: &str,
            n: Option<&str>,
            pw: &str,
        ) -> crate::keychain::KeychainResult<bool> {
            if self.load(key)?.is_none() {
                return Ok(false);
            }
            self.store(key, n, pw)?;
            Ok(true)
        }
    }

    fn source(keychain: MemKeychain) -> KeychainSource<'static> {
        KeychainSource {
            keychain: Arc::new(keychain),
            key: "v1",
            vault_label: "Secret",
        }
    }

    #[test]
    fn the_keychain_is_used_when_nothing_else_supplies_a_password() {
        let mut io = FakeIo::default();
        assert_eq!(
            *read_passphrase_with_keychain(
                &args(false, None, None),
                "Password: ",
                || Ok(Some(source(MemKeychain::with("v1", "from-keychain")))),
                &mut io
            )
            .unwrap(),
            "from-keychain"
        );
        assert!(
            io.prompted.is_empty(),
            "no prompt when the keychain answered"
        );
    }

    #[test]
    fn the_keychain_source_is_never_probed_when_password_stdin_supplies_the_answer() {
        // The whole point of the lazy closure: a caller whose own source answers first must not
        // pay for choosing a keychain provider, which can be a real probe (Secret Service D-Bus
        // on Linux) rather than a free call.
        let mut io = FakeIo {
            stdin: VecDeque::from(["from-stdin\n".to_string()]),
            ..Default::default()
        };
        let probed = std::cell::Cell::new(false);
        let result = read_passphrase_with_keychain(
            &args(true, None, None),
            "p",
            || {
                probed.set(true);
                Ok(Some(source(MemKeychain::with("v1", "from-keychain"))))
            },
            &mut io,
        )
        .unwrap();
        assert_eq!(*result, "from-stdin");
        assert!(
            !probed.get(),
            "the keychain source closure must not run when --password-stdin already answered"
        );
    }

    #[test]
    fn an_explicit_flag_and_crypto_password_both_beat_the_keychain() {
        // Flag wins.
        let mut io = FakeIo {
            stdin: VecDeque::from(["from-stdin\n".to_string()]),
            ..Default::default()
        };
        assert_eq!(
            *read_passphrase_with_keychain(
                &args(true, None, None),
                "p",
                || Ok(Some(source(MemKeychain::with("v1", "from-keychain")))),
                &mut io
            )
            .unwrap(),
            "from-stdin"
        );
        // $CRYPTO_PASSWORD wins too -- it sits *above* the keychain in the order, because it
        // never opens a dialog.
        let mut io = FakeIo {
            env: HashMap::from([(PASSWORD_ENV.to_string(), "from-env".to_string())]),
            ..Default::default()
        };
        assert_eq!(
            *read_passphrase_with_keychain(
                &args(false, None, None),
                "p",
                || Ok(Some(source(MemKeychain::with("v1", "from-keychain")))),
                &mut io
            )
            .unwrap(),
            "from-env"
        );
        // `--password-keychain` beats even $CRYPTO_PASSWORD: it is the exclusive source and
        // pre-empts every other step, not merely the highest-priority one among them.
        let mut io = FakeIo {
            env: HashMap::from([(PASSWORD_ENV.to_string(), "from-env".to_string())]),
            ..Default::default()
        };
        let mut explicit = args(false, None, None);
        explicit.password_keychain = true;
        assert_eq!(
            *read_passphrase_with_keychain(
                &explicit,
                "p",
                || Ok(Some(source(MemKeychain::with("v1", "from-keychain")))),
                &mut io
            )
            .unwrap(),
            "from-keychain"
        );
    }

    #[test]
    fn a_missing_entry_falls_through_to_the_prompt_but_password_keychain_does_not() {
        // Implicit: nothing stored, so the prompt takes over.
        let mut io = FakeIo {
            prompts: Some(VecDeque::from(["typed".to_string()])),
            ..Default::default()
        };
        assert_eq!(
            *read_passphrase_with_keychain(
                &args(false, None, None),
                "Password: ",
                || Ok(Some(source(MemKeychain::default()))),
                &mut io
            )
            .unwrap(),
            "typed"
        );
        // Explicit: the user asked for the keychain and only the keychain.
        let mut io = FakeIo {
            prompts: Some(VecDeque::from(["typed".to_string()])),
            ..Default::default()
        };
        let mut explicit = args(false, None, None);
        explicit.password_keychain = true;
        match read_passphrase_with_keychain(
            &explicit,
            "p",
            || Ok(Some(source(MemKeychain::default()))),
            &mut io,
        ) {
            Err(AppError::KeychainNoEntry { vault, provider }) => {
                assert_eq!(vault, "Secret");
                assert_eq!(provider, "Mem");
            }
            other => panic!("expected KeychainNoEntry, got {other:?}"),
        }
        assert!(io.prompted.is_empty(), "it must not fall through");
    }

    #[test]
    fn password_keychain_without_a_keychain_at_all_is_a_keychain_error() {
        // `--no-keychain --password-keychain`, or useKeychain=false: `source` is `None`.
        let mut explicit = args(false, None, None);
        explicit.password_keychain = true;
        let mut io = FakeIo::default();
        match read_passphrase_with_keychain(&explicit, "p", || Ok(None), &mut io) {
            Err(AppError::Keychain(err)) => {
                let text = err.to_string();
                assert!(
                    text.contains("useKeychain") || text.contains("--no-keychain"),
                    "{text}"
                );
            }
            other => panic!("expected a Keychain error, got {other:?}"),
        }
        // `read_passphrase` is the same call with no source, so the flag is an error there too
        // rather than a flag that is quietly ignored.
        let mut io = FakeIo::default();
        assert!(matches!(
            read_passphrase(&explicit, "p", &mut io),
            Err(AppError::Keychain(_))
        ));
    }

    #[test]
    fn an_unusable_provider_never_hides_the_prompt_but_a_locked_one_is_reported() {
        // "There is no keychain here after all" is the same situation as having none configured,
        // so the user still gets asked.
        let mut io = FakeIo {
            prompts: Some(VecDeque::from(["typed".to_string()])),
            ..Default::default()
        };
        assert_eq!(
            *read_passphrase_with_keychain(
                &args(false, None, None),
                "Password: ",
                || Ok(Some(source(MemKeychain::unsupported()))),
                &mut io
            )
            .unwrap(),
            "typed"
        );
        // A keyring that is *there* and refuses is a real problem: prompting would hide it.
        let mut io = FakeIo {
            prompts: Some(VecDeque::from(["typed".to_string()])),
            ..Default::default()
        };
        assert!(matches!(
            read_passphrase_with_keychain(
                &args(false, None, None),
                "p",
                || Ok(Some(source(MemKeychain::locked()))),
                &mut io
            ),
            Err(AppError::Keychain(
                crate::keychain::KeychainError::Locked { .. }
            ))
        ));
        assert!(io.prompted.is_empty(), "a locked keyring is not a prompt");
        // Explicitly asking an unusable keychain still fails, rather than falling back.
        let mut explicit = args(false, None, None);
        explicit.password_keychain = true;
        let mut io = FakeIo::default();
        assert!(matches!(
            read_passphrase_with_keychain(
                &explicit,
                "p",
                || Ok(Some(source(MemKeychain::unsupported()))),
                &mut io
            ),
            Err(AppError::Keychain(_))
        ));
    }

    #[test]
    fn a_new_password_is_never_read_from_the_keychain() {
        let mut new = args(false, None, None);
        new.password_keychain = true;
        let mut io = FakeIo::default();
        match read_new_passphrase(&new, "p", 8, &mut io) {
            Err(AppError::InvalidValue { key, .. }) => assert_eq!(key, "--password-keychain"),
            other => panic!("expected InvalidValue, got {other:?}"),
        }
        assert!(io.prompted.is_empty());
        // And the conversion from `NewPasswordArgs` never sets it in the first place.
        assert!(!PasswordArgs::from(&NewPasswordArgs::default()).password_keychain);
    }

    #[test]
    fn the_new_password_rejection_names_the_flag_that_actually_exists() {
        // `label` is "--new-password" at this position (`PasswordArgs::from(&NewPasswordArgs)`),
        // but clap only ever defines `--password-keychain` -- naming the flag via
        // `format!("{label}-keychain")` would claim a `--new-password-keychain` that does not
        // exist. `password_keychain` is never actually set by that conversion, so it is set by
        // hand here to reach the branch at all.
        let mut new = PasswordArgs::from(&NewPasswordArgs::default());
        new.password_keychain = true;
        let mut io = FakeIo::default();
        match read_new_passphrase(&new, "p", 8, &mut io) {
            Err(AppError::InvalidValue { key, .. }) => assert_eq!(key, "--password-keychain"),
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[test]
    fn password_keychain_is_in_the_same_exclusive_group_as_the_other_sources() {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            pw: PasswordArgs,
        }
        use clap::{CommandFactory, Parser};
        Cli::command().debug_assert();
        assert!(Cli::try_parse_from(["x", "--password-keychain"]).is_ok());
        assert!(Cli::try_parse_from(["x", "--password-keychain", "--password-stdin"]).is_err());
        assert!(Cli::try_parse_from(["x", "--password-keychain", "--password-env", "V"]).is_err());
    }

    #[test]
    fn new_password_errors_name_the_new_password_flags() {
        let args = PasswordArgs::from(&NewPasswordArgs {
            new_password_env: Some("MISSING".into()),
            ..Default::default()
        });
        let mut io = FakeIo::default();
        match read_passphrase(&args, "p", &mut io) {
            Err(AppError::InvalidValue { key, .. }) => assert_eq!(key, "--new-password-env"),
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }
}
