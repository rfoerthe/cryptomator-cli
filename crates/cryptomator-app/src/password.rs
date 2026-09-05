//! Passphrase sources for the CLI. Order: --password-stdin (one line) → --password-file → --password-env VAR
//! → $CRYPTO_PASSWORD → interactive prompt (only when stdin is a terminal). Passphrases are NFC-normalised
//! like the desktop app's `SecurePasswordField`. `read_new_passphrase_no_env_fallback` drops the
//! $CRYPTO_PASSWORD step for callers where that variable already holds a different password.
use crate::error::{AppError, Result};
use clap::Args;
use std::io::{BufRead, IsTerminal, Read};
use std::path::{Path, PathBuf};
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

fn read_raw(
    args: &PasswordArgs,
    prompt: &str,
    default_env: DefaultEnv,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    if args.password_stdin {
        return io
            .read_stdin_line()?
            .map(|line| Zeroizing::new(strip_line_ending(line)))
            .ok_or_else(|| no_source(args, default_env));
    }
    if let Some(file) = &args.password_file {
        return read_secret_file(file, &format!("{}-file", args.label));
    }
    if let Some(var) = &args.password_env {
        return io
            .env(var)
            .map(Zeroizing::new)
            .ok_or_else(|| AppError::InvalidValue {
                key: format!("{}-env", args.label),
                message: format!("environment variable {var} is not set"),
            });
    }
    if default_env == DefaultEnv::Allowed {
        if let Some(value) = io.env(PASSWORD_ENV) {
            return Ok(Zeroizing::new(value));
        }
    }
    io.prompt(prompt)?
        .map(Zeroizing::new)
        .ok_or_else(|| no_source(args, default_env))
}

pub fn read_passphrase(
    args: &PasswordArgs,
    prompt: &str,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    let raw = read_raw(args, prompt, DefaultEnv::Allowed, io)?;
    Ok(normalize_passphrase(&raw))
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
        // Current password: $CRYPTO_PASSWORD is one of the sources.
        let mut no_tty = FakeIo::default();
        let err = read_passphrase(&args(false, None, None), "p", &mut no_tty).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("--password-stdin, --password-file or --password-env"));
        assert!(message.contains(&format!("set {PASSWORD_ENV}")));

        // New password of `password change`: the variable holds the *current* password.
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
