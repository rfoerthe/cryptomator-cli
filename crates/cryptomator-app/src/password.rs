//! Passphrase sources for the CLI. Order: --password-stdin (one line) → --password-file → --password-env VAR
//! → $CRYPTO_PASSWORD → interactive prompt (only when stdin is a terminal). Passphrases are NFC-normalised
//! like the desktop app's `SecurePasswordField`.
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

fn read_password_file(path: &Path, label: &str) -> Result<Zeroizing<String>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_PASSWORD_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PASSWORD_FILE_BYTES {
        return Err(AppError::InvalidValue {
            key: format!("{label}-file"),
            message: format!("file is larger than {MAX_PASSWORD_FILE_BYTES} bytes"),
        });
    }
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| AppError::InvalidValue {
        key: format!("{label}-file"),
        message: "file is not valid UTF-8".to_string(),
    })?;
    Ok(Zeroizing::new(strip_line_ending(text)))
}

fn read_raw(
    args: &PasswordArgs,
    prompt: &str,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    if args.password_stdin {
        return io
            .read_stdin_line()?
            .map(|line| Zeroizing::new(strip_line_ending(line)))
            .ok_or(AppError::NoPasswordSource);
    }
    if let Some(file) = &args.password_file {
        return read_password_file(file, args.label);
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
    if let Some(value) = io.env(PASSWORD_ENV) {
        return Ok(Zeroizing::new(value));
    }
    io.prompt(prompt)?
        .map(Zeroizing::new)
        .ok_or(AppError::NoPasswordSource)
}

pub fn read_passphrase(
    args: &PasswordArgs,
    prompt: &str,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    let raw = read_raw(args, prompt, io)?;
    Ok(normalize_passphrase(&raw))
}

/// For new passwords: interactive input is asked twice and compared; every source enforces `min_len` characters.
pub fn read_new_passphrase(
    args: &PasswordArgs,
    prompt: &str,
    min_len: usize,
    io: &mut dyn PasswordIo,
) -> Result<Zeroizing<String>> {
    let interactive = !args.password_stdin
        && args.password_file.is_none()
        && args.password_env.is_none()
        && io.env(PASSWORD_ENV).is_none();
    let passphrase = read_passphrase(args, prompt, io)?;
    if passphrase.chars().count() < min_len {
        return Err(AppError::PasswordTooShort(min_len));
    }
    if interactive {
        let confirmation = io
            .prompt("Confirm password: ")?
            .map(|c| normalize_passphrase(&Zeroizing::new(c)))
            .ok_or(AppError::NoPasswordSource)?;
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
            Err(AppError::NoPasswordSource)
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
            Err(AppError::NoPasswordSource)
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
