//! The vault daemon's log file.
//!
//! A daemon is detached: it has no terminal to write to, and the only thing a user can look at
//! after a failed unlock is `<state-dir>/<vault-id>.log`. This module installs a [`log::Log`]
//! implementation that appends to that file, one line per record:
//!
//! ```text
//! 2026-09-06T10:00:00Z INFO cryptomator_app::daemon::server: mounted at /Users/me/mnt/Vault
//! ```
//!
//! The timestamp is UTC, formatted from [`SystemTime`] without a date library -- the workspace has
//! none, and the daemon needs exactly this one format.
//!
//! Nothing here ever logs a request payload; that rule lives at the call sites (see
//! [`crate::daemon::protocol::Request::op`], which names a request without its fields).
//!
//! The same module also carries the CLI's own logger. `log::set_boxed_logger` can be called only
//! once per process, and `crypto unlock --foreground` runs a daemon *inside* the CLI process --
//! so the two cannot each install one. [`init_stderr_logger`] therefore installs a delegating
//! logger whose target can be swapped, and [`init_file_logger`] swaps the file in behind it
//! instead of fighting over the one global slot.
use crate::error::Result;
use cryptomator_core::civil_utc;
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fs::{File, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// The mode of the log file: it names vault paths and mount points.
const FILE_MODE: u32 = 0o600;

/// The [`LevelFilter`] for a `cli.json` `logLevel` value; anything unknown is `info`.
pub fn level_filter(name: &str) -> LevelFilter {
    match name.trim().to_ascii_lowercase().as_str() {
        "off" => LevelFilter::Off,
        "error" => LevelFilter::Error,
        "warn" | "warning" => LevelFilter::Warn,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

/// Appends the process's log records to `path` at `level`.
///
/// The file is created 0600 and opened in append mode, so a daemon that is restarted for the same
/// vault adds to the log instead of truncating the evidence of the previous run.
///
/// When [`init_stderr_logger`] has installed the delegating logger -- which the CLI does before it
/// dispatches any command -- the file simply becomes that logger's target, and the process-wide
/// maximum level is raised if the file wants more than the console did. That is what keeps
/// `crypto unlock --foreground` writing its daemon log: a second `log::set_boxed_logger` would be
/// refused, silently leaving the daemon's records on the console instead of in its log file.
///
/// Without that logger (a library user, a test binary that installed its own), this falls back to
/// `log::set_boxed_logger`, whose second call is **not** an error here: the existing logger keeps
/// receiving the records, which is the only sane outcome for a process-global sink.
///
/// # Errors
/// [`crate::error::AppError::Io`] if the log file cannot be opened.
pub fn init_file_logger(path: &Path, level: LevelFilter) -> Result<()> {
    let file = File::options()
        .create(true)
        .append(true)
        .mode(FILE_MODE)
        .open(path)?;
    // `mode()` only applies to a file this call creates; an existing one keeps whatever mode it
    // has, so narrow it explicitly. Best effort: a log that cannot be chmod-ed is still a log.
    let _ = std::fs::set_permissions(path, Permissions::from_mode(FILE_MODE));
    let logger = FileLogger {
        out: Mutex::new(file),
        level,
    };
    match DELEGATING.get() {
        Some(delegating) => {
            delegating.swap(Box::new(logger));
            // Only ever upwards: the console was installed at `warn`, the daemon's log usually
            // wants `info`, and lowering the ceiling here would silence records the file asked for.
            if log::max_level() < level {
                log::set_max_level(level);
            }
        }
        None => {
            if log::set_boxed_logger(Box::new(logger)).is_ok() {
                log::set_max_level(level);
            }
        }
    }
    Ok(())
}

/// The delegating logger of this process, once [`init_stderr_logger`] has installed it.
///
/// Only set when `log::set_boxed_logger` actually accepted it: a handle the `log` crate never
/// calls must not be handed to [`init_file_logger`], which would then swap a file into a logger
/// nobody reads and lose the daemon's log.
static DELEGATING: OnceLock<Arc<Delegating>> = OnceLock::new();

/// Installs the process-wide logger that prints `warning: <message>` on standard error.
///
/// This is what makes the library's `log::warn!` visible to somebody running `crypto` -- a
/// keychain provider that had to be skipped, a self-test entry that could not be removed. Warn and
/// error print as `warning:`, everything below as `info:`, and `level` decides which of them are
/// reached at all (the CLI installs `warn`).
///
/// Call it once, before anything else; a second call, or a process that already has a logger, is a
/// no-op. What it installs can still be redirected: [`init_file_logger`] swaps the daemon's log
/// file in behind the same handle.
pub fn init_stderr_logger(level: LevelFilter) {
    let console = StreamLogger {
        out: Mutex::new(std::io::stderr()),
        level,
    };
    let delegating = Arc::new(Delegating::new(Box::new(console)));
    if log::set_boxed_logger(Box::new(Handle(Arc::clone(&delegating)))).is_ok() {
        log::set_max_level(level);
        let _ = DELEGATING.set(delegating);
    }
}

/// A [`Log`] that forwards to a target which can be replaced while the process runs.
///
/// The `RwLock` is read on every record and written exactly once, when a daemon starts inside a
/// CLI process; a logger that swaps its own target is the only way to have both, given that the
/// `log` crate takes one logger per process and keeps it forever.
struct Delegating {
    target: RwLock<Box<dyn Log>>,
}

impl Delegating {
    fn new(target: Box<dyn Log>) -> Self {
        Self {
            target: RwLock::new(target),
        }
    }

    /// Sends every following record to `target` instead.
    fn swap(&self, target: Box<dyn Log>) {
        // Poisoning is irrelevant: the lock guards a sink, not an invariant.
        let mut current = self.target.write().unwrap_or_else(PoisonError::into_inner);
        *current = target;
    }

    fn with<R>(&self, f: impl FnOnce(&dyn Log) -> R) -> R {
        let target = self.target.read().unwrap_or_else(PoisonError::into_inner);
        f(target.as_ref())
    }
}

impl Log for Delegating {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.with(|target| target.enabled(metadata))
    }

    fn log(&self, record: &Record<'_>) {
        self.with(|target| target.log(record));
    }

    fn flush(&self) {
        self.with(|target| target.flush());
    }
}

/// What the `log` crate owns: a handle onto the [`Delegating`] logger that [`init_file_logger`]
/// still holds a reference to.
struct Handle(Arc<Delegating>);

impl Log for Handle {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.0.enabled(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        self.0.log(record);
    }

    fn flush(&self) {
        self.0.flush();
    }
}

/// A [`Log`] that writes one prefixed line per record to a stream.
///
/// `warning:` for warn and error, `info:` for everything below -- the same words the CLI uses for
/// its own `eprintln!` warnings, so a keychain warning from the library reads like one from a
/// command. The record's target and timestamp are left out on purpose: this is a message to a
/// person at a terminal, not a log file.
struct StreamLogger<W> {
    out: Mutex<W>,
    level: LevelFilter,
}

impl<W: Write + Send> Log for StreamLogger<W> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let prefix = match record.level() {
            Level::Error | Level::Warn => "warning",
            _ => "info",
        };
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(out, "{prefix}: {}", record.args());
        let _ = out.flush();
    }

    fn flush(&self) {
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = out.flush();
    }
}

/// A [`Log`] that appends one line per record to an open file.
#[derive(Debug)]
struct FileLogger {
    out: Mutex<File>,
    level: LevelFilter,
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {} {}: {}\n",
            format_timestamp(SystemTime::now()),
            record.level(),
            record.target(),
            record.args()
        );
        // Poisoning is irrelevant: the mutex guards a file handle, not an invariant, and a logger
        // that panics takes the daemon down with it.
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }

    fn flush(&self) {
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = out.flush();
    }
}

/// `time` as `2026-09-06T10:00:00Z`.
///
/// One UTC format for everything the daemon and the CLI print: the log lines here and the
/// timestamps of `crypto events`.
///
/// A time before the epoch cannot come from a monotonic clock read here, and there is nothing
/// useful to print for it; it is clamped to the epoch.
///
/// The calendar itself is [`cryptomator_core::civil_utc`], shared with the health report's file
/// name so that the workspace has exactly one implementation of it.
pub fn format_timestamp(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .min(i64::MAX as u64) as i64;
    let (year, month, day, hour, minute, second) = civil_utc(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> String {
        format_timestamp(UNIX_EPOCH + Duration::from_secs(secs))
    }

    /// A [`Write`] the test can read back, so a console target can be exercised without writing
    /// to the test runner's own standard error.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn text(&self) -> String {
            let bytes = self
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            String::from_utf8(bytes).expect("utf-8")
        }
    }

    fn console(out: &Captured, level: LevelFilter) -> StreamLogger<Captured> {
        StreamLogger {
            out: Mutex::new(out.clone()),
            level,
        }
    }

    #[test]
    fn the_console_logger_says_warning_and_keeps_quiet_below_its_level() {
        let out = Captured::default();
        let logger = console(&out, LevelFilter::Warn);
        logger.log(
            &Record::builder()
                .args(format_args!("boom"))
                .level(Level::Error)
                .target("keychain")
                .build(),
        );
        logger.log(
            &Record::builder()
                .args(format_args!("careful"))
                .level(Level::Warn)
                .target("keychain")
                .build(),
        );
        logger.log(
            &Record::builder()
                .args(format_args!("chatter"))
                .level(Level::Info)
                .target("keychain")
                .build(),
        );
        // An error is a `warning:` too: the process is not failing because of it -- what fails a
        // command is printed by the command itself, as `error:`.
        assert_eq!(out.text(), "warning: boom\nwarning: careful\n");

        // Raising the level is what makes the info records visible; they name themselves.
        let verbose_out = Captured::default();
        console(&verbose_out, LevelFilter::Info).log(
            &Record::builder()
                .args(format_args!("chatter"))
                .level(Level::Info)
                .target("keychain")
                .build(),
        );
        assert_eq!(verbose_out.text(), "info: chatter\n");
    }

    #[test]
    fn the_delegating_logger_swaps_the_console_for_the_daemons_log_file() {
        let out = Captured::default();
        let delegating = Delegating::new(Box::new(console(&out, LevelFilter::Warn)));
        delegating.log(
            &Record::builder()
                .args(format_args!("before the swap"))
                .level(Level::Warn)
                .target("keychain")
                .build(),
        );
        assert_eq!(out.text(), "warning: before the swap\n");

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("V.log");
        delegating.swap(Box::new(FileLogger {
            out: Mutex::new(
                File::options()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .expect("log file"),
            ),
            level: LevelFilter::Info,
        }));
        delegating.log(
            &Record::builder()
                .args(format_args!("after the swap"))
                .level(Level::Warn)
                .target("keychain")
                .build(),
        );

        assert_eq!(
            out.text(),
            "warning: before the swap\n",
            "the console sees nothing after the swap"
        );
        let written = std::fs::read_to_string(&path).expect("read the log");
        assert!(
            written
                .trim_end()
                .ends_with(" WARN keychain: after the swap"),
            "unexpected log line {written:?}"
        );
        assert!(
            !written.contains("before the swap"),
            "the file only has what was logged after the swap: {written:?}"
        );
    }

    #[test]
    fn timestamps_are_utc_in_the_documented_format() {
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(1), "1970-01-01T00:00:01Z");
        // 2026-09-06T10:00:00Z, the format's own example.
        assert_eq!(at(1_788_688_800), "2026-09-06T10:00:00Z");
        // A leap day, and the last second of a leap year.
        assert_eq!(at(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(at(1_735_689_599), "2024-12-31T23:59:59Z");
        // Y2038 and beyond, to show the 32-bit boundary is not one here.
        assert_eq!(at(2_147_483_648), "2038-01-19T03:14:08Z");
        assert_eq!(at(4_102_444_800), "2100-01-01T00:00:00Z");
    }

    #[test]
    fn every_day_of_a_leap_year_round_trips_through_the_calendar() {
        // 2024-01-01, then one day at a time: the month must never go backwards and the day must
        // restart at 1 exactly when it does.
        let start = 1_704_067_200;
        let mut previous = (2023, 12, 31);
        for day in 0..366 {
            let stamp = at(start + day * 86_400);
            let (y, m, d, ..) = civil_utc(start as i64 + day as i64 * 86_400);
            assert_eq!(
                stamp,
                format!("{y:04}-{m:02}-{d:02}T00:00:00Z"),
                "day {day} formats what the calendar says"
            );
            let advanced = (y, m, d) > previous;
            assert!(advanced, "day {day}: {y}-{m}-{d} follows {previous:?}");
            previous = (y, m, d);
        }
        assert_eq!(previous, (2024, 12, 31), "a leap year has 366 days");
    }

    #[test]
    fn unknown_log_levels_fall_back_to_info() {
        assert_eq!(level_filter("debug"), LevelFilter::Debug);
        assert_eq!(level_filter(" WARN "), LevelFilter::Warn);
        assert_eq!(level_filter("error"), LevelFilter::Error);
        assert_eq!(level_filter("trace"), LevelFilter::Trace);
        assert_eq!(level_filter("off"), LevelFilter::Off);
        assert_eq!(level_filter("shout"), LevelFilter::Info);
        assert_eq!(level_filter(""), LevelFilter::Info);
    }

    #[test]
    fn the_log_file_is_created_private_and_appended_to() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("V.log");
        std::fs::write(&path, b"previous run\n").expect("seed the log");
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).expect("widen");

        init_file_logger(&path, LevelFilter::Info).expect("install the logger");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, FILE_MODE, "an existing log is narrowed to 0600");

        // Whether this process already has a logger installed is up to the test binary, so the
        // record is written through a `FileLogger` built here, not through the `log` macros.
        let logger = FileLogger {
            out: Mutex::new(
                File::options()
                    .append(true)
                    .open(&path)
                    .expect("reopen the log"),
            ),
            level: LevelFilter::Info,
        };
        logger.log(
            &Record::builder()
                .args(format_args!("mounted"))
                .level(log::Level::Info)
                .target("daemon")
                .build(),
        );
        logger.log(
            &Record::builder()
                .args(format_args!("noisy"))
                .level(log::Level::Debug)
                .target("daemon")
                .build(),
        );

        let written = std::fs::read_to_string(&path).expect("read the log");
        let mut lines = written.lines();
        assert_eq!(lines.next(), Some("previous run"), "the log is appended to");
        let line = lines.next().expect("the record");
        assert!(
            line.ends_with(" INFO daemon: mounted"),
            "unexpected log line {line:?}"
        );
        assert_eq!(
            line.len(),
            "2026-09-06T10:00:00Z".len() + " INFO daemon: mounted".len()
        );
        assert_eq!(lines.next(), None, "a debug record is below the level");
    }
}
