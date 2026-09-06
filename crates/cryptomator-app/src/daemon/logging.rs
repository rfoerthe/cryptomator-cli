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
use crate::error::Result;
use log::{LevelFilter, Log, Metadata, Record};
use std::fs::{File, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, PoisonError};
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
/// `log::set_boxed_logger` can be called only once per process. A second call -- another daemon in
/// the same process, or a test binary that has already installed one -- is **not** an error here:
/// the existing logger keeps receiving the records, which is the only sane outcome for a
/// process-global sink.
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
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(level);
    }
    Ok(())
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
/// A time before the epoch cannot come from a monotonic clock read here, and there is nothing
/// useful to print for it; it is clamped to the epoch.
fn format_timestamp(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .min(i64::MAX as u64) as i64;
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`: the Gregorian date of a day number counted from
/// 1970-01-01. Shifting the era to start in March makes the leap day the last day of the year,
/// which is what removes every special case for February.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // 719468 = days from 0000-03-01 to 1970-01-01; 146097 = days in a 400-year era.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // `month_prime` counts March as 0; days 0..=152 are the first five 31/30-day months, and
    // (5*doy + 2)/153 is the exact inverse of that pattern.
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> String {
        format_timestamp(UNIX_EPOCH + Duration::from_secs(secs))
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
            let (y, m, d) = civil_from_days((start as i64 / 86_400) + day as i64);
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
