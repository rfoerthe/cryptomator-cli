//! Human vs. `--json` output.
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub struct Output {
    pub json: bool,
}

impl Output {
    pub fn emit(
        &self,
        value: serde_json::Value,
        human: impl FnOnce() -> String,
    ) -> anyhow::Result<()> {
        if self.json {
            write_line(&serde_json::to_string_pretty(&value)?)?;
        } else {
            Self::print_human(human)?;
        }
        Ok(())
    }

    /// Like [`Output::emit`], but for payloads carrying key material: the rendered JSON lives in a
    /// buffer that is wiped on drop. The human closure must leave the secret out – the caller
    /// prints it straight from its own wiped buffer.
    pub fn emit_secret(
        &self,
        value: serde_json::Value,
        human: impl FnOnce() -> String,
    ) -> anyhow::Result<()> {
        if self.json {
            let rendered = Zeroizing::new(serde_json::to_string_pretty(&value)?);
            // `serde_json::Value` cannot be wiped, so drop its copy of the secret right away.
            drop(value);
            write_line(rendered.as_str())?;
        } else {
            Self::print_human(human)?;
        }
        Ok(())
    }

    fn print_human(human: impl FnOnce() -> String) -> io::Result<()> {
        let text = human();
        if text.is_empty() {
            return Ok(());
        }
        write_line(&text)
    }
}

/// Writes one line to stdout, holding the lock for the whole line.
///
/// Unlike `println!` a closed pipe -- `crypto events v --follow | head -1` -- is an
/// [`io::ErrorKind::BrokenPipe`] error here rather than a panic, so a command can end the way the
/// reader that walked away expects: quietly, and successfully.
pub fn write_line(text: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{text}")
}

/// Whether `err` is a reader that closed the pipe on us, wherever in an `anyhow` chain it sits.
pub fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == io::ErrorKind::BrokenPipe)
    })
}

/// Seconds since the Unix epoch; pre-epoch instants (a clock skew or a broken file system) count as 0.
pub fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
///
/// The calendar arithmetic itself lives in [`cryptomator_core::health::report::civil_utc`], which
/// the health report needs for its own file names; there is no second copy of it here.
pub fn format_timestamp(time: SystemTime) -> String {
    let (y, mo, d, h, m, s) =
        cryptomator_core::health::report::civil_utc(epoch_seconds(time) as i64);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_timestamp(UNIX_EPOCH), "1970-01-01 00:00:00");
        assert_eq!(
            format_timestamp(UNIX_EPOCH + Duration::from_secs(1_600_000_000)),
            "2020-09-13 12:26:40"
        );
        assert_eq!(
            format_timestamp(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "2000-02-29 00:00:00"
        );
        // Pre-epoch instants clamp to 0 rather than panicking.
        assert_eq!(
            format_timestamp(UNIX_EPOCH - Duration::from_secs(1)),
            "1970-01-01 00:00:00"
        );
    }
}
