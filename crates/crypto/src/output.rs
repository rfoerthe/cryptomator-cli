//! Human vs. `--json` output.
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
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            Self::print_human(human);
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
            println!("{}", rendered.as_str());
        } else {
            Self::print_human(human);
        }
        Ok(())
    }

    fn print_human(human: impl FnOnce() -> String) {
        let text = human();
        if !text.is_empty() {
            println!("{text}");
        }
    }
}

/// Seconds since the Unix epoch; pre-epoch instants (a clock skew or a broken file system) count as 0.
pub fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn format_timestamp(time: SystemTime) -> String {
    let secs = epoch_seconds(time) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // days since 1970-01-01 -> civil date (Howard Hinnant, "chrono-compatible low-level date algorithms")
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
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
