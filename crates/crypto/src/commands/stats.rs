//! `crypto stats`: what the daemon's file system has been doing.
//!
//! The numbers come from the daemon over its control socket, so the vault has to be unlocked --
//! a locked one has nobody to ask, which is a state error (exit code 5), not an empty result.
use crate::cli::StatsArgs;
use crate::commands::{unlocked_vault, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::{DaemonClient, StatsResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How often `--follow` looks at the Ctrl-C flag while waiting out its interval.
const POLL: Duration = Duration::from_millis(100);

pub fn stats(ctx: &Ctx, args: StatsArgs) -> Result<u8> {
    let (_, socket) = unlocked_vault(ctx, &args.vault)?;
    let mut client = DaemonClient::connect(&socket)?;
    if !args.follow {
        let stats = client.stats()?;
        ctx.out
            .emit(serde_json::to_value(&stats)?, || render(&stats))?;
        return Ok(exit::OK);
    }

    // The handler is installed before the notice is printed, so anything that reacts to the
    // notice cannot interrupt this process before it can catch the signal.
    let interrupted = install_interrupt()?;
    eprintln!(
        "following the statistics of {}; press Ctrl-C to stop",
        args.vault
    );
    let interval = Duration::from_secs(args.interval);
    while !interrupted.load(Ordering::Relaxed) {
        let stats = client.stats()?;
        if ctx.out.json {
            // One object per line, not the pretty-printed document a single `stats` prints: a
            // follow stream is read line by line.
            println!("{}", serde_json::to_string(&stats)?);
        } else {
            println!("{}", render(&stats));
        }
        wait(interval, &interrupted);
    }
    Ok(exit::OK)
}

/// Sets a flag on Ctrl-C instead of ending the process, so the loop can stop between samples and
/// exit 0 like any other successful command.
///
/// # Errors
/// Whatever `signal_hook` reports while installing the handler.
fn install_interrupt() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))?;
    Ok(flag)
}

/// Waits `interval`, looking at `interrupted` every [`POLL`] so Ctrl-C is not sat out.
fn wait(interval: Duration, interrupted: &AtomicBool) {
    let deadline = std::time::Instant::now() + interval;
    while !interrupted.load(Ordering::Relaxed) {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return;
        }
        std::thread::sleep(left.min(POLL));
    }
}

/// One line: the two rates, the cache hit rate, the totals, the file count and the idle time.
fn render(stats: &StatsResult) -> String {
    format!(
        "read {}/s  write {}/s  cache {}%  total read {}  written {}  files {}  last activity {}",
        human_bytes(stats.bytes_per_second_read),
        human_bytes(stats.bytes_per_second_written),
        (stats.cache_hit_rate * 100.0).round() as i64,
        human_bytes(stats.total_bytes_read),
        human_bytes(stats.total_bytes_written),
        stats.total_files_accessed,
        last_activity(stats.last_activity, SystemTime::now()),
    )
}

/// `12s ago`, or `never` for a vault nothing has touched yet. A timestamp in the future (a clock
/// that jumped) reads as `just now` rather than as a negative age.
fn last_activity(timestamp: u64, now: SystemTime) -> String {
    if timestamp == 0 {
        return "never".to_string();
    }
    let now = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    match now.checked_sub(timestamp) {
        Some(0) | None => "just now".to_string(),
        Some(secs) => format!("{secs}s ago"),
    }
}

/// Binary units, one decimal from KiB up: `0 B`, `512 B`, `12.3 KiB`, `1.2 MiB`.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StatsResult {
        StatsResult {
            bytes_per_second_read: 12_595,
            bytes_per_second_written: 0,
            bytes_per_second_encrypted: 0,
            bytes_per_second_decrypted: 0,
            cache_hit_rate: 0.87,
            total_bytes_read: 1_258_291,
            total_bytes_written: 0,
            total_bytes_encrypted: 0,
            total_bytes_decrypted: 0,
            files_read: 3,
            files_written: 0,
            total_files_accessed: 3,
            last_activity: 1_757_000_000,
        }
    }

    #[test]
    fn bytes_are_rendered_in_binary_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(12_595), "12.3 KiB");
        assert_eq!(human_bytes(1_258_291), "1.2 MiB");
        // The largest unit is not exceeded; the number grows instead.
        assert_eq!(human_bytes(u64::MAX), "16384.0 PiB");
    }

    #[test]
    fn the_idle_time_counts_from_the_last_access() {
        let now = UNIX_EPOCH + Duration::from_secs(1_757_000_012);
        assert_eq!(last_activity(1_757_000_000, now), "12s ago");
        assert_eq!(last_activity(1_757_000_012, now), "just now");
        assert_eq!(last_activity(0, now), "never");
        // A clock that jumped backwards must not produce a negative age.
        assert_eq!(last_activity(1_757_000_099, now), "just now");
    }

    #[test]
    fn the_human_line_names_every_number_it_shows() {
        let line = render(&sample());
        assert!(
            line.starts_with("read 12.3 KiB/s  write 0 B/s  cache 87%"),
            "{line}"
        );
        assert!(line.contains("total read 1.2 MiB  written 0 B"), "{line}");
        assert!(line.contains("files 3"), "{line}");
        assert!(line.contains("last activity"), "{line}");
    }
}
