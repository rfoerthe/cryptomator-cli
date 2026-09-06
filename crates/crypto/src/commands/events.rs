//! `crypto events`: the daemon's event log for one vault.
//!
//! Events are what the file system reports about itself -- a name it could not decrypt, a
//! conflict it resolved. The daemon keeps the last thousand of them in memory, so the log starts
//! over with every unlock and a locked vault has none (exit code 5, like `stats`).
use crate::cli::EventsArgs;
use crate::commands::{unlocked_vault, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::{format_timestamp, DaemonClient, EventRecord, Request};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

/// How long a `--follow` read waits before it looks at the Ctrl-C flag again. The daemon sends
/// nothing while nothing happens, so without this the stream would sit in `read` until it does.
const FOLLOW_POLL: Duration = Duration::from_millis(500);

pub fn events(ctx: &Ctx, args: EventsArgs) -> Result<u8> {
    let (_, socket) = unlocked_vault(ctx, &args.vault)?;
    let mut client = DaemonClient::connect(&socket)?;
    if !args.follow {
        let result = client.events(args.since)?;
        ctx.out.emit(serde_json::to_value(&result.events)?, || {
            render(&result.events)
        })?;
        return Ok(exit::OK);
    }

    // The handler is installed before the notice is printed, so anything that reacts to the
    // notice cannot interrupt this process before it can catch the signal.
    let interrupted = install_interrupt()?;
    eprintln!(
        "following the events of {}; press Ctrl-C to stop",
        args.vault
    );
    // A read timeout turns the daemon's silence into an idle callback instead of a blocked
    // process; a message that arrives split across one of those timeouts is not lost, see
    // `DaemonClient::set_read_timeout`.
    client.set_read_timeout(Some(FOLLOW_POLL))?;
    let json = ctx.out.json;
    let mut failure = None;
    client.stream_until(
        Request::Events {
            id: 0,
            follow: true,
            since: args.since,
        },
        |event| {
            // One record per line, not the pretty-printed array a single `events` prints.
            let line = if json {
                serde_json::to_string(&event).map_err(anyhow::Error::from)
            } else {
                Ok(line_of(&event))
            };
            match line {
                Ok(line) => {
                    println!("{line}");
                    !interrupted.load(Ordering::Relaxed)
                }
                Err(err) => {
                    failure = Some(err);
                    false
                }
            }
        },
        || !interrupted.load(Ordering::Relaxed),
    )?;
    match failure {
        Some(err) => Err(err),
        None => Ok(exit::OK),
    }
}

/// Sets a flag on Ctrl-C instead of ending the process, so the stream can be closed properly and
/// the command exits 0 like any other successful one.
///
/// # Errors
/// Whatever `signal_hook` reports while installing the handler.
fn install_interrupt() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))?;
    Ok(flag)
}

/// One line per event, or a note that there are none.
fn render(events: &[EventRecord]) -> String {
    if events.is_empty() {
        return "no events".to_string();
    }
    events.iter().map(line_of).collect::<Vec<_>>().join("\n")
}

/// `seq  time  KIND  message`, with the same UTC timestamp format as the daemon's log.
fn line_of(event: &EventRecord) -> String {
    format!(
        "{:<6}  {}  {:<20}  {}",
        event.seq,
        format_timestamp(UNIX_EPOCH + Duration::from_secs(event.timestamp)),
        event.kind,
        event.message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64) -> EventRecord {
        EventRecord {
            seq,
            timestamp: 1_757_000_000,
            kind: "DECRYPTION_FAILED".to_string(),
            message: "cannot decrypt /a/b".to_string(),
            cleartext_path: Some("/a/b".to_string()),
            ciphertext_path: None,
        }
    }

    #[test]
    fn a_line_carries_the_sequence_number_the_time_the_kind_and_the_message() {
        let line = line_of(&event(7));
        assert!(line.starts_with("7 "), "{line}");
        assert!(line.contains("2025-09-04T15:33:20Z"), "{line}");
        assert!(line.contains("DECRYPTION_FAILED"), "{line}");
        assert!(line.ends_with("cannot decrypt /a/b"), "{line}");
    }

    #[test]
    fn an_empty_log_says_so() {
        assert_eq!(render(&[]), "no events");
        assert_eq!(render(&[event(1), event(2)]).lines().count(), 2);
    }
}
