//! `crypto events`: the daemon's event log for one vault.
//!
//! Events are what the file system reports about itself -- a name it could not decrypt, a
//! conflict it resolved. The daemon keeps the last thousand of them in memory, so the log starts
//! over with every unlock and a locked vault has none (exit code 5, like `stats`).
use crate::cli::EventsArgs;
use crate::commands::{daemon_gone, install_interrupt, unlocked_vault, vault_label, Ctx};
use crate::exit;
use crate::output::{is_broken_pipe, write_line};
use anyhow::Result;
use cryptomator_app::{format_timestamp, DaemonClient, EventRecord, Request};
use std::sync::atomic::Ordering;
use std::time::{Duration, UNIX_EPOCH};

/// How long a `--follow` read waits before it looks at the Ctrl-C flag again. The daemon sends
/// nothing while nothing happens, so without this the stream would sit in `read` until it does.
const FOLLOW_POLL: Duration = Duration::from_millis(500);

pub fn events(ctx: &Ctx, args: EventsArgs) -> Result<u8> {
    let (info, socket) = unlocked_vault(ctx, &args.vault)?;
    let mut client = DaemonClient::connect(&socket)?;
    if !args.follow {
        let result = client.events(args.since)?;
        let printed = ctx.out.emit(serde_json::to_value(&result.events)?, || {
            render(&result.events)
        });
        return match printed {
            // A reader that closed the pipe is done with us, so we are done too.
            Err(err) if is_broken_pipe(&err) => Ok(exit::OK),
            Err(err) => Err(err),
            Ok(()) => Ok(exit::OK),
        };
    }

    // The handler is installed before the notice is printed, so anything that reacts to the
    // notice cannot interrupt this process before it can catch the signal.
    let interrupted = install_interrupt()?;
    eprintln!(
        "following the events of {}; press Ctrl-C to stop",
        vault_label(&info)
    );
    // A read timeout turns the daemon's silence into an idle callback instead of a blocked
    // process; a message that arrives split across one of those timeouts is not lost, see
    // `DaemonClient::set_read_timeout`.
    client.set_read_timeout(Some(FOLLOW_POLL))?;
    let json = ctx.out.json;
    let mut failure = None;
    let mut printed = 0u64;
    let streamed = client.stream_until(
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
            match line.and_then(|line| write_line(&line).map_err(anyhow::Error::from)) {
                Ok(()) => {
                    printed += 1;
                    !interrupted.load(Ordering::Relaxed)
                }
                Err(err) => {
                    // `| head -1` is the canonical way to read a stream: a closed pipe ends the
                    // stream successfully instead of panicking out of `println!` with code 101.
                    if !is_broken_pipe(&err) {
                        failure = Some(err);
                    }
                    false
                }
            }
        },
        || !interrupted.load(Ordering::Relaxed),
    );
    match (failure, streamed) {
        (Some(err), _) => Err(err),
        // A daemon that shuts down cleanly ends the stream with a response and lands in `Ok`;
        // one that is gone before it can leaves the read hanging in mid-air. After at least one
        // event that is still the end of the stream and not a failure of this command.
        (None, Err(err)) if printed > 0 && daemon_gone(&err) => Ok(exit::OK),
        (None, Err(err)) => Err(err.into()),
        (None, Ok(())) => Ok(exit::OK),
    }
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
