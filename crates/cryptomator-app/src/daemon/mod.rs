//! The daemon protocol: newline-delimited JSON over a per-vault Unix socket.
//!
//! Unlocking a vault detaches a daemon process that mounts the vault and then serves this
//! protocol on `<state-dir>/<vault-id>.sock`. Every later command (`status`, `stats`, `events`,
//! `lock`) is a round trip over that socket, so the CLI never touches the vault key again after
//! handing it over once.
//!
//! The wire format is one JSON object per line, UTF-8, `\n`-terminated:
//!
//! | direction        | message                                                              |
//! |------------------|----------------------------------------------------------------------|
//! | daemon → client  | [`Hello`], exactly once, immediately after `accept`                  |
//! | client → daemon  | [`Request`], tagged by `"op"`, carrying a client-chosen `id`          |
//! | daemon → client  | [`StreamItem`], zero or more, only while a follow stream is running  |
//! | daemon → client  | [`Response`], exactly one per request, echoing its `id`               |
//!
//! [`protocol`] holds the message types and the two line primitives, [`client`] the synchronous
//! client the CLI commands use, [`server`] the daemon that serves one vault and [`logging`] the
//! log file it writes.
pub mod client;
pub mod logging;
pub mod protocol;
pub mod server;

pub use client::DaemonClient;
pub use logging::{init_file_logger, level_filter};
pub use protocol::{
    read_line, read_request, write_line, ErrorBody, EventRecord, EventsResult, Hello, Request,
    Response, StatsResult, StatusResult, StreamItem, MAX_LINE_LEN, PROTOCOL_VERSION,
};
pub use server::{run_daemon, DaemonConfig};
