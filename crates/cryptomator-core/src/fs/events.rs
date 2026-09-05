//! `org.cryptomator.cryptofs.event.*` (without `FileIsInUseEvent`: `.c9u` markers exist only with Hub).
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemEvent {
    DecryptionFailed {
        ciphertext_path: PathBuf,
        reason: String,
    },
    ConflictResolved {
        canonical_cleartext_path: String,
        conflicting_ciphertext_path: PathBuf,
        resolved_cleartext_path: String,
        resolved_ciphertext_path: PathBuf,
    },
    ConflictResolutionFailed {
        canonical_cleartext_path: String,
        conflicting_ciphertext_path: PathBuf,
        reason: String,
    },
    BrokenDirFile {
        ciphertext_path: PathBuf,
    },
    BrokenFileNode {
        cleartext_path: String,
        ciphertext_path: PathBuf,
    },
}

impl FilesystemEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            FilesystemEvent::DecryptionFailed { .. } => "DECRYPTION_FAILED",
            FilesystemEvent::ConflictResolved { .. } => "CONFLICT_RESOLVED",
            FilesystemEvent::ConflictResolutionFailed { .. } => "CONFLICT_RESOLUTION_FAILED",
            FilesystemEvent::BrokenDirFile { .. } => "BROKEN_DIR_FILE",
            FilesystemEvent::BrokenFileNode { .. } => "BROKEN_FILE_NODE",
        }
    }
}

impl fmt::Display for FilesystemEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilesystemEvent::DecryptionFailed {
                ciphertext_path,
                reason,
            } => {
                write!(
                    f,
                    "decryption of {} failed: {reason}",
                    ciphertext_path.display()
                )
            }
            FilesystemEvent::ConflictResolved {
                canonical_cleartext_path,
                resolved_cleartext_path,
                ..
            } => {
                write!(
                    f,
                    "conflicting copy of {canonical_cleartext_path} renamed to {resolved_cleartext_path}"
                )
            }
            FilesystemEvent::ConflictResolutionFailed {
                canonical_cleartext_path,
                reason,
                ..
            } => {
                write!(
                    f,
                    "conflict for {canonical_cleartext_path} could not be resolved: {reason}"
                )
            }
            FilesystemEvent::BrokenDirFile { ciphertext_path } => {
                write!(f, "broken directory file {}", ciphertext_path.display())
            }
            FilesystemEvent::BrokenFileNode {
                cleartext_path,
                ciphertext_path,
            } => {
                write!(
                    f,
                    "{cleartext_path}: ciphertext node {} has no dir.c9r, symlink.c9r or contents.c9r",
                    ciphertext_path.display()
                )
            }
        }
    }
}

pub type EventSink = Arc<dyn Fn(FilesystemEvent) + Send + Sync>;

pub fn discard_events() -> EventSink {
    Arc::new(|_| {})
}

/// Collects events for assertions.
#[derive(Clone, Debug, Default)]
pub struct EventCollector {
    events: Arc<Mutex<Vec<FilesystemEvent>>>,
}

impl EventCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sink(&self) -> EventSink {
        let events = self.events.clone();
        Arc::new(move |event| super::lock(&events).push(event))
    }

    pub fn take(&self) -> Vec<FilesystemEvent> {
        std::mem::take(&mut *super::lock(&self.events))
    }

    pub fn kinds(&self) -> Vec<&'static str> {
        super::lock(&self.events)
            .iter()
            .map(FilesystemEvent::kind)
            .collect()
    }
}
