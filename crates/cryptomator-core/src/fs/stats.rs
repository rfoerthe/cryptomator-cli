//! `CryptoFileSystemStats`: monotonic counters; the daemon (M4) derives rates from snapshots.
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct CryptoFsStats {
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    bytes_decrypted: AtomicU64,
    bytes_encrypted: AtomicU64,
    chunk_cache_accesses: AtomicU64,
    chunk_cache_misses: AtomicU64,
    accesses_read: AtomicU64,
    accesses_written: AtomicU64,
    accesses: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsSnapshot {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub bytes_decrypted: u64,
    pub bytes_encrypted: u64,
    pub chunk_cache_accesses: u64,
    pub chunk_cache_hits: u64,
    pub chunk_cache_misses: u64,
    pub accesses_read: u64,
    pub accesses_written: u64,
    pub accesses: u64,
}

macro_rules! adder {
    ($name:ident, $field:ident) => {
        pub fn $name(&self, n: u64) {
            self.$field.fetch_add(n, Ordering::Relaxed);
        }
    };
}

impl CryptoFsStats {
    adder!(add_bytes_read, bytes_read);
    adder!(add_bytes_written, bytes_written);
    adder!(add_bytes_decrypted, bytes_decrypted);
    adder!(add_bytes_encrypted, bytes_encrypted);

    pub fn add_chunk_cache_access(&self) {
        self.chunk_cache_accesses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_chunk_cache_miss(&self) {
        self.chunk_cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_accesses_read(&self) {
        self.accesses_read.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_accesses_written(&self) {
        self.accesses_written.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_accesses(&self) {
        self.accesses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let accesses = get(&self.chunk_cache_accesses);
        let misses = get(&self.chunk_cache_misses);
        StatsSnapshot {
            bytes_read: get(&self.bytes_read),
            bytes_written: get(&self.bytes_written),
            bytes_decrypted: get(&self.bytes_decrypted),
            bytes_encrypted: get(&self.bytes_encrypted),
            chunk_cache_accesses: accesses,
            chunk_cache_hits: accesses.saturating_sub(misses),
            chunk_cache_misses: misses,
            accesses_read: get(&self.accesses_read),
            accesses_written: get(&self.accesses_written),
            accesses: get(&self.accesses),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hits_are_accesses_minus_misses() {
        let s = CryptoFsStats::default();
        s.add_chunk_cache_access();
        s.add_chunk_cache_access();
        s.add_chunk_cache_miss();
        s.add_bytes_read(10);
        let snap = s.snapshot();
        assert_eq!(
            (
                snap.chunk_cache_accesses,
                snap.chunk_cache_hits,
                snap.chunk_cache_misses
            ),
            (2, 1, 1)
        );
        assert_eq!(snap.bytes_read, 10);
    }
}
