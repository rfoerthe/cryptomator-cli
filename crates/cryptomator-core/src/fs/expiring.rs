//! `ExpiringMap<K, V>`: a `HashMap` whose entries expire after [`DIR_CACHE_TTL`](super::DIR_CACHE_TTL),
//! shared between the `CryptoPathMapper`'s directory-mapping cache and the `DirIdLoader`'s
//! directory-id cache so both carry the same amortised-pruning fix.
//!
//! Task 15 review, finding I1: pruning the whole map on every cache miss made a hot `find`, a
//! backup run or Spotlight indexing a fresh mount quadratic, because inside a 20 s window nothing
//! has expired yet and the scan removes nothing. [`ExpiringMap::insert`] instead amortises the
//! scan: it only runs when the map has roughly doubled since the last prune, or when a whole TTL
//! has passed without one, so a plain miss (nothing found, nothing loaded) never pays for a scan.
use super::{is_fresh, Clock, DIR_CACHE_TTL};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::Instant;

#[cfg(test)]
use std::time::Duration;

pub(crate) struct ExpiringMap<K, V> {
    entries: HashMap<K, (Instant, V)>,
    clock: Clock,
    /// `entries.len()` right after the last prune -- the high-water mark's baseline.
    last_prune_len: usize,
    last_prune: Instant,
    #[cfg(test)]
    prune_count: usize,
}

impl<K: Eq + Hash, V> ExpiringMap<K, V> {
    pub(crate) fn new() -> Self {
        let clock = Clock::default();
        let last_prune = clock.now();
        Self {
            entries: HashMap::new(),
            clock,
            last_prune_len: 0,
            last_prune,
            #[cfg(test)]
            prune_count: 0,
        }
    }

    /// The clock this map expires against (production: [`Instant::now`]; test: advanceable).
    pub(crate) fn now(&self) -> Instant {
        self.clock.now()
    }

    /// Moves this map's clock forward, for tests only.
    #[cfg(test)]
    pub(crate) fn advance(&self, d: Duration) {
        self.clock.advance(d);
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn prune_count(&self) -> usize {
        self.prune_count
    }

    /// A fresh hit only: an expired entry is removed from the map and treated as a miss.
    pub(crate) fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let now = self.clock.now();
        if self
            .entries
            .get(key)
            .is_some_and(|(loaded, _)| !is_fresh(*loaded, now))
        {
            self.entries.remove(key);
        }
        self.entries.get(key).map(|(_, value)| value)
    }

    /// Inserts `value` as read at `loaded` -- not necessarily "now": a rename keeps the original
    /// load time so it cannot extend an entry's life beyond the TTL it started with. Amortises
    /// pruning (see the module docs and [`Self::maybe_prune`]).
    pub(crate) fn insert(&mut self, key: K, value: V, loaded: Instant) {
        self.entries.insert(key, (loaded, value));
        self.maybe_prune();
    }

    /// Removes and returns the entry with its original load time (for a rename that carries the
    /// time over to the new key).
    pub(crate) fn remove<Q>(&mut self, key: &Q) -> Option<(Instant, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.entries.remove(key)
    }

    /// Keeps only the entries for which `f` returns `true`; does not touch load times.
    pub(crate) fn retain(&mut self, mut f: impl FnMut(&K, &V) -> bool) {
        self.entries.retain(|key, (_, value)| f(key, value));
    }

    /// Every entry with its load time, for a rename remap that must carry it over unchanged.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &Instant, &V)> {
        self.entries.iter().map(|(k, (loaded, v))| (k, loaded, v))
    }

    /// Amortised `expireAfterWrite` pruning (finding I1): scanning the whole map on every insert
    /// made a hot `find`/backup/Spotlight pass over a fresh mount quadratic, since nothing is
    /// expired yet inside a 20 s window and the scan removed nothing. Scanning only once the map
    /// has roughly doubled since the last prune, or once a whole TTL has passed without one, keeps
    /// the amortised cost O(1) per insert while still bounding the map to what was touched
    /// recently (cryptofs additionally caps its cache at 5000 entries; expiry alone bounds ours).
    fn maybe_prune(&mut self) {
        let now = self.clock.now();
        let high_water = 2 * self.last_prune_len + 64;
        let elapsed_a_ttl = now.saturating_duration_since(self.last_prune) >= DIR_CACHE_TTL;
        if self.entries.len() <= high_water && !elapsed_a_ttl {
            return;
        }
        self.entries.retain(|_, (loaded, _)| is_fresh(*loaded, now));
        self.last_prune_len = self.entries.len();
        self.last_prune = now;
        #[cfg(test)]
        {
            self.prune_count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_hit_then_expired_miss_removes_the_entry() {
        let mut map: ExpiringMap<u32, &str> = ExpiringMap::new();
        let now = map.now();
        map.insert(1, "a", now);
        assert_eq!(map.get(&1), Some(&"a"), "fresh hit");
        map.advance(DIR_CACHE_TTL + Duration::from_secs(1));
        assert_eq!(map.get(&1), None, "an expired hit is a miss");
        assert_eq!(map.len(), 0, "the expired hit was removed, not just hidden");
    }

    #[test]
    fn prune_triggers_once_the_high_water_mark_is_crossed() {
        let mut map: ExpiringMap<u32, ()> = ExpiringMap::new();
        for i in 0..64 {
            let now = map.now();
            map.insert(i, (), now);
        }
        assert_eq!(map.prune_count(), 0, "64 entries is still at the mark");
        let now = map.now();
        map.insert(64, (), now); // the 65th entry crosses 2 * 0 + 64
        assert_eq!(map.prune_count(), 1, "crossing the mark scans exactly once");
    }

    #[test]
    fn prune_triggers_once_a_ttl_has_elapsed_even_under_the_mark() {
        let mut map: ExpiringMap<u32, ()> = ExpiringMap::new();
        let now = map.now();
        map.insert(1, (), now);
        assert_eq!(map.prune_count(), 0);
        map.advance(DIR_CACHE_TTL);
        let now = map.now();
        map.insert(2, (), now); // far under the high-water mark, but a full TTL passed
        assert_eq!(
            map.prune_count(),
            1,
            "the elapsed TTL alone triggers a scan"
        );
    }

    #[test]
    fn an_ordinary_miss_never_prunes() {
        let mut map: ExpiringMap<u32, ()> = ExpiringMap::new();
        let now = map.now();
        map.insert(1, (), now);
        assert!(map.get(&99).is_none(), "a miss on an absent key");
        assert_eq!(map.prune_count(), 0, "a miss alone never scans");
        // a handful of ordinary inserts, all under both thresholds, do not scan either
        for i in 2..10 {
            let now = map.now();
            map.insert(i, (), now);
        }
        assert_eq!(map.prune_count(), 0);
    }
}
