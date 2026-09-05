//! Random number source abstraction so tests can reproduce Java's deterministic vectors.

/// Fills buffers with random bytes.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Operating system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("operating system random number generator unavailable");
    }
}

/// Deterministic and therefore **insecure** RNG: for known-answer tests and fixture generation only,
/// never for real keys, nonces or salts.
///
/// Reproduces the Java `DetRandom` used to create the known-answer vectors: byte number `n`
/// (counting from 0 over the lifetime of the instance) is `0xA0 + (n & 0x3F)`.
/// Outside this crate it exists only behind the non-default `det-rng` feature.
#[cfg(any(test, feature = "det-rng"))]
#[derive(Debug, Default, Clone)]
pub struct DetRng {
    counter: u64,
}

#[cfg(any(test, feature = "det-rng"))]
impl DetRng {
    pub fn starting_at(counter: u64) -> Self {
        Self { counter }
    }
}

#[cfg(any(test, feature = "det-rng"))]
impl Rng for DetRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = 0xA0 + (self.counter & 0x3F) as u8;
            self.counter += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn det_rng_matches_java_det_random_sequence() {
        let mut rng = DetRng::default();
        let mut buf = [0u8; 70];
        rng.fill(&mut buf);
        assert_eq!(&buf[..4], &[0xa0, 0xa1, 0xa2, 0xa3]);
        assert_eq!(buf[63], 0xdf);
        assert_eq!(buf[64], 0xa0, "counter wraps after 64 bytes");
        assert_eq!(buf[69], 0xa5);
    }

    #[test]
    fn det_rng_starting_at_continues_the_counter() {
        let mut rng = DetRng::starting_at(8);
        let mut buf = [0u8; 8];
        rng.fill(&mut buf);
        assert_eq!(buf, [0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf]);
    }

    #[test]
    fn os_rng_produces_different_outputs() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        OsRng.fill(&mut a);
        OsRng.fill(&mut b);
        assert_ne!(a, b);
    }
}
