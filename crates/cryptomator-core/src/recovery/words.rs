//! 12-bit word encoding: every 3 bytes become 2 words of a 4096-word dictionary.
use crate::error::{CoreError, Result};
use std::collections::HashMap;

pub const WORD_COUNT: usize = 4096;
const DELIMITER: char = ' ';
/// English word list shipped with the Cryptomator desktop app (`i18n/4096words_en.txt`).
const WORD_FILE: &str = include_str!("4096words_en.txt");

#[derive(Debug, Clone)]
pub struct WordEncoder {
    words: Vec<&'static str>,
    indices: HashMap<&'static str, u16>,
}

impl Default for WordEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl WordEncoder {
    pub fn new() -> Self {
        let words: Vec<&'static str> = WORD_FILE.lines().take(WORD_COUNT).collect();
        assert_eq!(
            words.len(),
            WORD_COUNT,
            "word list must contain {WORD_COUNT} words"
        );
        let indices = words
            .iter()
            .enumerate()
            .map(|(i, w)| (*w, i as u16))
            .collect();
        Self { words, indices }
    }

    pub fn words(&self) -> &[&'static str] {
        &self.words
    }

    pub fn encode_padded(&self, input: &[u8]) -> Result<String> {
        if input.len() % 3 != 0 {
            return Err(CoreError::InvalidArgument(
                "input needs to be padded to a multiple of three".into(),
            ));
        }
        let mut out = Vec::with_capacity(input.len() / 3 * 2);
        for triple in input.chunks_exact(3) {
            let (b1, b2, b3) = (triple[0] as u32, triple[1] as u32, triple[2] as u32);
            let first = ((b1 << 4) & 0xFF0) | ((b2 >> 4) & 0x00F);
            let second = ((b2 << 8) & 0xF00) | (b3 & 0x0FF);
            out.push(self.words[first as usize]);
            out.push(self.words[second as usize]);
        }
        Ok(out.join(&DELIMITER.to_string()))
    }

    pub fn decode(&self, encoded: &str) -> Result<Vec<u8>> {
        let split: Vec<&str> = encoded.split(DELIMITER).filter(|w| !w.is_empty()).collect();
        if split.len() % 2 != 0 {
            return Err(CoreError::InvalidRecoveryKey(format!(
                "{encoded} needs to be a multiple of two words"
            )));
        }
        let mut out = Vec::with_capacity(split.len() / 2 * 3);
        for pair in split.chunks_exact(2) {
            let first = *self.indices.get(pair[0]).ok_or_else(|| {
                CoreError::InvalidRecoveryKey(format!("{} not in dictionary", pair[0]))
            })? as u32;
            let second = *self.indices.get(pair[1]).ok_or_else(|| {
                CoreError::InvalidRecoveryKey(format!("{} not in dictionary", pair[1]))
            })? as u32;
            out.push((first >> 4) as u8);
            out.push((((first << 4) & 0xF0) | ((second >> 8) & 0x0F)) as u8);
            out.push((second & 0xFF) as u8);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_has_4096_words() {
        let enc = WordEncoder::new();
        assert_eq!(enc.words().len(), 4096);
        assert_eq!(enc.words()[0], "ad");
        assert_eq!(enc.words()[4095], "residence");
    }

    #[test]
    fn encode_then_decode_round_trips_for_all_multiples_of_three() {
        let enc = WordEncoder::new();
        let mut seed = 42u64;
        for i in 0..30 {
            let input: Vec<u8> = (0..i * 3)
                .map(|_| {
                    seed = seed
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    (seed >> 33) as u8
                })
                .collect();
            let encoded = enc.encode_padded(&input).unwrap();
            assert_eq!(
                enc.decode(&encoded).unwrap(),
                input,
                "length {}",
                input.len()
            );
        }
    }

    #[test]
    fn encode_rejects_length_not_multiple_of_three() {
        assert!(matches!(
            WordEncoder::new().encode_padded(&[1, 2]),
            Err(CoreError::InvalidArgument(_))
        ));
    }

    #[test]
    fn decode_rejects_odd_word_count_and_unknown_words() {
        let enc = WordEncoder::new();
        assert!(matches!(
            enc.decode("pathway"),
            Err(CoreError::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            enc.decode("Backpfeifengesicht Schweinehund"),
            Err(CoreError::InvalidRecoveryKey(_))
        ));
        assert_eq!(enc.decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_ignores_extra_whitespace() {
        let enc = WordEncoder::new();
        assert_eq!(enc.decode("  ad   ad ").unwrap(), vec![0, 0, 0]);
    }
}
