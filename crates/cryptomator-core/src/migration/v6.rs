//! 5 → 6, a port of `migration/v6/Version6Migrator.java`.
//!
//! Format 6 encodes the passphrase in Unicode NFC. Nothing on disk moves: the masterkey itself
//! stays exactly the same, only the key file is re-wrapped with the normalised passphrase and
//! stamped with version 6.
use crate::constants::MASTERKEY_FILENAME;
use crate::crypto::rng::Rng;
use crate::error::Result;
use crate::masterkey_file::MasterkeyFileAccess;
use crate::migration::back_up;
use std::path::Path;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// `passphrase` is the passphrase in whatever form the user typed it — that is the form the
/// format 5 key file was locked with. Afterwards the vault opens with its NFC form only.
///
/// # Preconditions
///
/// The vault is at format 5. Nothing here checks that: called on a format 6 or 7 vault this would
/// happily re-stamp the key file back to version 6. Java reaches the migrator only through
/// `Migrators`' dispatch map; call [`crate::migration::migrate`] for the same effect.
pub fn migrate(vault_path: &Path, passphrase: &str, rng: &mut dyn Rng) -> Result<()> {
    let masterkey_file = vault_path.join(MASTERKEY_FILENAME);
    let access = MasterkeyFileAccess::new(Vec::new());
    // Java's order, and it matters: a wrong passphrase must leave neither a backup nor a change.
    let masterkey = access.load(&masterkey_file, passphrase)?;
    back_up(&masterkey_file)?;
    let normalized: Zeroizing<String> = Zeroizing::new(passphrase.nfc().collect());
    access.persist(&masterkey, &masterkey_file, &normalized, 6, rng)
}
