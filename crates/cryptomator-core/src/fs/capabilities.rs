//! `FileSystemCapabilityChecker.determineSupportedCleartextFileNameLength`: probes the longest
//! `.c9r` name the storage accepts below `<vault>/c/` by binary search, then removes the probe dir.
use crate::constants::{
    MAX_ADDITIONAL_PATH_LENGTH, MAX_CIPHER_NAME_LENGTH, MIN_CIPHER_NAME_LENGTH,
};
use std::io;
use std::path::Path;

/// Cleartext characters that survive base64 + IV overhead for `max_ciphertext` ciphertext
/// characters (math explained in cryptofs issue #60: subtract 4 for the `.c9r` extension,
/// base64-decode, subtract 16 for the IV). Both subtractions saturate, because a manipulated vault
/// config may carry a shortening threshold below 25, which `CryptoPathMapper` accepts unchecked.
pub fn max_cleartext_file_name_length(max_ciphertext: usize) -> usize {
    (max_ciphertext.saturating_sub(4) / 4 * 3).saturating_sub(16)
}

/// Cleartext characters that survive base64 + IV overhead for the supported ciphertext length.
pub fn determine_supported_cleartext_file_name_length(vault_path: &Path) -> io::Result<u32> {
    let max_ciphertext = determine_supported_ciphertext_file_name_length(vault_path)?;
    Ok(max_cleartext_file_name_length(max_ciphertext as usize) as u32)
}

pub fn determine_supported_ciphertext_file_name_length(vault_path: &Path) -> io::Result<u32> {
    let sub_path_length = MAX_ADDITIONAL_PATH_LENGTH - 2; // subtract "c/"
    let check_dir = vault_path.join("c");
    let result = determine_in_dir(
        &check_dir,
        sub_path_length,
        MIN_CIPHER_NAME_LENGTH,
        MAX_CIPHER_NAME_LENGTH,
    );
    let _ = std::fs::remove_dir_all(&check_dir);
    result
}

fn determine_in_dir(dir: &Path, sub_path_length: usize, min: usize, max: usize) -> io::Result<u32> {
    let filler_dir = dir.join("a".repeat(sub_path_length - 5)); // "a…a/nnn/" fills the sub path
    let result = (|| {
        std::fs::create_dir_all(filler_dir.join("nnn"))?;
        if !can_list_dir(&filler_dir) {
            return Err(io::Error::other("Unable to read dir"));
        }
        Ok(search(min, max + 1, |n| {
            can_handle_file_name_length(&filler_dir, n)
        }) as u32)
    })();
    let _ = std::fs::remove_dir_all(&filler_dir);
    result
}

/// Largest `n` in `[lower, upper)` for which `ok(n)` holds, assuming `ok` is monotonic and `ok(lower)`.
pub(crate) fn search(
    lower_incl: usize,
    upper_excl: usize,
    mut ok: impl FnMut(usize) -> bool,
) -> usize {
    let (mut lower, mut upper) = (lower_incl, upper_excl);
    loop {
        let mid = (lower + upper) / 2;
        if mid == lower {
            return mid;
        }
        if ok(mid) {
            lower = mid
        } else {
            upper = mid
        }
    }
}

fn can_handle_file_name_length(parent: &Path, name_length: usize) -> bool {
    let check_dir = parent.join(format!("{name_length:03}"));
    let check_file = check_dir.join("a".repeat(name_length));
    let result = std::fs::create_dir_all(&check_dir)
        .and_then(|_| match std::fs::File::create_new(&check_file) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        })
        .map(|_| can_list_dir(&check_dir))
        .unwrap_or(false);
    let _ = std::fs::remove_file(&check_file);
    let _ = std::fs::remove_dir_all(&check_dir);
    result
}

fn can_list_dir(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|mut entries| entries.next().is_none_or(|e| e.is_ok()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_filesystem_supports_the_maximum_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let cleartext = determine_supported_cleartext_file_name_length(dir.path()).unwrap();
        assert_eq!(cleartext, (220 - 4) / 4 * 3 - 16);
        assert!(!dir.path().join("c").exists(), "probe directory removed");
    }

    #[test]
    fn binary_search_finds_a_limit() {
        // a probe whose "file system" refuses names longer than 100 chars
        let mut probes = Vec::new();
        let found = search(28, 221, |n| {
            probes.push(n);
            n <= 100
        });
        assert_eq!(found, 100);
        assert!(probes.len() <= 9, "{probes:?}");
    }
}
