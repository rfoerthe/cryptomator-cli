//! Every Java fixture, walked through the `CryptoFs` facade, equals its `expected.json`.
mod common;

use common::{expected_entries, open_fixture, ExpectedEntry, FIXTURE_NAMES};
use cryptomator_core::fs::{CleartextPath, CryptoFs, CryptoFsOptions};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

fn walk(fs: &CryptoFs, dir: &CleartextPath, out: &mut Vec<ExpectedEntry>) {
    for entry in fs.read_dir(dir).unwrap() {
        let path = dir.join(&entry.cleartext_name).unwrap();
        let attrs = fs.symlink_metadata(&path).unwrap();
        if attrs.is_symlink() {
            out.push(ExpectedEntry {
                path: path.to_string(),
                kind: "symlink".into(),
                size: None,
                sha256: None,
                target: Some(fs.read_link(&path).unwrap()),
            });
        } else if attrs.is_dir() {
            out.push(ExpectedEntry {
                path: path.to_string(),
                kind: "dir".into(),
                size: None,
                sha256: None,
                target: None,
            });
            walk(fs, &path, out);
        } else {
            let data = fs.read_file(&path).unwrap();
            assert_eq!(attrs.size, data.len() as u64, "{path}: metadata size");
            out.push(ExpectedEntry {
                path: path.to_string(),
                kind: "file".into(),
                size: Some(data.len() as u64),
                sha256: Some(HEXLOWER.encode(&Sha256::digest(&data))),
                target: None,
            });
        }
    }
}

#[test]
fn every_fixture_reads_through_crypto_fs() {
    for name in FIXTURE_NAMES {
        let (dir, opened) = open_fixture(name);
        let fs = CryptoFs::open(
            opened,
            CryptoFsOptions {
                read_only: true,
                ..Default::default()
            },
        );
        let mut actual = Vec::new();
        walk(&fs, &CleartextPath::root(), &mut actual);
        actual.sort();
        assert_eq!(actual, expected_entries(dir.path()), "{name}");
        assert!(fs.stats().snapshot().accesses > 0);
        fs.close().unwrap();
    }
}

#[test]
fn ciphertext_paths_and_streaming_reads() {
    let (dir, opened) = open_fixture("long_names");
    let fs = CryptoFs::open(opened, CryptoFsOptions::default());
    let long_dir = CleartextPath::parse(&format!("/{}", "d".repeat(200)));
    let content_dir = fs.ciphertext_path(&long_dir).unwrap();
    assert!(content_dir.starts_with(dir.path().join("d")) && content_dir.is_dir());
    // "inner.txt" is short enough for the 220-char threshold even inside the long directory, so its
    // ciphertext is a plain `.c9r` file; only the 200-char root file below is shortened.
    let inner = long_dir.join("inner.txt").unwrap();
    let inner_ciphertext = fs.ciphertext_path(&inner).unwrap();
    assert!(
        inner_ciphertext.extension().is_some_and(|e| e == "c9r"),
        "{}",
        inner_ciphertext.display()
    );
    assert!(
        !inner_ciphertext.ends_with("contents.c9r"),
        "{}",
        inner_ciphertext.display()
    );
    let long_file = CleartextPath::parse(&format!("/{}.txt", "c".repeat(200)));
    assert!(
        fs.ciphertext_path(&long_file)
            .unwrap()
            .ends_with("contents.c9r"),
        "{}",
        fs.ciphertext_path(&long_file).unwrap().display()
    );
    let mut out = Vec::new();
    assert_eq!(fs.copy_to_writer(&inner, &mut out).unwrap(), 16);
    assert_eq!(out, b"inside long dir\n");
    assert_eq!(
        fs.read_dir(&inner).unwrap_err().kind(),
        std::io::ErrorKind::NotADirectory
    );
    assert_eq!(
        fs.read_file(&CleartextPath::parse("/missing"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}
