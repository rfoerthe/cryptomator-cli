//! `OrphanContentDir.fix`, ported from cryptofs 2.10.0
//! (`org.cryptomator.cryptofs.health.dirid.OrphanContentDir`).
//!
//! An orphaned content directory is a `d/XX/YYYY…` that no `dir.c9r` points at: the cleartext path
//! leading to it is gone, so its children are unreachable even though their ciphertext is intact.
//! The repair does not restore the lost path -- it *adopts* the children into a recovery directory
//! that is reachable again:
//!
//! ```text
//! /LOST+FOUND                       dir id "recovery", created in the vault root
//! └── /LOST+FOUND/<XXYYYY…>         one "step parent" per orphan, named after its hash
//!     ├── adopted.txt               the original name, if the orphan still had its dirid.c9r
//!     └── file1_<runId>             otherwise: <prefix><counter>_<run id>
//! ```
//!
//! Everything happens on the ciphertext level (moves under `d/`), so the fix works without a mount
//! and cannot resurrect the orphan's own `dir.c9r`.
//!
//! Deliberate differences to Java, all noted at the place they occur: the entries of the orphan are
//! processed in sorted order (Java takes the order of the directory stream), `.c9u` in-use markers
//! are moved verbatim instead of being adopted under a new name, and the run id comes from
//! [`OsRng`] instead of `UUID.randomUUID()` -- the fix owns its randomness because [`CheckContext`]
//! deliberately has none.
use super::{CheckContext, Fix};
use crate::constants::{
    CRYPTOMATOR_FILE_SUFFIX, DEFLATED_FILE_SUFFIX, DIR_FILE_NAME, DIR_ID_BACKUP_FILE_NAME,
    INUSE_FILE_SUFFIX, RECOVERY_DIR_ID, RECOVERY_DIR_NAME, ROOT_DIR_ID, SYMLINK_FILE_NAME,
};
use crate::crypto::rng::{OsRng, Rng};
use crate::fs::dir_id::{read_dir_id_backup, write_dir_id_backup};
use crate::fs::dir_stream::matches_encrypted_content_pattern;
use crate::fs::long_names::{deflate, inflate};
use crate::fs::{CiphertextDirectory, CiphertextFileType};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// `OrphanContentDir.FILE_PREFIX`.
pub(crate) const FILE_PREFIX: &str = "file";
/// `OrphanContentDir.DIR_PREFIX`.
pub(crate) const DIR_PREFIX: &str = "directory";
/// `OrphanContentDir.SYMLINK_PREFIX`.
pub(crate) const SYMLINK_PREFIX: &str = "symlink";
/// `OrphanContentDir.LONG_NAME_SUFFIX_BASE`: repeated until the generated name is long enough to be
/// shortened again, so that a `.c9s` node stays a `.c9s` node after the adoption.
pub(crate) const LONG_NAME_SUFFIX_BASE: &str = "_withVeryLongName";

/// `OrphanContentDir.getFix`: moves everything the orphaned content directory holds into
/// `/LOST+FOUND/<hash of the orphan>` and deletes the orphan afterwards.
#[derive(Debug)]
pub(crate) struct AdoptOrphan {
    /// Vault-relative, e.g. `d/CU/JUVHHOHR37XSFJOOJJKFUPSLEJNPVQ`.
    pub content_dir: PathBuf,
}

impl Fix for AdoptOrphan {
    fn describe(&self) -> String {
        format!(
            "adopt the contents of {} into /{RECOVERY_DIR_NAME}",
            self.content_dir.display()
        )
    }

    fn apply(&self, ctx: &CheckContext) -> io::Result<()> {
        let orphan = ctx.resolve(&self.content_dir);
        // A second `--fix` run finds nothing to adopt: the orphan was removed by the first one.
        // Java has no such guard (its report is built once, then fixed once).
        if !orphan.is_dir() {
            return Ok(());
        }
        // `orphanDirIdHash`: the two path components of the content dir, concatenated. It becomes
        // the cleartext name of the step parent, so the recovered files can be traced back.
        let hash_name = format!(
            "{}{}",
            file_name_of(self.content_dir.parent().unwrap_or(Path::new(""))),
            file_name_of(&self.content_dir)
        );

        let recovery_dir = prepare_recovery_dir(ctx)?;
        if recovery_dir == orphan {
            // "recovery dir was orphaned, already recovered by prepare method"
            return Ok(());
        }
        let step_parent = prepare_step_parent(ctx, &recovery_dir, &hash_name)?;

        let run = run_id(&mut OsRng);
        let long_suffix = clear_name_to_be_shortened(ctx.shortening_threshold);
        // `retrieveDirId`: with the orphan's own `dirid.c9r` the original names can be decrypted;
        // without it every child is renamed after its type and a counter.
        // `read_dir_id_backup` yields a `String` and refuses a dir id that is not UTF-8, where
        // Java's `DirectoryIdBackup.read` keeps the raw bytes. Such an orphan simply falls back to
        // the counter names below -- unreachable for a real vault, whose dir ids are UUIDs.
        let dir_id = read_dir_id_backup(&ctx.cryptor, &orphan).ok();
        let (mut files, mut dirs, mut links) = (1u32, 1u32, 1u32);

        for name in sorted_entries(&orphan)? {
            // A ciphertext name is BASE64URL and therefore ASCII; anything else is not ours and
            // travels with its own name through the second pass below.
            let Some(name) = name.to_str() else { continue };
            // `matchesEncryptedContentPattern`, minus the `.c9u` in-use markers our shared helper
            // also accepts: Java's filter is `.c9r`/`.c9s` only, so a `.c9u` is left to the
            // verbatim move below instead of being adopted under an encrypted name.
            if !matches_encrypted_content_pattern(name) || name.ends_with(INUSE_FILE_SUFFIX) {
                continue;
            }
            let shortened = name.ends_with(DEFLATED_FILE_SUFFIX);
            let path = orphan.join(name);
            let new_clear_name = match dir_id
                .as_deref()
                .and_then(|id| decrypt_orphan_name(ctx, &path, shortened, id))
            {
                Some(name) => name,
                None => {
                    let (prefix, counter) = match determine_ciphertext_file_type(&path) {
                        CiphertextFileType::Directory => (DIR_PREFIX, &mut dirs),
                        CiphertextFileType::Symlink => (SYMLINK_PREFIX, &mut links),
                        CiphertextFileType::File => (FILE_PREFIX, &mut files),
                    };
                    let n = *counter;
                    *counter += 1;
                    format!(
                        "{prefix}{n}_{run}{}",
                        if shortened { long_suffix.as_str() } else { "" }
                    )
                }
            };
            adopt_orphaned_resource(ctx, &path, &new_clear_name, shortened, &step_parent)?;
        }

        // `Files.deleteIfExists(orphanedDir.resolve(DIR_ID_BACKUP_FILE_NAME))`: the backup names the
        // dir id of a directory that is about to disappear.
        match std::fs::remove_file(orphan.join(DIR_ID_BACKUP_FILE_NAME)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        // Whatever else the orphan holds is not ours to rename; it moves with its own name.
        for name in sorted_entries(&orphan)? {
            move_path(&orphan.join(&name), &step_parent.path.join(&name))?;
        }
        std::fs::remove_dir(&orphan)
    }
}

/// `OrphanContentDir.prepareRecoveryDir`: creates `/LOST+FOUND` (dir id `recovery`) in the vault
/// root and returns its content directory -- absolute, because the adoption moves nodes there.
///
/// Like Java, this writes no `dirid.c9r` for the recovery directory: a `dirid` re-run therefore
/// reports one `MissingDirIdBackup` for it, which its own fix then repairs.
pub(crate) fn prepare_recovery_dir(ctx: &CheckContext) -> io::Result<PathBuf> {
    let names = ctx.cryptor.file_name_cryptor();
    let root_hash = names.hash_directory_id(ROOT_DIR_ID);
    let root = content_dir_of(ctx, &root_hash);
    let cipher_name = encrypt_name(ctx, RECOVERY_DIR_NAME, ROOT_DIR_ID.as_bytes());
    let dir_file = root.join(&cipher_name).join(DIR_FILE_NAME);
    // `Files.notExists(…, NOFOLLOW_LINKS)`, i.e. a dangling symlink counts as existing.
    if exists_no_follow(&dir_file)? {
        let existing = std::fs::read_to_string(&dir_file)?;
        if existing != RECOVERY_DIR_ID {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Directory /{RECOVERY_DIR_NAME} already exists, but with wrong directory id."
                ),
            ));
        }
    } else {
        std::fs::create_dir_all(root.join(&cipher_name))?;
        create_new_file(&dir_file)?.write_all(RECOVERY_DIR_ID.as_bytes())?;
    }
    let recovery_hash = names.hash_directory_id(RECOVERY_DIR_ID);
    let dir = content_dir_of(ctx, &recovery_hash);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// `OrphanContentDir.prepareStepParent`: a subdirectory of `/LOST+FOUND` whose cleartext name is the
/// hash of the orphaned content directory, so the recovered nodes can be traced back to it.
///
/// Unlike the recovery directory itself, the step parent does get a `dirid.c9r`; an existing one is
/// tolerated because a previous repair attempt may have written it.
pub(crate) fn prepare_step_parent(
    ctx: &CheckContext,
    recovery_dir: &Path,
    clear_name: &str,
) -> io::Result<CiphertextDirectory> {
    let cipher_name = encrypt_name(ctx, clear_name, RECOVERY_DIR_ID.as_bytes());
    let dir_file = recovery_dir.join(&cipher_name).join(DIR_FILE_NAME);
    let uuid = if exists_no_follow(&dir_file)? {
        std::fs::read_to_string(&dir_file)?
    } else {
        std::fs::create_dir_all(recovery_dir.join(&cipher_name))?;
        let uuid = uuid::Uuid::new_v4().to_string();
        create_new_file(&dir_file)?.write_all(uuid.as_bytes())?;
        uuid
    };
    let hash = ctx.cryptor.file_name_cryptor().hash_directory_id(&uuid);
    let path = content_dir_of(ctx, &hash);
    std::fs::create_dir_all(&path)?;
    let dir = CiphertextDirectory { dir_id: uuid, path };
    // `catch (FileAlreadyExistsException e)`: a previous recovery attempt was already here.
    match write_dir_id_backup(&ctx.cryptor, &dir, &mut OsRng) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    Ok(dir)
}

/// `OrphanContentDir.createClearnameToBeShortened`.
///
/// The arithmetic is Java's and is wrong there (`%` where a `/` was meant), but it is reproduced
/// deliberately: all it has to do is yield a name long enough to be shortened again, and both
/// implementations should hand out the same names.
pub(crate) fn clear_name_to_be_shortened(threshold: usize) -> String {
    let needed = (threshold as i64 - 4) / 4 * 3 - 16;
    let times = (needed.rem_euclid(LONG_NAME_SUFFIX_BASE.len() as i64) + 1) as usize;
    LONG_NAME_SUFFIX_BASE.repeat(times)
}

/// `Integer.toString((short) UUID.randomUUID().getMostSignificantBits(), 32)`: 16 random bits as a
/// *signed* number in base 32 with the digits `0-9a-v`; negative values get a leading `-`.
pub(crate) fn run_id(rng: &mut dyn Rng) -> String {
    let mut buf = [0u8; 2];
    rng.fill(&mut buf);
    let mut value = i64::from(i16::from_be_bytes(buf));
    if value == 0 {
        return "0".to_string();
    }
    let negative = value < 0;
    value = value.abs();
    let digits = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = Vec::new();
    while value > 0 {
        out.push(digits[(value % 32) as usize]);
        value /= 32;
    }
    if negative {
        out.push(b'-');
    }
    out.reverse();
    // Every pushed byte is one of the 32 ASCII digits or '-'.
    String::from_utf8(out).unwrap_or_default()
}

/// `OrphanContentDir.decryptFileName`, with Java's `catch`: any failure means "no name", and the
/// caller falls back to `<prefix><counter>_<run id>`.
///
/// The `name.c9s` of a shortened node is read through [`inflate`], which refuses anything larger
/// than [`MAX_FILENAME_BUFFER_SIZE`](crate::fs::long_names::MAX_FILENAME_BUFFER_SIZE). Java reads it
/// unbounded, but a `--fix` is aimed at damaged vaults by definition: a corrupt name file of
/// arbitrary size must not be pulled into memory whole, and "too large to be a name" is exactly the
/// case the counter-name fallback exists for.
fn decrypt_orphan_name(
    ctx: &CheckContext,
    resource: &Path,
    shortened: bool,
    dir_id: &str,
) -> Option<String> {
    let with_extension = if shortened {
        inflate(resource).ok()?
    } else {
        resource.file_name()?.to_str()?.to_owned()
    };
    let name = with_extension
        .len()
        .checked_sub(CRYPTOMATOR_FILE_SUFFIX.len())
        .and_then(|end| with_extension.get(..end))?;
    ctx.cryptor
        .file_name_cryptor()
        .decrypt_filename(name, &[dir_id.as_bytes()])
        .ok()
}

/// `OrphanContentDir.adoptOrphanedResource`: encrypt the new name under the step parent's dir id,
/// move the node, and only then (re)write `name.c9s` -- the order matters, the `.c9s` directory is
/// the moved node itself.
fn adopt_orphaned_resource(
    ctx: &CheckContext,
    old: &Path,
    new_clear_name: &str,
    shortened: bool,
    step_parent: &CiphertextDirectory,
) -> io::Result<()> {
    let cipher_name = encrypt_name(ctx, new_clear_name, step_parent.dir_id.as_bytes());
    let target = step_parent.path.join(&cipher_name);
    if shortened {
        // `LongFileNameProvider.deflate` is the same BASE64URL(SHA1(name)) Java computes inline.
        let deflated = deflate(&target);
        move_path(old, &deflated.c9s_path)?;
        deflated.persist()
    } else {
        move_path(old, &target)
    }
}

/// `OrphanContentDir.determineCiphertextFileType`, never following symlinks.
fn determine_ciphertext_file_type(path: &Path) -> CiphertextFileType {
    if path.join(DIR_FILE_NAME).symlink_metadata().is_ok() {
        CiphertextFileType::Directory
    } else if path.join(SYMLINK_FILE_NAME).symlink_metadata().is_ok() {
        CiphertextFileType::Symlink
    } else {
        CiphertextFileType::File
    }
}

/// The entry names of `dir`, sorted. Java iterates a `DirectoryStream` in file system order; the
/// numbering of the generated names would then depend on it, and an unpredictable repair is worse
/// than Java parity here (the same argument as in `health::dir_id`).
fn sorted_entries(dir: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        names.push(entry?.file_name());
    }
    names.sort();
    Ok(names)
}

/// `Files.move`, with a copy-and-delete fallback for the (practically impossible) case that the
/// orphan and `/LOST+FOUND` sit on different devices -- both live under `d/`, but a vault can be
/// assembled across mount points.
///
/// An existing target is refused instead of replaced. `std::fs::rename` silently overwrites a
/// regular file, Java's `Files.move` without `REPLACE_EXISTING` throws -- and this is the one place
/// in the adoption where data could be lost: two children of one orphan that decrypt to the same
/// cleartext name (a half-finished rename in a damaged vault) would otherwise leave one of them
/// gone without a word.
fn move_path(from: &Path, to: &Path) -> io::Result<()> {
    if exists_no_follow(to)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", to.display()),
        ));
    }
    match std::fs::rename(from, to) {
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            copy_recursively(from, to)?;
            if from.symlink_metadata()?.is_dir() {
                std::fs::remove_dir_all(from)
            } else {
                std::fs::remove_file(from)
            }
        }
        other => other,
    }
}

fn copy_recursively(from: &Path, to: &Path) -> io::Result<()> {
    if !from.symlink_metadata()?.is_dir() {
        std::fs::copy(from, to)?;
        return Ok(());
    }
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let name = entry?.file_name();
        copy_recursively(&from.join(&name), &to.join(&name))?;
    }
    Ok(())
}

/// `encrypt(cryptor, clearTextName, dirId)`: the ciphertext name plus its `.c9r` suffix.
fn encrypt_name(ctx: &CheckContext, clear_name: &str, dir_id: &[u8]) -> String {
    format!(
        "{}{CRYPTOMATOR_FILE_SUFFIX}",
        ctx.cryptor
            .file_name_cryptor()
            .encrypt_filename(clear_name, &[dir_id])
    )
}

/// `d/XX/YYYY…` for a 32 character directory id hash, absolute.
fn content_dir_of(ctx: &CheckContext, hash: &str) -> PathBuf {
    let (prefix, rest) = hash.split_at(2);
    ctx.data_dir().join(prefix).join(rest)
}

/// `Files.exists(path, NOFOLLOW_LINKS)`; anything but "not found" is reported instead of being
/// silently treated as "absent", which would send the caller into a `create_new` that fails anyway.
pub(crate) fn exists_no_follow(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// `StandardOpenOption.CREATE_NEW`.
fn create_new_file(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// The last component of a path as a `String`, empty if there is none.
fn file_name_of(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CONTENTS_FILE_NAME, DATA_DIR_NAME, INFLATED_FILE_NAME};
    use crate::crypto::rng::DetRng;
    use crate::fs::long_names::MAX_FILENAME_BUFFER_SIZE;
    use crate::fs::testutil::new_vault;
    use crate::health::{DiagnosticResult, HealthCheck};

    fn vault() -> (tempfile::TempDir, CheckContext) {
        let (dir, cryptor, config) = new_vault(220);
        let ctx = CheckContext::new(dir.path().to_path_buf(), cryptor, config);
        (dir, ctx)
    }

    fn dirid(ctx: &CheckContext) -> Vec<DiagnosticResult> {
        let mut results = Vec::new();
        crate::health::dir_id::DirIdCheck.run(ctx, &mut |r| results.push(r));
        results
    }

    /// An orphaned content directory `d/AA/BBB…` holding the given entries, plus (optionally) the
    /// `dirid.c9r` that lets the fix recover the original names.
    fn orphan(ctx: &CheckContext, dir_id: &str, with_backup: bool) -> PathBuf {
        let hash = ctx.cryptor.file_name_cryptor().hash_directory_id(dir_id);
        let dir = content_dir_of(ctx, &hash);
        std::fs::create_dir_all(&dir).unwrap();
        if with_backup {
            write_dir_id_backup(
                &ctx.cryptor,
                &CiphertextDirectory {
                    dir_id: dir_id.to_owned(),
                    path: dir.clone(),
                },
                &mut DetRng::default(),
            )
            .unwrap();
        }
        dir
    }

    fn adopt(ctx: &CheckContext, orphan: &Path) -> io::Result<()> {
        AdoptOrphan {
            content_dir: ctx.relativize(orphan),
        }
        .apply(ctx)
    }

    /// The one step parent below `/LOST+FOUND`, as a ciphertext directory.
    fn step_parent_of(ctx: &CheckContext, orphan: &Path) -> CiphertextDirectory {
        let hash_name = format!(
            "{}{}",
            file_name_of(orphan.parent().unwrap()),
            file_name_of(orphan)
        );
        let recovery_hash = ctx
            .cryptor
            .file_name_cryptor()
            .hash_directory_id(RECOVERY_DIR_ID);
        let recovery_dir = content_dir_of(ctx, &recovery_hash);
        let cipher = encrypt_name(ctx, &hash_name, RECOVERY_DIR_ID.as_bytes());
        let dir_id =
            std::fs::read_to_string(recovery_dir.join(cipher).join(DIR_FILE_NAME)).unwrap();
        let hash = ctx.cryptor.file_name_cryptor().hash_directory_id(&dir_id);
        CiphertextDirectory {
            path: content_dir_of(ctx, &hash),
            dir_id,
        }
    }

    /// The cleartext names of everything in a content directory, decrypted under its dir id.
    fn cleartext_names(ctx: &CheckContext, dir: &CiphertextDirectory) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&dir.path)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| matches_encrypted_content_pattern(name))
            .map(|name| {
                let path = dir.path.join(&name);
                let shortened = name.ends_with(DEFLATED_FILE_SUFFIX);
                decrypt_orphan_name(ctx, &path, shortened, &dir.dir_id)
                    .unwrap_or_else(|| panic!("{name} decrypts"))
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_clear_name_to_be_shortened_reproduces_the_java_arithmetic() {
        // threshold 220: needed = (220 - 4) / 4 * 3 - 16 = 146, 146 % 17 = 10, so 11 repetitions.
        let name = clear_name_to_be_shortened(220);
        assert_eq!(name.len(), 11 * LONG_NAME_SUFFIX_BASE.len());
        assert_eq!(name.len(), 187);
        assert!(name.starts_with(LONG_NAME_SUFFIX_BASE));
        // A tiny threshold must not panic (Java would throw on a negative repeat count).
        assert!(!clear_name_to_be_shortened(0).is_empty());
    }

    #[test]
    fn the_run_id_is_a_signed_16_bit_number_in_base_32() {
        assert_eq!(run_id(&mut Bytes(vec![0x00, 0x00])), "0");
        assert_eq!(run_id(&mut Bytes(vec![0xff, 0xff])), "-1");
        // 0x0021 = 33 = 1 * 32 + 1
        assert_eq!(run_id(&mut Bytes(vec![0x00, 0x21])), "11");
        // The extremes: 0x8000 = -32768 = -(32^3), 0x7fff = 32767 = 31*(1024 + 32 + 1).
        assert_eq!(run_id(&mut Bytes(vec![0x80, 0x00])), "-1000");
        assert_eq!(run_id(&mut Bytes(vec![0x7f, 0xff])), "vvv");
        // Whatever the bytes, the id stays a short ASCII token.
        let id = run_id(&mut OsRng);
        assert!(!id.is_empty() && id.len() <= 5 && id.is_ascii(), "{id}");
    }

    /// Feeds fixed bytes, so the base-32 conversion can be pinned.
    struct Bytes(Vec<u8>);

    impl Rng for Bytes {
        fn fill(&mut self, buf: &mut [u8]) {
            buf.copy_from_slice(&self.0[..buf.len()]);
        }
    }

    #[test]
    fn the_recovery_dir_is_created_once_and_reused() {
        let (_dir, ctx) = vault();
        let first = prepare_recovery_dir(&ctx).unwrap();
        assert!(first.is_dir());
        let root_hash = ctx
            .cryptor
            .file_name_cryptor()
            .hash_directory_id(ROOT_DIR_ID);
        let dir_file = content_dir_of(&ctx, &root_hash)
            .join(encrypt_name(
                &ctx,
                RECOVERY_DIR_NAME,
                ROOT_DIR_ID.as_bytes(),
            ))
            .join(DIR_FILE_NAME);
        assert_eq!(std::fs::read_to_string(&dir_file).unwrap(), RECOVERY_DIR_ID);
        // Idempotent, and Java writes no dirid.c9r for it.
        assert_eq!(prepare_recovery_dir(&ctx).unwrap(), first);
        assert!(!first.join(DIR_ID_BACKUP_FILE_NAME).exists());

        // A foreign dir id in the LOST+FOUND node is refused instead of being overwritten.
        std::fs::write(&dir_file, b"not-recovery").unwrap();
        let e = prepare_recovery_dir(&ctx).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert!(e.to_string().contains(RECOVERY_DIR_NAME), "{e}");
    }

    #[test]
    fn the_step_parent_keeps_its_dir_id_and_gets_a_backup() {
        let (_dir, ctx) = vault();
        let recovery = prepare_recovery_dir(&ctx).unwrap();
        let first = prepare_step_parent(&ctx, &recovery, "AABBB").unwrap();
        assert!(first.path.is_dir());
        assert_eq!(
            read_dir_id_backup(&ctx.cryptor, &first.path).unwrap(),
            first.dir_id
        );
        // A second run reuses the UUID from the existing dir.c9r and tolerates the backup.
        let second = prepare_step_parent(&ctx, &recovery, "AABBB").unwrap();
        assert_eq!(second.dir_id, first.dir_id);
        assert_eq!(second.path, first.path);
    }

    #[test]
    fn an_orphan_with_a_dir_id_backup_keeps_the_original_names() {
        let (_dir, ctx) = vault();
        let orphan_dir = orphan(&ctx, "lost-dir-id", true);
        for name in ["adopted.txt", "second.txt"] {
            let cipher = encrypt_name(&ctx, name, b"lost-dir-id");
            std::fs::write(orphan_dir.join(cipher), b"payload").unwrap();
        }
        // A file nobody encrypted travels along under its own name.
        std::fs::write(orphan_dir.join("not-ours.txt"), b"foreign").unwrap();

        adopt(&ctx, &orphan_dir).unwrap();

        assert!(!orphan_dir.exists(), "the orphan itself is gone");
        let step_parent = step_parent_of(&ctx, &orphan_dir);
        assert_eq!(
            cleartext_names(&ctx, &step_parent),
            vec!["adopted.txt".to_string(), "second.txt".to_string()]
        );
        assert!(step_parent.path.join("not-ours.txt").is_file());
        assert_eq!(
            std::fs::read(step_parent.path.join("not-ours.txt")).unwrap(),
            b"foreign"
        );
        // The orphan's own backup is not carried over -- the step parent's `dirid.c9r` names the
        // step parent, not the directory that just disappeared.
        assert_eq!(
            read_dir_id_backup(&ctx.cryptor, &step_parent.path).unwrap(),
            step_parent.dir_id
        );
    }

    #[test]
    fn without_a_dir_id_backup_the_nodes_are_numbered_by_type() {
        let (_dir, ctx) = vault();
        let orphan_dir = orphan(&ctx, "no-backup-here", false);
        // One file, one directory (has dir.c9r), one symlink (has symlink.c9r).
        std::fs::write(
            orphan_dir.join("A".repeat(32) + CRYPTOMATOR_FILE_SUFFIX),
            b"x",
        )
        .unwrap();
        let sub_dir = orphan_dir.join("B".repeat(32) + CRYPTOMATOR_FILE_SUFFIX);
        std::fs::create_dir_all(&sub_dir).unwrap();
        std::fs::write(sub_dir.join(DIR_FILE_NAME), b"child-dir-id").unwrap();
        let link = orphan_dir.join("C".repeat(32) + CRYPTOMATOR_FILE_SUFFIX);
        std::fs::create_dir_all(&link).unwrap();
        std::fs::write(link.join(SYMLINK_FILE_NAME), b"target").unwrap();

        adopt(&ctx, &orphan_dir).unwrap();

        let step_parent = step_parent_of(&ctx, &orphan_dir);
        let names = cleartext_names(&ctx, &step_parent);
        assert_eq!(names.len(), 3, "{names:?}");
        // Every name is `<prefix><counter>_<run id>` with the same run id.
        let run = names[0].rsplit('_').next().unwrap().to_owned();
        assert!(
            names.iter().all(|n| n.ends_with(&format!("_{run}"))),
            "{names:?}"
        );
        let prefixes: Vec<&str> = names
            .iter()
            .map(|n| n.split(|c: char| c.is_ascii_digit()).next().unwrap())
            .collect();
        assert_eq!(prefixes, vec![DIR_PREFIX, FILE_PREFIX, SYMLINK_PREFIX]);
    }

    #[test]
    fn a_shortened_orphan_node_stays_shortened_and_gets_a_name_file() {
        let (_dir, ctx) = vault();
        let orphan_dir = orphan(&ctx, "shortened-orphan", false);
        let c9s = orphan_dir.join("D".repeat(32) + DEFLATED_FILE_SUFFIX);
        std::fs::create_dir_all(&c9s).unwrap();
        std::fs::write(c9s.join(CONTENTS_FILE_NAME), b"payload").unwrap();
        std::fs::write(c9s.join(INFLATED_FILE_NAME), b"unreadable.c9r").unwrap();

        adopt(&ctx, &orphan_dir).unwrap();

        let step_parent = step_parent_of(&ctx, &orphan_dir);
        let entries = sorted_entries(&step_parent.path).unwrap();
        let adopted: Vec<String> = entries
            .iter()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| n.ends_with(DEFLATED_FILE_SUFFIX))
            .collect();
        assert_eq!(adopted.len(), 1, "{entries:?}");
        let node = step_parent.path.join(&adopted[0]);
        assert!(node.join(CONTENTS_FILE_NAME).is_file(), "content moved");
        // `name.c9s` was rewritten, and it deflates to exactly the directory it sits in.
        let long_name = std::fs::read_to_string(node.join(INFLATED_FILE_NAME)).unwrap();
        assert_eq!(deflate(&step_parent.path.join(&long_name)).c9s_path, node);
        // The name carries the `_withVeryLongName` padding, so it is long enough to be shortened.
        let clear = decrypt_orphan_name(&ctx, &node, true, &step_parent.dir_id).unwrap();
        assert!(clear.contains(LONG_NAME_SUFFIX_BASE), "{clear}");
        assert!(long_name.len() > ctx.shortening_threshold, "{long_name}");
    }

    #[test]
    fn the_adoption_is_reported_as_a_fix_and_applying_it_twice_is_harmless() {
        let (_dir, ctx) = vault();
        let orphan_dir = orphan(&ctx, "twice", true);
        let cipher = encrypt_name(&ctx, "only.txt", b"twice");
        std::fs::write(orphan_dir.join(cipher), b"payload").unwrap();

        let before = dirid(&ctx);
        let orphan_result = before
            .iter()
            .find(|r| r.kind == "OrphanContentDir")
            .expect("the orphan is reported");
        assert!(orphan_result.fixable(), "Task 5 attaches the adoption");
        let fix = orphan_result.fix.as_ref().unwrap();
        assert!(fix.describe().contains(RECOVERY_DIR_NAME));
        fix.apply(&ctx).unwrap();
        // The orphan is gone, so the second run finds nothing to do.
        fix.apply(&ctx).expect("the second run is a no-op");

        let step_parent = step_parent_of(&ctx, &orphan_dir);
        assert_eq!(cleartext_names(&ctx, &step_parent), vec!["only.txt"]);
        let after = dirid(&ctx);
        assert_eq!(
            after
                .iter()
                .filter(|r| r.kind == "OrphanContentDir")
                .count(),
            0,
            "{after:#?}"
        );
        // What Java leaves behind: the recovery dir has no dirid.c9r of its own.
        assert_eq!(
            after
                .iter()
                .filter(|r| r.kind == "MissingDirIdBackup")
                .count(),
            1,
            "{after:#?}"
        );
    }

    #[test]
    fn an_orphaned_recovery_dir_is_left_alone() {
        let (_dir, ctx) = vault();
        // The recovery content dir itself is the orphan: `prepareRecoveryDir` already re-attached
        // it to the root, so there is nothing left to adopt.
        let recovery = orphan(&ctx, RECOVERY_DIR_ID, false);
        std::fs::write(
            recovery.join("E".repeat(32) + CRYPTOMATOR_FILE_SUFFIX),
            b"x",
        )
        .unwrap();
        adopt(&ctx, &recovery).unwrap();
        assert!(recovery
            .join("E".repeat(32) + CRYPTOMATOR_FILE_SUFFIX)
            .is_file());
        let after = dirid(&ctx);
        assert_eq!(
            after
                .iter()
                .filter(|r| r.kind == "OrphanContentDir")
                .count(),
            0,
            "the recovery dir is referenced by the root now: {after:#?}"
        );
    }

    #[test]
    fn an_oversized_name_file_falls_back_to_a_counter_name() {
        let (_dir, ctx) = vault();
        let orphan_dir = orphan(&ctx, "oversized-name-orphan", true);
        let c9s = orphan_dir.join("D".repeat(32) + DEFLATED_FILE_SUFFIX);
        std::fs::create_dir_all(&c9s).unwrap();
        std::fs::write(c9s.join(CONTENTS_FILE_NAME), b"payload").unwrap();
        // Larger than `MAX_FILENAME_BUFFER_SIZE`: `inflate` refuses to read it at all, so the
        // adoption never sees a name to decrypt and numbers the node instead.
        std::fs::write(
            c9s.join(INFLATED_FILE_NAME),
            vec![b'A'; MAX_FILENAME_BUFFER_SIZE as usize + 1],
        )
        .unwrap();

        adopt(&ctx, &orphan_dir).unwrap();

        let step_parent = step_parent_of(&ctx, &orphan_dir);
        let names = cleartext_names(&ctx, &step_parent);
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].starts_with(FILE_PREFIX), "{names:?}");
        assert!(names[0].contains(LONG_NAME_SUFFIX_BASE), "{names:?}");
    }

    #[test]
    fn a_move_never_replaces_an_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("from");
        let to = dir.path().join("to");
        std::fs::write(&from, b"new").unwrap();
        std::fs::write(&to, b"old").unwrap();

        let error = move_path(&from, &to).expect_err("an existing target is never overwritten");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&to).unwrap(), b"old");
        assert!(from.is_file(), "the source is still there");

        std::fs::remove_file(&to).unwrap();
        move_path(&from, &to).expect("a free target is moved onto");
        assert_eq!(std::fs::read(&to).unwrap(), b"new");
    }

    #[test]
    fn a_vanished_orphan_is_not_an_error() {
        let (_dir, ctx) = vault();
        let fix = AdoptOrphan {
            content_dir: Path::new(DATA_DIR_NAME).join("AA").join("B".repeat(30)),
        };
        fix.apply(&ctx).expect("nothing to adopt");
        // Nothing was created either.
        let hash = ctx
            .cryptor
            .file_name_cryptor()
            .hash_directory_id(RECOVERY_DIR_ID);
        assert!(!content_dir_of(&ctx, &hash).exists());
    }
}
