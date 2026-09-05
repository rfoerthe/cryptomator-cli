//! `crypto fs …`: mount-less access to vault contents.
use crate::cli::{
    FsCommand, FsGetArgs, FsLsArgs, FsMkdirArgs, FsMvArgs, FsPathArgs, FsPutArgs, FsRmArgs,
    FsTreeArgs,
};
use crate::commands::{locked_vault, Ctx};
use crate::exit;
use crate::output::{epoch_seconds, format_timestamp};
use anyhow::{Context, Result};
use cryptomator_app::{read_passphrase, AppError, PasswordArgs, SystemIo};
use cryptomator_core::fs::{
    CleartextPath, CryptoFs, CryptoFsOptions, EventSink, FileAttributes,
    DEFAULT_MAX_CLEARTEXT_NAME_LENGTH,
};
use cryptomator_core::{open_vault, read_vault_config, MasterkeyFileAccess};
use data_encoding::HEXLOWER;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

/// Events are warnings on stderr (never on stdout, which carries data for `cat`/`get -`).
fn warn_sink() -> EventSink {
    Arc::new(|event| eprintln!("warning: {event}"))
}

/// One wording per error kind. The cleartext layer, `std::fs` and the kernel describe the same
/// condition differently ("already exists" vs. "File exists"), and the layer repeats the path that
/// the caller's context line already names, so these kinds are restated in a single, stable form.
fn io_detail(err: io::Error) -> io::Error {
    let phrase = match err.kind() {
        io::ErrorKind::AlreadyExists => "already exists",
        io::ErrorKind::NotFound => "no such file or directory",
        io::ErrorKind::IsADirectory => "is a directory",
        io::ErrorKind::NotADirectory => "not a directory",
        io::ErrorKind::DirectoryNotEmpty => "directory not empty",
        io::ErrorKind::ReadOnlyFilesystem => "vault is opened read-only",
        _ => return err,
    };
    io::Error::new(err.kind(), phrase)
}

/// Unlocks a registered LOCKED vault for mount-less access. Hub vaults are rejected before the
/// password is read; `usesReadOnlyMode` makes write commands fail with exit 5.
pub fn open_fs(
    ctx: &Ctx,
    reference: &str,
    password: &PasswordArgs,
    needs_write: bool,
) -> Result<CryptoFs> {
    let (vault, path) = locked_vault(ctx, reference)?;
    // Reject Hub and unsupported key ids before asking for any passphrase.
    read_vault_config(&path)?
        .key_id()?
        .require_masterkey_file()?;
    if needs_write && vault.uses_read_only_mode {
        return Err(AppError::WrongState {
            expected: "writable vault".to_string(),
            actual: "usesReadOnlyMode=true (read-only)".to_string(),
        }
        .into());
    }
    let passphrase = read_passphrase(password, "Password: ", &mut SystemIo)?;
    let opened = open_vault(&path, &MasterkeyFileAccess::new(Vec::new()), &passphrase)?;
    // `maxCleartextFilenameLength` is -1 ("probe on unlock") by default; anything unusable falls
    // back to the cryptofs default instead of rejecting every name.
    let max_cleartext_name_length = usize::try_from(vault.max_cleartext_filename_length)
        .ok()
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_CLEARTEXT_NAME_LENGTH);
    Ok(CryptoFs::open(
        opened,
        CryptoFsOptions {
            read_only: vault.uses_read_only_mode,
            max_cleartext_name_length,
            events: warn_sink(),
        },
    ))
}

pub fn run(ctx: &Ctx, command: FsCommand) -> Result<u8> {
    match command {
        FsCommand::Ls(args) => ls(ctx, args),
        FsCommand::Tree(args) => tree(ctx, args),
        FsCommand::Cat(args) => cat(ctx, args),
        FsCommand::Get(args) => get(ctx, args),
        FsCommand::Put(args) => put(ctx, args),
        FsCommand::Rm(args) => rm(ctx, args),
        FsCommand::Mkdir(args) => mkdir(ctx, args),
        FsCommand::Mv(args) => mv(ctx, args),
    }
}

fn entry_json(name: &str, path: &str, attrs: &FileAttributes, target: Option<&str>) -> Value {
    let mut value = json!({ "name": name, "path": path, "type": attrs.file_type.as_str() });
    if attrs.is_file() {
        value["size"] = json!(attrs.size);
    }
    value["modified"] = attrs
        .modified
        .map(|t| json!(epoch_seconds(t)))
        .unwrap_or(Value::Null);
    if let Some(target) = target {
        value["target"] = json!(target);
    }
    value
}

/// `read_dir` sorts by UTF-8 bytes; the Java fixture generator compares `Path.toString()`, i.e. by
/// UTF-16 code units. The two differ above the BMP, so listings are re-sorted the Java way.
fn utf16_key(name: &str) -> Vec<u16> {
    name.encode_utf16().collect()
}

/// One entry of a listing.
struct Row {
    name: String,
    path: CleartextPath,
    attrs: FileAttributes,
    /// Only symlinks have one; `ls -l` and `fs tree` show it instead of a size.
    target: Option<String>,
}

/// The children of `dir` with their own attributes (symlinks are not followed).
fn children(fs: &CryptoFs, dir: &CleartextPath) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for entry in fs.read_dir(dir).map_err(io_detail)? {
        let path = dir.join(&entry.cleartext_name)?;
        let attrs = fs.symlink_metadata(&path).map_err(io_detail)?;
        let target = if attrs.is_symlink() {
            Some(fs.read_link(&path).map_err(io_detail)?)
        } else {
            None
        };
        rows.push(Row {
            name: entry.cleartext_name,
            path,
            attrs,
            target,
        });
    }
    rows.sort_by_key(|row| utf16_key(&row.name));
    Ok(rows)
}

fn ls(ctx: &Ctx, args: FsLsArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let dir = CleartextPath::parse(&args.path);
    let rows = children(&fs, &dir).with_context(|| format!("cannot list {dir}"))?;
    let payload: Vec<Value> = rows
        .iter()
        .map(|row| {
            entry_json(
                &row.name,
                &row.path.to_string(),
                &row.attrs,
                row.target.as_deref(),
            )
        })
        .collect();
    ctx.out.emit(Value::Array(payload), || {
        rows.iter()
            .map(
                |Row {
                     name,
                     attrs,
                     target,
                     ..
                 }| {
                    if args.long {
                        let kind = match attrs.file_type.as_str() {
                            "dir" => 'd',
                            "symlink" => 'l',
                            _ => 'f',
                        };
                        let size = if attrs.is_file() {
                            attrs.size.to_string()
                        } else {
                            "-".to_string()
                        };
                        let modified = attrs
                            .modified
                            .map(format_timestamp)
                            .unwrap_or_else(|| "-".repeat(19));
                        let suffix = target
                            .as_deref()
                            .map(|t| format!(" -> {t}"))
                            .unwrap_or_default();
                        format!("{kind} {size:>10} {modified}  {name}{suffix}")
                    } else if attrs.is_dir() {
                        format!("{name}/")
                    } else {
                        name.clone()
                    }
                },
            )
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    Ok(exit::OK)
}

/// `sha2` 0.11 hashers no longer implement `io::Write`, so this adapter feeds the cleartext stream
/// of `copy_to_writer` into the digest.
struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Depth-first, sorted like the Java fixture generator (by cleartext path).
fn walk(fs: &CryptoFs, dir: &CleartextPath, hash: bool, out: &mut Vec<Value>) -> Result<()> {
    for row in children(fs, dir)? {
        let path = row.path;
        let mut value = json!({ "path": path.to_string(), "type": row.attrs.file_type.as_str() });
        if let Some(target) = row.target {
            value["target"] = json!(target);
        } else if row.attrs.is_file() {
            value["size"] = json!(row.attrs.size);
            if hash {
                let mut hasher = HashWriter(Sha256::new());
                let size = fs
                    .copy_to_writer(&path, &mut hasher)
                    .map_err(io_detail)
                    .with_context(|| format!("cannot read {path}"))?;
                value["size"] = json!(size);
                value["sha256"] = json!(HEXLOWER.encode(&hasher.0.finalize()));
            }
        }
        out.push(value);
        if row.attrs.is_dir() {
            walk(fs, &path, hash, out)?;
        }
    }
    Ok(())
}

fn tree(ctx: &Ctx, args: FsTreeArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let root = CleartextPath::parse(&args.path);
    let mut entries = Vec::new();
    walk(&fs, &root, args.hash, &mut entries).with_context(|| format!("cannot walk {root}"))?;
    ctx.out.emit(Value::Array(entries.clone()), || {
        entries
            .iter()
            .filter_map(|e| e["path"].as_str().map(str::to_string))
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    Ok(exit::OK)
}

fn cat(ctx: &Ctx, args: FsPathArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let path = CleartextPath::parse(&args.path);
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    fs.copy_to_writer(&path, &mut lock)
        .map_err(io_detail)
        .with_context(|| format!("cannot read {path}"))?;
    Ok(exit::OK)
}

fn get(ctx: &Ctx, args: FsGetArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let path = CleartextPath::parse(&args.path);
    if args.local == Path::new("-") {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        fs.copy_to_writer(&path, &mut lock)
            .map_err(io_detail)
            .with_context(|| format!("cannot read {path}"))?;
        return Ok(exit::OK);
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .create_new(!args.force)
        .truncate(true)
        .open(&args.local)
        .map_err(io_detail)
        .with_context(|| format!("cannot create {}", args.local.display()))?;
    let bytes = fs
        .copy_to_writer(&path, &mut file)
        .map_err(io_detail)
        .with_context(|| format!("cannot read {path}"))?;
    ctx.out.emit(
        json!({ "path": path.to_string(), "local": args.local, "bytes": bytes }),
        || format!("{path} -> {} ({bytes} bytes)", args.local.display()),
    )?;
    Ok(exit::OK)
}

fn put(ctx: &Ctx, args: FsPutArgs) -> Result<u8> {
    let from_stdin = args.local == Path::new("-");
    if from_stdin && args.password.password_stdin {
        return Err(AppError::InvalidValue {
            key: "--password-stdin".to_string(),
            message: "standard input already carries the file content".to_string(),
        }
        .into());
    }
    let fs = open_fs(ctx, &args.vault, &args.password, true)?;
    let path = CleartextPath::parse(&args.path);
    let bytes = if from_stdin {
        let stdin = io::stdin();
        let mut lock = stdin.lock();
        fs.write_from_reader(&path, &mut lock, args.force)
    } else {
        let mut file = std::fs::File::open(&args.local)
            .map_err(io_detail)
            .with_context(|| format!("cannot open {}", args.local.display()))?;
        fs.write_from_reader(&path, &mut file, args.force)
    }
    .map_err(io_detail)
    .with_context(|| format!("cannot write {path}"))?;
    ctx.out
        .emit(json!({ "path": path.to_string(), "bytes": bytes }), || {
            format!("{path} ({bytes} bytes)")
        })?;
    Ok(exit::OK)
}

fn rm(ctx: &Ctx, args: FsRmArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, true)?;
    let path = CleartextPath::parse(&args.path);
    if args.recursive {
        fs.delete_recursive(&path)
    } else {
        fs.delete(&path)
    }
    .map_err(io_detail)
    .with_context(|| format!("cannot delete {path}"))?;
    ctx.out.emit(json!({ "deleted": path.to_string() }), || {
        format!("deleted {path}")
    })?;
    Ok(exit::OK)
}

fn mkdir(ctx: &Ctx, args: FsMkdirArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, true)?;
    let path = CleartextPath::parse(&args.path);
    if args.parents {
        fs.create_dir_all(&path)
    } else {
        fs.create_dir(&path)
    }
    .map_err(io_detail)
    .with_context(|| format!("cannot create {path}"))?;
    ctx.out.emit(json!({ "created": path.to_string() }), || {
        format!("created {path}")
    })?;
    Ok(exit::OK)
}

fn mv(ctx: &Ctx, args: FsMvArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, true)?;
    let src = CleartextPath::parse(&args.source);
    let dst = CleartextPath::parse(&args.destination);
    fs.rename(&src, &dst, args.force)
        .map_err(io_detail)
        .with_context(|| format!("cannot move {src} to {dst}"))?;
    ctx.out.emit(
        json!({ "from": src.to_string(), "to": dst.to_string() }),
        || format!("{src} -> {dst}"),
    )?;
    Ok(exit::OK)
}
