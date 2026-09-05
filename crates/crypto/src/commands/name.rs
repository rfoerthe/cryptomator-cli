//! `crypto name …`: cleartext ↔ ciphertext file name conversion.
use crate::cli::{NameCommand, NameDecryptArgs, NameLocateArgs};
use crate::commands::fs::{io_detail, open_fs};
use crate::commands::Ctx;
use crate::exit;
use anyhow::{Context, Result};
use cryptomator_core::fs::{decrypt_filename, CleartextPath};
use serde_json::{json, Value};

pub fn run(ctx: &Ctx, command: NameCommand) -> Result<u8> {
    match command {
        NameCommand::Decrypt(args) => decrypt(ctx, args),
        NameCommand::Locate(args) => locate(ctx, args),
    }
}

/// All paths are processed; the exit code is 1 if any of them failed.
fn decrypt(ctx: &Ctx, args: NameDecryptArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let mut failed = false;
    let rows: Vec<Value> = args
        .paths
        .iter()
        .map(|path| {
            // Paths come from the shell and may not be UTF-8: rendered lossily instead of failing
            // the whole run in `serde_json`.
            let shown = path.display().to_string();
            match decrypt_filename(fs.vault_path(), fs.cryptor_ref(), path) {
                Ok(name) => json!({ "ciphertext": shown, "cleartext": name }),
                Err(e) => {
                    failed = true;
                    json!({ "ciphertext": shown, "error": e.to_string() })
                }
            }
        })
        .collect();
    ctx.out.emit(Value::Array(rows.clone()), || {
        rows.iter()
            .map(|row| {
                let ciphertext = row["ciphertext"].as_str().unwrap_or_default();
                match row.get("cleartext").and_then(Value::as_str) {
                    Some(name) => format!("{ciphertext}\t{name}"),
                    None => format!(
                        "{ciphertext}\terror: {}",
                        row["error"].as_str().unwrap_or_default()
                    ),
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    Ok(if failed { exit::GENERAL } else { exit::OK })
}

fn locate(ctx: &Ctx, args: NameLocateArgs) -> Result<u8> {
    let fs = open_fs(ctx, &args.vault, &args.password, false)?;
    let path = CleartextPath::parse(&args.path);
    let file_type = fs
        .mapper()
        .ciphertext_file_type(&path)
        .map_err(io_detail)
        .with_context(|| format!("cannot locate {path}"))?;
    // The root has no node of its own, so it is always shown as its content directory.
    let ciphertext = if args.contents || path.is_root() {
        fs.ciphertext_path(&path)
    } else {
        fs.mapper()
            .ciphertext_file_path(&path)
            .map(|node| node.raw_path().to_path_buf())
    }
    .map_err(io_detail)
    .with_context(|| format!("cannot locate {path}"))?;
    let ciphertext = ciphertext.display().to_string();
    ctx.out.emit(
        json!({
            "cleartext": path.to_string(),
            "ciphertext": ciphertext,
            "type": file_type.as_str(),
        }),
        || ciphertext.clone(),
    )?;
    Ok(exit::OK)
}
