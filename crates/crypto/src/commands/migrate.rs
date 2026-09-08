//! `crypto migrate`: bring a vault of format 5, 6 or 7 up to format 8.
//!
//! The command is the CLI's answer to the desktop app's migration dialog, and it has the same two
//! jobs: say what is about to happen, and make sure the user agreed to it. A migration renames
//! every file in the vault and rewrites `masterkey.cryptomator`; it cannot be undone, and there is
//! no partial success to fall back on. So:
//!
//! * `--dry-run` prints the chain of steps and every rename the 6 → 7 step would make, and writes
//!   nothing at all -- not even the capability probe, see [`MigrationOptions::dry_run`];
//! * without `--dry-run` the user confirms on the terminal, or passes `--yes`. Without either --
//!   a script, a cron job, a pipe -- the command refuses (exit code 2) rather than migrating
//!   something nobody watched.
//!
//! Everything the command says while it works goes to **stderr**, so `--json` leaves exactly one
//! object on stdout.
use crate::cli::MigrateArgs;
use crate::commands::password::update_keychain_entry_or_warn;
use crate::commands::{backup_files, keychain_source, migratable_vault, Ctx};
use crate::exit;
use anyhow::Result;
use cryptomator_app::{decompose_passphrase, read_passphrase_with_keychain, AppError, SystemIo};
use cryptomator_core::migration::{
    self, MigrationEvent, MigrationOptions, MigrationPlan, MigrationStep, VaultVersion,
};
use cryptomator_core::CoreError;
use serde_json::{json, Value};
use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// How often the rename pass reports its progress on stderr. One line per file would be thousands
/// of lines for a vault of any size, and the count is the only interesting part of them.
const PROGRESS_EVERY: u64 = 100;

pub fn run(ctx: &Ctx, args: MigrateArgs) -> Result<u8> {
    // Before the version is even read: a vault a daemon is serving must be refused whatever format
    // it is in, and that includes the format 8 vault that would otherwise be waved through below.
    let (vault, path) = migratable_vault(ctx, &args.vault)?;
    let label = vault
        .display_name
        .clone()
        .unwrap_or_else(|| vault.id.clone());
    // An unsupported format (0..=4, or something from the future) fails here with
    // `CoreError::UnsupportedVaultVersion` -- exit code 5, message included.
    let from = migration::detect_version(&path)?;
    let steps = chain(from);
    let step_names: Vec<&str> = steps.iter().map(|step| step.as_str()).collect();

    if steps.is_empty() {
        ctx.out.emit(
            json!({
                "vault": vault.id,
                "path": path,
                "from": from.number(),
                "to": from.number(),
                "steps": step_names,
                "migrated": false,
            }),
            || format!("Vault {label} is already at format {from}; nothing to migrate"),
        )?;
        return Ok(exit::OK);
    }

    // Not when a confirmation is about to be asked: `confirm` below prints its own sentence
    // covering the same format-and-steps information, and printing it twice (once here, once in
    // the prompt) is just noise. `--yes` and `--dry-run` never reach `confirm`, so they keep this
    // line as their only announcement.
    if args.yes || args.dry_run {
        note(
            ctx,
            format!(
                "Vault {label} is at format {from}; migrating to {} via {}",
                VaultVersion::LATEST,
                step_names.join(", ")
            ),
        );
    }
    // Lazy keychain, exactly as `health` and `fs` have it: a scripted `--password-stdin` run never
    // pays for the provider probe. `keychain_resolved` remembers whether this closure actually ran
    // and found one, so the keychain-update step below (which needs the same information) can
    // reuse it instead of probing a second time -- see there.
    let mut keychain_resolved = false;
    let passphrase = read_passphrase_with_keychain(
        &args.password,
        "Password: ",
        || {
            let source = keychain_source(ctx.keychain()?.as_ref(), &vault);
            keychain_resolved = source.is_some();
            Ok(source)
        },
        &mut SystemIo,
    )?;

    if args.dry_run {
        // `plan` reads the whole of `d/` and verifies the passphrase; it is the only place the CLI
        // calls it, so no run pays for scrypt twice.
        let (plan, _) = with_legacy_passphrase(from, &passphrase, |passphrase| {
            Ok(migration::plan(&path, passphrase)?)
        })?;
        ctx.out.emit(
            json!({
                "vault": vault.id,
                "path": path,
                "from": plan.from.number(),
                "to": plan.to.number(),
                "steps": step_names,
                "renames": renames_json(&plan),
                "dryRun": true,
            }),
            || render_dry_run(&label, &plan),
        )?;
        return Ok(exit::OK);
    }

    if !args.yes && !confirm(&label, from, &step_names)? {
        ctx.out
            .emit(aborted_json(&vault.id, &path, from, &step_names), || {
                "aborted".to_string()
            })?;
        return Ok(exit::OK);
    }

    // Every step that rewrites `masterkey.cryptomator` backs the old file up first, and the core
    // does not report where. Which of them are new is the difference between these two listings --
    // the legacy vaults usually carry a `.bkup` of their own from the cryptofs release that wrote
    // them, and telling the user to keep *that* one would be wrong.
    let backups_before = backup_files(&path);
    let mut renamed = 0u64;
    let mut reported = 0u64;
    let json_output = ctx.out.json;
    let outcome = with_legacy_passphrase(from, &passphrase, |passphrase| {
        renamed = 0;
        reported = 0;
        let mut progress = |event: MigrationEvent| {
            if let MigrationEvent::StepProgress { done, .. } = event {
                renamed = done;
            }
            if !json_output {
                if let Some(line) = progress_line(event, &mut reported) {
                    eprintln!("  {line}");
                }
            }
        };
        Ok(migration::migrate(
            &path,
            passphrase,
            MigrationOptions {
                // The confirmation above (or `--yes`) *is* our version of Java's
                // `REQUIRES_FULL_VAULT_DIR_SCAN` dialog: a storage that cannot hold 220-character
                // names has to be walked before the 6 → 7 step can promise anything, and asking a
                // second question in the middle of a migration is not something a CLI can do.
                full_scan_allowed: true,
                dry_run: false,
            },
            &mut progress,
        )?)
    });
    // This is the one command that cannot be undone by re-running it with different arguments --
    // a chain that dies between two steps (a storage limit in 6 → 7, a permission lost mid-write)
    // leaves the vault at whatever format it reached, and `--json` suppresses every step line
    // above, so the error is the only thing that says the vault moved at all. The core resumes
    // from whatever `detect_version` reports (`migration::migrate`'s doc comment), so re-reading
    // it here and naming it in the error is also the correct instruction, not just reassurance.
    let (reached, used) = outcome.map_err(|err| stopped_at(err, &path, &args.vault))?;

    // The passphrase of a format 5 vault becomes its NFC form in the 5 → 6 step, so a stored one
    // has to follow -- otherwise the next implicit-keychain unlock would fail with a password the
    // user never got wrong. `update_keychain_entry_or_warn` writes only when something is stored,
    // and a keychain that refuses is a warning: the vault is migrated either way.
    //
    // Gated on `keychain_resolved`, not just `*used != *passphrase`: `update_keychain_entry` calls
    // `ctx.keychain()` too, and without this gate a `--password-stdin` run that hit the format 5
    // NFD retry would pay for the provider probe here even though the read above never needed it
    // -- the opposite of what this function's first comment promises. `keychain_resolved` is only
    // ever `true` when that probe already ran (and is thus cached), so this adds no new cost.
    let keychain_updated = *used != *passphrase
        && keychain_resolved
        && update_keychain_entry_or_warn(
            ctx,
            &vault,
            &passphrase,
            &args.vault,
            "normalised by the migration",
        );

    let backups: Vec<PathBuf> = backup_files(&path)
        .difference(&backups_before)
        .cloned()
        .collect();
    ctx.out.emit(
        json!({
            "vault": vault.id,
            "path": path,
            "from": from.number(),
            "to": reached.number(),
            "steps": step_names,
            "migrated": true,
            "renamed": renamed,
            "backups": backups,
            "keychainUpdated": keychain_updated,
        }),
        || {
            render_result(
                &label,
                from,
                reached,
                &args.vault,
                &backups,
                keychain_updated,
            )
        },
    )?;
    Ok(exit::OK)
}

/// Adds "where it stopped, and how to go on" to an error out of `migration::migrate`.
///
/// Re-reads the format rather than trusting `from`: the whole point is to say where the vault
/// *actually* ended up, and a chain that got through one or more steps before failing is already
/// past `from`. When even that re-read fails -- the vault directory itself became unreadable, say
/// -- `err` is returned as it came in; a second error about the first would only obscure it.
fn stopped_at(err: anyhow::Error, path: &Path, reference: &str) -> anyhow::Error {
    match migration::detect_version(path) {
        Ok(now) => err.context(format!(
            "migration stopped: the vault is now at format {now}; run `crypto migrate {reference}` \
             again to continue where it stopped"
        )),
        Err(_) => err,
    }
}

/// The `*.bkup` files directly in the vault directory. Unreadable directory: an empty set, because
/// this only ever feeds a message -- the migration itself has long since said whether it worked.
/// The steps from `from` up to [`VaultVersion::LATEST`]; empty when there is nothing to do.
///
/// Computed here rather than through [`migration::plan`] on purpose: naming the chain needs no
/// passphrase, and the header line is printed before the password is asked for.
fn chain(from: VaultVersion) -> Vec<MigrationStep> {
    let mut steps = Vec::new();
    let mut version = from;
    while let Some(step) = MigrationStep::from_version(version) {
        steps.push(step);
        version = step.to();
    }
    steps
}

/// Runs `attempt` with the passphrase as the CLI read it and, for a format 5 vault only, with its
/// canonical decomposition when the first form is refused. Returns what `attempt` produced
/// together with the form that worked.
///
/// Every passphrase this CLI reads is NFC-normalised ([`cryptomator_app::normalize_passphrase`],
/// the desktop app's `SecurePasswordField` rule). A format 5 vault predates that rule: Cryptomator
/// 1.3 wrapped the masterkey with whatever the operating system put into the password field, which
/// on macOS is the decomposed form -- and normalising it is precisely what the 5 → 6 step does. So
/// the same keystrokes can need either form here, and only here: from format 6 on there is one
/// form and one only.
///
/// The second attempt costs a second scrypt derivation, which is why it is not made when the two
/// forms are equal (every ASCII passphrase) or when the first attempt failed for any other reason.
/// Nothing is written before the passphrase is checked -- [`migration::migrate`] verifies it ahead
/// of the first step -- so a refused first attempt leaves the vault untouched.
fn with_legacy_passphrase<T>(
    from: VaultVersion,
    passphrase: &Zeroizing<String>,
    mut attempt: impl FnMut(&str) -> Result<T>,
) -> Result<(T, Zeroizing<String>)> {
    match attempt(passphrase) {
        Ok(value) => Ok((value, passphrase.clone())),
        Err(err) if from == VaultVersion::V5 && is_invalid_passphrase(&err) => {
            let decomposed = decompose_passphrase(passphrase);
            if *decomposed == **passphrase {
                return Err(err);
            }
            let value = attempt(&decomposed)?;
            Ok((value, decomposed))
        }
        Err(err) => Err(err),
    }
}

/// Whether `err` is "that is not the passphrase of this vault", wherever in the chain it sits.
fn is_invalid_passphrase(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<CoreError>(),
            Some(CoreError::InvalidPassphrase)
        ) || matches!(
            cause.downcast_ref::<AppError>(),
            Some(AppError::Core(CoreError::InvalidPassphrase))
        )
    })
}

/// One line on stderr for an event, or `None` for the progress events between two reports.
fn progress_line(event: MigrationEvent, reported: &mut u64) -> Option<String> {
    match event {
        MigrationEvent::StepStarted { step } => Some(format!("step {step} …")),
        MigrationEvent::StepProgress { step, done, total } => {
            // The last one always, so the line the user is left with is the final count.
            (done == total || done - *reported >= PROGRESS_EVERY).then(|| {
                *reported = done;
                format!("{step}: {done}/{total} entries")
            })
        }
        MigrationEvent::StepFinished { step, version } => Some(format!(
            "step {step} done; the vault is at format {version}"
        )),
    }
}

/// The `[y/N]` question, on stderr so it is visible next to a `--json` run's stdout.
///
/// Only ever reached with a terminal on stdin: without one there is nobody to answer, and
/// migrating anyway is the one thing this command must not do.
fn confirm(label: &str, from: VaultVersion, steps: &[&str]) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        return Err(AppError::InvalidValue {
            key: "--yes".to_string(),
            message: "refusing to migrate without --yes: there is no terminal to ask for a \
                      confirmation at"
                .to_string(),
        }
        .into());
    }
    // Not through `note`: a question needs the sentence it is about, `--json` or not.
    eprintln!(
        "Vault {label} is in format {from} and will be migrated to format {} ({}).\n\
         This rewrites the file names in the vault and cannot be undone; make sure you have a \
         backup.",
        VaultVersion::LATEST,
        steps.join(", ")
    );
    eprint!("Migrate now? [y/N] ");
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// A line of running commentary. Suppressed by `--json`, whose caller wants one object and nothing
/// else; stderr, so it never mixes into stdout even then.
fn note(ctx: &Ctx, text: String) {
    if !ctx.out.json {
        eprintln!("{text}");
    }
}

/// The JSON contract for `crypto migrate`: every object this command emits names the format
/// numbers `from`/`to` (never the brief's `fromVersion`/`toVersion`), and a single planned rename
/// is `{old, new}` (never `{from, to}`, which would collide with the format keys on the same
/// object). This is the shape actually shipped and pinned by `tests/cli_migrate.rs` -- a
/// deliberate, if undocumented, deviation from the brief, not a draft to rename later.
fn renames_json(plan: &MigrationPlan) -> Vec<Value> {
    plan.renames
        .iter()
        .map(|rename| json!({ "old": rename.from, "new": rename.to }))
        .collect()
}

/// The object for the one outcome that stops at the `[y/N]` prompt: the same four keys every
/// other outcome carries (`path`, `from`, `to`, `steps`), plus `migrated: false` and `aborted:
/// true`. `to` is [`VaultVersion::LATEST`] -- what the migration would have reached, since nothing
/// ran.
fn aborted_json(vault_id: &str, path: &Path, from: VaultVersion, steps: &[&str]) -> Value {
    json!({
        "vault": vault_id,
        "path": path,
        "from": from.number(),
        "to": VaultVersion::LATEST.number(),
        "steps": steps,
        "migrated": false,
        "aborted": true,
    })
}

fn render_dry_run(label: &str, plan: &MigrationPlan) -> String {
    let mut lines: Vec<String> = plan
        .renames
        .iter()
        .map(|rename| format!("{} → {}", rename.from.display(), rename.to.display()))
        .collect();
    lines.push(format!(
        "{} would be migrated from format {} to format {}: {} rename(s), nothing was changed \
         (--dry-run)",
        label,
        plan.from,
        plan.to,
        plan.renames.len()
    ));
    if !plan.renames.is_empty() {
        // `MigrationPlan::renames` lists what each name *would* become; two sources landing on the
        // same target are both listed with it and the migration itself appends `_1`, `_2`.
        lines.push(
            "Names that collide get a _1, _2 … suffix when the migration reaches them.".to_string(),
        );
    }
    lines.join("\n")
}

fn render_result(
    label: &str,
    from: VaultVersion,
    reached: VaultVersion,
    reference: &str,
    backups: &[PathBuf],
    keychain_updated: bool,
) -> String {
    let mut lines = vec![format!("Migrated {label} from format {from} to {reached}")];
    if backups.is_empty() {
        // Only when every step found its backup already there, byte for byte: `attempt_backup`
        // never overwrites one.
        lines.push(
            "The previous key files were already backed up next to masterkey.cryptomator (*.bkup)"
                .to_string(),
        );
    } else {
        lines.push("The previous key files were kept as:".to_string());
        lines.extend(backups.iter().map(|path| format!("  {}", path.display())));
    }
    if keychain_updated {
        lines.push("The stored password in the keychain was updated.".to_string());
    }
    // Formats 7 and earlier never wrote `dirid.c9r`, so a freshly migrated vault reports
    // `MissingDirIdBackup` for every content directory -- INFO findings, and the one repair a
    // migration cannot do for itself. Unconditional, not a live branch: `render_result` is only
    // reached when `steps` was non-empty, and every chain starts at V5, V6 or V7 -- there is no
    // migrated vault for which this hint would not apply.
    lines.push(format!(
        "hint: run `crypto health {reference} --fix --fix-severity INFO` to write the \
         directory-id backups format 7 vaults lack"
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptomator_core::PlannedRename;
    use std::path::PathBuf;

    fn a_plan(from: VaultVersion, renames: Vec<(&str, &str)>) -> MigrationPlan {
        MigrationPlan {
            from,
            to: VaultVersion::LATEST,
            steps: chain(from),
            renames: renames
                .into_iter()
                .map(|(from, to)| PlannedRename {
                    from: PathBuf::from(from),
                    to: PathBuf::from(to),
                })
                .collect(),
        }
    }

    #[test]
    fn the_chain_stops_at_the_current_format() {
        assert_eq!(
            chain(VaultVersion::V5)
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            ["5->6", "6->7", "7->8"]
        );
        assert_eq!(
            chain(VaultVersion::V7)
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            ["7->8"]
        );
        assert!(chain(VaultVersion::V8).is_empty());
    }

    #[test]
    fn the_aborted_object_carries_the_same_keys_as_every_other_outcome() {
        let value = aborted_json(
            "v1",
            Path::new("/vaults/v1"),
            VaultVersion::V6,
            &["6->7", "7->8"],
        );
        assert_eq!(value["vault"], "v1");
        assert_eq!(value["path"], "/vaults/v1");
        assert_eq!(value["from"], 6);
        assert_eq!(value["to"], 8, "what the migration would have reached");
        assert_eq!(value["steps"], serde_json::json!(["6->7", "7->8"]));
        assert_eq!(value["migrated"], false);
        assert_eq!(value["aborted"], true);
    }

    #[test]
    fn the_dry_run_lists_every_rename_and_says_it_changed_nothing() {
        let plan = a_plan(
            VaultVersion::V6,
            vec![("d/AB/CD/OLDNAME", "d/AB/CD/new.c9r")],
        );
        let text = render_dry_run("legacy", &plan);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "d/AB/CD/OLDNAME → d/AB/CD/new.c9r");
        assert!(lines[1].contains("from format 6 to format 8"), "{text}");
        assert!(lines[1].contains("1 rename(s)"), "{text}");
        assert!(lines[1].contains("--dry-run"), "{text}");
        assert!(lines[2].contains("_1, _2"), "{text}");

        // A 7 → 8 vault renames nothing, and then the collision note has nothing to warn about.
        let text = render_dry_run("legacy", &a_plan(VaultVersion::V7, vec![]));
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("0 rename(s)"), "{text}");
    }

    #[test]
    fn the_result_names_the_backups_and_points_at_the_health_fix() {
        let text = render_result(
            "legacy_v6",
            VaultVersion::V6,
            VaultVersion::V8,
            "legacy_v6",
            &[PathBuf::from(
                "/vaults/legacy_v6/masterkey.cryptomator.AABBCCDD.bkup",
            )],
            false,
        );
        assert!(
            text.starts_with("Migrated legacy_v6 from format 6 to 8"),
            "{text}"
        );
        assert!(
            text.contains("  /vaults/legacy_v6/masterkey.cryptomator.AABBCCDD.bkup"),
            "{text}"
        );
        assert!(
            text.contains("crypto health legacy_v6 --fix --fix-severity INFO"),
            "{text}"
        );
        assert!(!text.contains("keychain"), "{text}");

        let text = render_result("v5", VaultVersion::V5, VaultVersion::V8, "v5", &[], true);
        assert!(text.contains("already backed up"), "{text}");
        assert!(
            text.contains("The stored password in the keychain was updated."),
            "{text}"
        );
    }

    /// The progress lines: both step boundaries, one line per [`PROGRESS_EVERY`] entries, and the
    /// final count whatever the total is.
    #[test]
    fn the_progress_lines_thin_out_the_per_file_events() {
        let step = MigrationStep::SixToSeven;
        let mut reported = 0;
        assert_eq!(
            progress_line(MigrationEvent::StepStarted { step }, &mut reported),
            Some("step 6->7 …".to_string())
        );
        let total = 250;
        let reported_lines: Vec<String> = (1..=total)
            .filter_map(|done| {
                progress_line(
                    MigrationEvent::StepProgress { step, done, total },
                    &mut reported,
                )
            })
            .collect();
        assert_eq!(
            reported_lines,
            [
                "6->7: 100/250 entries",
                "6->7: 200/250 entries",
                "6->7: 250/250 entries",
            ]
        );
        assert_eq!(
            progress_line(
                MigrationEvent::StepFinished {
                    step,
                    version: VaultVersion::V7
                },
                &mut reported
            ),
            Some("step 6->7 done; the vault is at format 7".to_string())
        );
    }

    /// The retry exists for one format and one error; everything else is reported as it is.
    #[test]
    fn only_a_format_five_vault_is_tried_with_the_decomposed_passphrase() {
        // Written composed in the source, i.e. already NFC.
        let nfc = Zeroizing::new("tästpaß".to_string());
        let nfd = decompose_passphrase(&nfc);
        assert_ne!(*nfd, *nfc);

        // Format 5: the second form is tried and its result is handed back with it.
        let mut seen: Vec<String> = Vec::new();
        let (value, used) = with_legacy_passphrase(VaultVersion::V5, &nfc, |passphrase| {
            seen.push(passphrase.to_string());
            if passphrase == nfd.as_str() {
                Ok(42)
            } else {
                Err(CoreError::InvalidPassphrase.into())
            }
        })
        .expect("the decomposed form opens it");
        assert_eq!(value, 42);
        assert_eq!(*used, *nfd);
        assert_eq!(seen, vec![nfc.to_string(), nfd.to_string()]);

        // Format 6: one attempt, and the error stands.
        let mut attempts = 0;
        let err = with_legacy_passphrase(VaultVersion::V6, &nfc, |_| {
            attempts += 1;
            Err::<(), _>(CoreError::InvalidPassphrase.into())
        })
        .expect_err("no retry above format 5");
        assert_eq!(attempts, 1);
        assert!(is_invalid_passphrase(&err));

        // Format 5, but the failure is not about the passphrase: no second scrypt either.
        let mut attempts = 0;
        with_legacy_passphrase(VaultVersion::V5, &nfc, |_| {
            attempts += 1;
            Err::<(), _>(CoreError::MigrationBlocked("no".to_string()).into())
        })
        .expect_err("the error stands");
        assert_eq!(attempts, 1);

        // An ASCII passphrase has one form, so the retry cannot help and is not made.
        let ascii = Zeroizing::new("plain-ascii".to_string());
        let mut attempts = 0;
        with_legacy_passphrase(VaultVersion::V5, &ascii, |_| {
            attempts += 1;
            Err::<(), _>(CoreError::InvalidPassphrase.into())
        })
        .expect_err("still wrong");
        assert_eq!(attempts, 1);
    }
}
