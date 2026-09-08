//! The release surface of the binary: `crypto completions <shell>` and `crypto --version`.
//! Nothing here needs a vault, a settings file or a keychain, so there is no `Sandbox`.
use assert_cmd::Command;
use predicates::prelude::*;

fn crypto() -> Command {
    Command::cargo_bin("crypto").expect("the `crypto` binary is built")
}

/// One script per shell, and each one has to look like that shell's completion script rather
/// than merely be non-empty: a generator wired to the wrong shell would still print something.
/// No script may name the hidden `__daemon`, in any shell -- clap_complete's generators do not
/// filter hidden subcommands themselves, so this is the check on the filter that does.
#[test]
fn every_supported_shell_gets_its_own_script() {
    let expected: &[(&str, &str)] = &[
        ("bash", "complete -F _crypto"),
        ("zsh", "#compdef crypto"),
        ("fish", "complete -c crypto"),
        ("elvish", "edit:completion:arg-completer[crypto]"),
        ("powershell", "Register-ArgumentCompleter"),
    ];
    for (shell, marker) in expected {
        crypto()
            .args(["completions", shell])
            .assert()
            .success()
            .stdout(predicate::str::contains(*marker))
            .stdout(predicate::str::contains("__daemon").not());
    }
}

/// The generated script has to know the subcommands, otherwise it completes nothing useful.
#[test]
fn the_bash_script_mentions_the_subcommands() {
    let out = crypto().args(["completions", "bash"]).output().unwrap();
    let script = String::from_utf8(out.stdout).unwrap();
    for subcommand in ["vault", "unlock", "health", "migrate", "completions"] {
        assert!(
            script.contains(subcommand),
            "bash script is missing {subcommand}"
        );
    }
    // `__daemon` is `hide = true`; a hidden command must not be advertised.
    assert!(
        !script.contains("__daemon"),
        "the hidden daemon command leaked into the script"
    );
}

/// An unknown shell is a usage error, and clap lists the valid values.
#[test]
fn an_unknown_shell_is_exit_two_and_names_the_valid_ones() {
    crypto()
        .args(["completions", "tcsh"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("bash").and(predicate::str::contains("zsh")));
}

/// Completions must work when there is no readable settings file: a user who broke their
/// `settings.json` still has to be able to install completions, and the shell startup that runs
/// this command must never block on anything.
#[test]
fn completions_do_not_read_the_settings_file() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("settings.json");
    std::fs::write(&broken, b"{ this is not json").unwrap();
    crypto()
        .args(["--settings"])
        .arg(&broken)
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef crypto"));
}

/// `crypto 0.1.0 (<sha>, <target>)` -- version, commit and target triple on one line. Checked
/// by shape rather than by value: the sha changes with every commit and the target with the
/// machine, but the shape is what a bug report has to be able to carry.
#[test]
fn version_carries_the_commit_and_the_target() {
    let out = crypto().arg("--version").output().unwrap();
    assert!(out.status.success());
    let line = String::from_utf8(out.stdout).unwrap();
    let line = line.trim();
    let rest = line
        .strip_prefix("crypto ")
        .unwrap_or_else(|| panic!("does not start with the program name: {line:?}"));
    let (version, tail) = rest
        .split_once(" (")
        .unwrap_or_else(|| panic!("no ` (` after the version: {line:?}"));
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    let inner = tail
        .strip_suffix(')')
        .unwrap_or_else(|| panic!("no closing parenthesis: {line:?}"));
    let (sha, target) = inner
        .split_once(", ")
        .unwrap_or_else(|| panic!("no `, ` between sha and target: {line:?}"));
    // Either a short hex sha or the documented fallback -- never empty, never a git error message.
    assert!(
        sha == "unknown" || (sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit())),
        "not a short sha and not `unknown`: {sha:?}"
    );
    // A target triple, e.g. aarch64-apple-darwin or x86_64-unknown-linux-gnu.
    assert!(
        target.matches('-').count() >= 2,
        "not a target triple: {target:?}"
    );
}

/// The environment override exists so a build from a source tarball (Homebrew, a distribution)
/// can still name the commit it was cut from.
#[test]
fn the_environment_can_supply_the_sha() {
    // Not a run-time variable: it is read by build.rs, so this only pins that the documented name
    // is the one the build script looks at. The value itself is checked by the shape test above.
    assert!(
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/build.rs"))
            .unwrap()
            .contains("CRYPTO_GIT_SHA"),
        "build.rs no longer honours $CRYPTO_GIT_SHA"
    );
}
