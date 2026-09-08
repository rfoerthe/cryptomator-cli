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
