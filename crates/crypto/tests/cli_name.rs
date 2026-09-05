//! `crypto name decrypt|locate` against the `long_names` fixture vault.
mod common;

use common::Sandbox;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn locate_and_decrypt_round_trip() {
    let sb = Sandbox::new();
    sb.add_fixture("long_names");
    let long_dir = format!("/{}", "d".repeat(200));
    let locate = |path: &str, contents: bool| -> String {
        let mut args = vec!["--json", "name", "locate", "long_names", path];
        if contents {
            args.push("--contents");
        }
        let out = sb
            .crypto(&args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&out).unwrap()["ciphertext"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let node = locate(&long_dir, false);
    assert!(node.ends_with(".c9s"), "{node}");
    let content_dir = locate(&long_dir, true);
    assert!(std::path::Path::new(&content_dir)
        .join("dirid.c9r")
        .is_file());
    let inner = locate(&format!("{long_dir}/inner.txt"), false);
    assert!(inner.ends_with(".c9r"), "{inner}");
    // short name inside a long directory: the ciphertext stays a plain `.c9r` file, so --contents
    // is the node itself. The 200-char root file is the shortened case.
    let inner_contents = locate(&format!("{long_dir}/inner.txt"), true);
    assert_eq!(inner_contents, inner, "{inner_contents}");
    assert!(
        !inner_contents.ends_with("contents.c9r"),
        "{inner_contents}"
    );
    let long_file = format!("/{}.txt", "c".repeat(200));
    assert!(locate(&long_file, false).ends_with(".c9s"));
    let long_file_contents = locate(&long_file, true);
    assert!(
        long_file_contents.ends_with("contents.c9r"),
        "{long_file_contents}"
    );
    sb.crypto(&["name", "locate", "long_names", "/missing"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no such file"));
    sb.crypto(&["name", "locate", "long_names", "/"])
        .assert()
        .success()
        .stdout(predicate::str::ends_with("\n"));
    // decrypt gives the names back
    sb.crypto(&["name", "decrypt", "long_names", &node, &inner])
        .assert()
        .success()
        .stdout(
            predicate::str::contains(format!("\t{}\n", "d".repeat(200)))
                .and(predicate::str::contains("\tinner.txt\n")),
        );
    let out = sb
        .crypto(&[
            "--json",
            "name",
            "decrypt",
            "long_names",
            &inner,
            "/not/in/vault/x.c9r",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let entries: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(entries[0]["cleartext"], "inner.txt");
    assert!(entries[1]["error"]
        .as_str()
        .unwrap()
        .contains("not a part of vault"));
    sb.crypto(&["name", "decrypt", "long_names"])
        .assert()
        .code(2);
}
