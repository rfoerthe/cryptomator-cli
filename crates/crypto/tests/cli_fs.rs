//! `crypto fs …` against Java-generated fixtures and a freshly created vault.
mod common;

use common::{fixtures_root, Sandbox};
use predicates::prelude::*;
use serde_json::Value;

fn json(out: &[u8]) -> Value {
    serde_json::from_slice(out).unwrap()
}

#[test]
fn fixture_trees_match_expected_json() {
    let sb = Sandbox::new();
    for name in [
        "siv_gcm_basic",
        "siv_ctrmac_basic",
        "long_names",
        "symlinks",
        "unicode",
        "nested",
        "sizes",
        "threshold_36",
    ] {
        sb.add_fixture(name);
        let out = sb
            .crypto(&["--json", "fs", "tree", name, "--hash"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let expected: Value = serde_json::from_slice(
            &std::fs::read(fixtures_root().join(name).join("expected.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(json(&out), expected, "{name}");
    }
}

#[test]
fn ls_cat_and_get() {
    let sb = Sandbox::new();
    sb.add_fixture("siv_gcm_basic");
    sb.crypto(&["fs", "ls", "siv_gcm_basic"])
        .assert()
        .success()
        .stdout("docs/\nhello.txt\n");
    let out = sb
        .crypto(&["--json", "fs", "ls", "siv_gcm_basic", "-l"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let entries = json(&out);
    assert_eq!(entries[0]["name"], "docs");
    assert_eq!(entries[0]["type"], "dir");
    assert_eq!(entries[1]["name"], "hello.txt");
    assert_eq!(entries[1]["size"], 20);
    assert!(entries[1]["modified"].is_u64());
    sb.crypto(&["fs", "ls", "siv_gcm_basic", "-l"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("f         20 ").and(predicate::str::contains("hello.txt")),
        );
    sb.crypto(&["fs", "cat", "siv_gcm_basic", "/hello.txt"])
        .assert()
        .success()
        .stdout("Hello, Cryptomator!\n");
    sb.crypto(&["fs", "cat", "siv_gcm_basic", "docs/notes.md"])
        .assert()
        .success()
        .stdout("# Notes\n\nsome text\n");
    sb.crypto(&["fs", "cat", "siv_gcm_basic", "/docs"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("is a directory"));
    sb.crypto(&["fs", "cat", "siv_gcm_basic", "/nope"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no such file"));
    let local = sb.path("out.txt");
    sb.crypto(&["fs", "get", "siv_gcm_basic", "/hello.txt"])
        .arg(&local)
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(&local).unwrap(),
        "Hello, Cryptomator!\n"
    );
    sb.crypto(&["fs", "get", "siv_gcm_basic", "/hello.txt"])
        .arg(&local)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    sb.crypto(&["fs", "get", "siv_gcm_basic", "/hello.txt", "--force"])
        .arg(&local)
        .assert()
        .success();
    sb.crypto(&["fs", "get", "siv_gcm_basic", "/hello.txt", "-"])
        .assert()
        .success()
        .stdout("Hello, Cryptomator!\n");
    // symlink listing shows the target; ls of the link itself follows it
    sb.add_fixture("symlinks");
    sb.crypto(&["fs", "ls", "symlinks", "-l"])
        .assert()
        .success()
        .stdout(predicate::str::contains("relative-link -> target.txt"));
    sb.crypto(&["fs", "cat", "symlinks", "/relative-link"])
        .assert()
        .success()
        .stdout("link target\n");
}

#[test]
fn put_mkdir_mv_rm_round_trip() {
    let sb = Sandbox::new();
    sb.crypto(&["vault", "create"])
        .arg(sb.path("v"))
        .assert()
        .success();
    sb.crypto(&["fs", "mkdir", "v", "/docs"]).assert().success();
    sb.crypto(&["fs", "mkdir", "v", "/docs"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    sb.crypto(&["fs", "mkdir", "v", "/a/b/c"]).assert().code(1);
    sb.crypto(&["fs", "mkdir", "v", "-p", "/a/b/c"])
        .assert()
        .success();
    let local = sb.path("in.txt");
    std::fs::write(&local, "put me\n").unwrap();
    sb.crypto(&["fs", "put", "v"])
        .arg(&local)
        .arg("/docs/in.txt")
        .assert()
        .success();
    sb.crypto(&["fs", "put", "v"])
        .arg(&local)
        .arg("/docs/in.txt")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    sb.crypto(&["fs", "put", "v"])
        .arg(&local)
        .arg("/docs")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("is a directory"));
    std::fs::write(&local, "replaced\n").unwrap();
    sb.crypto(&["fs", "put", "v", "--force"])
        .arg(&local)
        .arg("/docs/in.txt")
        .assert()
        .success();
    sb.crypto(&["fs", "cat", "v", "/docs/in.txt"])
        .assert()
        .success()
        .stdout("replaced\n");
    sb.crypto(&["fs", "put", "v", "-", "/from-stdin"])
        .write_stdin("stdin data")
        .assert()
        .success();
    sb.crypto(&["fs", "cat", "v", "/from-stdin"])
        .assert()
        .success()
        .stdout("stdin data");
    sb.crypto(&["fs", "put", "v", "-", "/x", "--password-stdin"])
        .assert()
        .code(2);
    let long = "n".repeat(200);
    sb.crypto(&["fs", "put", "v", "-"])
        .arg(format!("/docs/{long}"))
        .write_stdin("long")
        .assert()
        .success();
    sb.crypto(&["fs", "mv", "v", "/docs/in.txt", "/a/b/c/moved.txt"])
        .assert()
        .success();
    sb.crypto(&["fs", "mv", "v", "/from-stdin", "/a/b/c/moved.txt"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    sb.crypto(&[
        "fs",
        "mv",
        "v",
        "/from-stdin",
        "/a/b/c/moved.txt",
        "--force",
    ])
    .assert()
    .success();
    sb.crypto(&["fs", "cat", "v", "/a/b/c/moved.txt"])
        .assert()
        .success()
        .stdout("stdin data");
    sb.crypto(&["fs", "mv", "v", "/a", "/renamed"])
        .assert()
        .success();
    let out = sb
        .crypto(&["--json", "fs", "tree", "v"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let paths: Vec<String> = json(&out)
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        paths,
        vec![
            "/WELCOME.rtf".to_string(),
            "/docs".to_string(),
            format!("/docs/{long}"),
            "/renamed".to_string(),
            "/renamed/b".to_string(),
            "/renamed/b/c".to_string(),
            "/renamed/b/c/moved.txt".to_string(),
        ]
    );
    sb.crypto(&["fs", "tree", "v", "/renamed"])
        .assert()
        .success()
        .stdout("/renamed/b\n/renamed/b/c\n/renamed/b/c/moved.txt\n");
    sb.crypto(&["fs", "rm", "v", "/renamed"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not empty"));
    sb.crypto(&["fs", "rm", "v", "-r", "/renamed"])
        .assert()
        .success();
    // a non-empty directory without -r
    sb.crypto(&["fs", "rm", "v", "/docs"]).assert().code(1);
    sb.crypto(&["fs", "rm", "v", "-r", "/docs"])
        .assert()
        .success();
    sb.crypto(&["fs", "rm", "v", "/WELCOME.rtf"])
        .assert()
        .success();
    sb.crypto(&["--json", "fs", "ls", "v"])
        .assert()
        .success()
        .stdout("[]\n");
    // the vault is still valid for the core walker
    sb.crypto(&["fs", "rm", "v", "/"]).assert().code(1);
}

#[test]
fn read_only_setting_and_password_errors() {
    let sb = Sandbox::new();
    sb.crypto(&["vault", "create"])
        .arg(sb.path("v"))
        .assert()
        .success();
    sb.crypto(&["vault", "set", "v", "--read-only", "true"])
        .assert()
        .success();
    sb.crypto(&["fs", "mkdir", "v", "/d"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("read-only"));
    sb.crypto(&["fs", "ls", "v"]).assert().success();
    sb.crypto(&["fs", "ls", "v"])
        .env("CRYPTO_PASSWORD", "wrong-password")
        .assert()
        .code(4);
    sb.crypto(&["fs", "ls", "nope"]).assert().code(3);
    // hub vault: rejected before any password is read
    let hub = sb.path("hub");
    std::fs::create_dir_all(hub.join("d")).unwrap();
    std::fs::write(hub.join("vault.cryptomator"), "eyJraWQiOiJodWIraHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vYXBpL3ZhdWx0cy8xIiwiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJ4IiwiZm9ybWF0Ijo4LCJjaXBoZXJDb21ibyI6IlNJVl9HQ00iLCJzaG9ydGVuaW5nVGhyZXNob2xkIjoyMjB9.AAAA").unwrap();
    std::fs::write(hub.join("masterkey.cryptomator"), "{}").unwrap();
    sb.crypto(&["vault", "add"]).arg(&hub).assert().success();
    sb.crypto(&["fs", "ls", "hub", "--password-stdin"])
        .write_stdin("")
        .assert()
        .code(9);
}
