//! The GitHub workflows are checked here rather than by a linter nobody has installed: they parse
//! as YAML, and the jobs a release depends on exist with the runners, targets, permissions and
//! artefact names they need.
//!
//! Nothing in here runs on GitHub, so nothing here can prove that a release succeeds. What it can
//! prove is that the file is well-formed and internally consistent -- that every artefact the
//! later jobs download is one an earlier job uploaded, that only the job which creates the release
//! may write to the repository, that no step turns on shell tracing while a secret is in scope,
//! and that every action is pinned to a tag from a list somebody chose on purpose.
//!
//! Ruby carries YAML in its standard library, so the parsing is done by `ruby -ryaml` through
//! `ruby_over` below. `YAML.load_file` and not `YAML.unsafe_load_file`: the latter only exists
//! from Psych 3.3.2, and 2.6-era Rubies (Psych 3.1) still in the wild would fail on it.
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_path_buf()
}

fn workflow_path(workflow: &str) -> PathBuf {
    root().join(".github/workflows").join(workflow)
}

/// Runs a Ruby script with `path` as its `ARGV[0]` and returns its stdout.
///
/// `None` means Ruby is not installed: the caller prints why it is doing nothing and passes,
/// because a missing interpreter is a property of the machine, not of the file being read.
/// Everything else -- a YAML syntax error included -- fails the test with Ruby's own message.
fn ruby_with(script: &str, path: &Path) -> Option<String> {
    let out = match Command::new("ruby")
        .arg("-ryaml")
        .arg("-e")
        .arg(script)
        .arg(path)
        .output()
    {
        Ok(out) => out,
        Err(err) => {
            println!(
                "skipped: cannot run ruby ({err}); {} is not parsed here",
                path.display()
            );
            return None;
        }
    };
    assert!(
        out.status.success(),
        "ruby failed on {}: {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).expect("ruby printed utf-8"))
}

/// Runs a Ruby script over a workflow and returns its stdout.
///
/// Task 8 reuses this helper for the jobs it adds; `ruby_with` above is the same thing over an
/// arbitrary file, which is how the `cargo metadata` output is read.
fn ruby_over(workflow: &str, script: &str) -> Option<String> {
    ruby_with(script, &workflow_path(workflow))
}

/// The four release triples, in the order the matrix and the package job spell them.
const TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
];

/// Every action either workflow is allowed to use. A new entry is a decision -- a third-party
/// action runs with the job's token -- so it is made here and not in a pull request diff nobody
/// reads to the end.
const ALLOWED_ACTIONS: [&str; 10] = [
    "actions/checkout@v4",
    "actions/download-artifact@v4",
    "actions/setup-java@v4",
    "actions/upload-artifact@v4",
    "dtolnay/rust-toolchain@master",
    "dtolnay/rust-toolchain@stable",
    // The MSRV job: `dtolnay/rust-toolchain` keeps a branch per released Rust, and this one has
    // to stay equal to the workspace's `rust-version` (asserted below).
    "dtolnay/rust-toolchain@1.89",
    "Swatinem/rust-cache@v2",
    "softprops/action-gh-release@v2",
    "EmbarkStudios/cargo-deny-action@v2",
];

#[test]
fn both_workflows_are_valid_yaml() {
    for workflow in ["ci.yml", "release.yml"] {
        let Some(out) = ruby_over(
            workflow,
            "puts YAML.load_file(ARGV[0])['jobs'].keys.sort.join(' ')",
        ) else {
            return;
        };
        assert!(!out.trim().is_empty(), "{workflow} declares no jobs");
    }
}

/// The four jobs a release needs, and nothing may quietly drop one.
#[test]
fn the_release_workflow_has_the_four_jobs() {
    let Some(out) = ruby_over(
        "release.yml",
        "puts YAML.load_file(ARGV[0])['jobs'].keys.sort.join(' ')",
    ) else {
        return;
    };
    assert_eq!(out.trim(), "build deb package release");
}

/// The full target matrix from the spec's "Build & Packaging" section.
#[test]
fn the_build_matrix_covers_all_four_targets() {
    let script = r##"
        m = YAML.load_file(ARGV[0])['jobs']['build']['strategy']['matrix']
        puts m['include'].map { |e| "#{e['os']}=#{e['target']}" }.sort.join(' ')
    "##;
    let Some(out) = ruby_over("release.yml", script) else {
        return;
    };
    assert_eq!(
        out.trim(),
        "macos-13=x86_64-apple-darwin \
         macos-15=aarch64-apple-darwin \
         ubuntu-22.04-arm=aarch64-unknown-linux-gnu \
         ubuntu-22.04=x86_64-unknown-linux-gnu"
    );
}

/// The `deb` jobs are built on the runner whose architecture they package: cargo-deb records the
/// architecture of the machine it runs on, so a cross-built package would be mislabelled.
#[test]
fn the_deb_matrix_is_the_two_linux_runners() {
    let script = r##"
        m = YAML.load_file(ARGV[0])['jobs']['deb']['strategy']['matrix']
        puts m['include'].map { |e| "#{e['os']}=#{e['target']}" }.sort.join(' ')
    "##;
    let Some(out) = ruby_over("release.yml", script) else {
        return;
    };
    assert_eq!(
        out.trim(),
        "ubuntu-22.04-arm=aarch64-unknown-linux-gnu ubuntu-22.04=x86_64-unknown-linux-gnu"
    );
}

/// Only the job that creates the release may write to the repository, and the default for
/// everything else is read.
#[test]
fn only_the_release_job_can_write() {
    let script = r##"
        y = YAML.load_file(ARGV[0])
        puts (y['permissions'] || {})['contents'].to_s
        puts y['jobs'].map { |k, v| "#{k}:#{(v['permissions'] || {})['contents'] || 'none'}" }
                      .sort.join(' ')
    "##;
    let Some(out) = ruby_over("release.yml", script) else {
        return;
    };
    let mut lines = out.lines();
    assert_eq!(lines.next().map(str::trim), Some("read"));
    assert_eq!(
        lines.next().map(str::trim),
        Some("build:none deb:none package:none release:write")
    );
}

/// The trigger: a version tag, and a manual re-run against an existing tag. A workflow that also
/// ran on `push: main` would cut a release from every commit.
#[test]
fn the_release_only_triggers_on_a_version_tag() {
    // Psych reads the key `on:` as the boolean `true` (YAML 1.1), so both spellings are accepted.
    let script = r##"
        y = YAML.load_file(ARGV[0])
        on = y[true] || y['on']
        puts on.keys.map(&:to_s).sort.join(' ')
        puts on['push']['tags'].join(' ')
        puts on['workflow_dispatch']['inputs'].keys.sort.join(' ')
    "##;
    let Some(out) = ruby_over("release.yml", script) else {
        return;
    };
    let mut lines = out.lines();
    assert_eq!(lines.next().map(str::trim), Some("push workflow_dispatch"));
    assert_eq!(lines.next().map(str::trim), Some("v*"));
    assert_eq!(lines.next().map(str::trim), Some("tag"));
}

/// Every action is pinned to a major tag from the allow-list. An unpinned `@main` would let a
/// third party change what runs with the release token between two runs of the same tag.
#[test]
fn every_action_is_pinned_to_a_tag_from_the_allow_list() {
    let script = r##"
        y = YAML.load_file(ARGV[0])
        u = []
        y['jobs'].each { |_, j| (j['steps'] || []).each { |s| u << s['uses'] if s['uses'] } }
        puts u.uniq.sort.join(' ')
    "##;
    for workflow in ["ci.yml", "release.yml"] {
        let Some(out) = ruby_over(workflow, script) else {
            return;
        };
        for uses in out.split_whitespace() {
            let (action, reference) = uses
                .rsplit_once('@')
                .unwrap_or_else(|| panic!("{workflow}: {uses} is not pinned to anything"));
            let pinned = reference == "stable"
                || reference == "master"
                || (reference.starts_with('v')
                    && reference.len() > 1
                    && reference[1..].chars().all(|c| c.is_ascii_digit()))
                // A Rust release branch such as `1.89`: a moving target only in the sense that
                // 1.89.x point releases land on it, which is what an MSRV job wants.
                || (reference.starts_with(|c: char| c.is_ascii_digit())
                    && reference.chars().all(|c| c.is_ascii_digit() || c == '.'));
            assert!(
                pinned,
                "{workflow}: {action} is pinned to {reference}, which is not a major tag"
            );
            assert!(
                ALLOWED_ACTIONS.contains(&uses),
                "{workflow}: {uses} is not in the allow-list in this test"
            );
        }
    }
}

/// No step traces its commands, and the only secret in the whole workflow is the release job's
/// `GITHUB_TOKEN`. `set -x` in a job that can see a secret would print it into a public log.
#[test]
fn nothing_traces_its_commands_and_only_the_release_job_sees_a_secret() {
    let script = r##"
        y = YAML.load_file(ARGV[0])
        puts y['jobs'].map { |k, v|
          s = YAML.dump(v)
          # `set -x`, but also the cluster spelling `set -euxo pipefail` and `set -o xtrace`.
          traced = s.lines.any? { |l| l =~ /^\s*set\s+-[a-z]*x/ || l.include?('set -o xtrace') }
          "#{k}:#{s.scan(/secrets\.[A-Za-z_]+/).uniq.sort.join(',')}:#{traced}"
        }.sort.join(' ')
    "##;
    let Some(out) = ruby_over("release.yml", script) else {
        return;
    };
    assert_eq!(
        out.trim(),
        "build::false deb::false package::false release:secrets.GITHUB_TOKEN:false"
    );
}

/// Every artefact a job downloads is one an earlier job uploaded. A renamed upload would otherwise
/// only be noticed by a red release, half an hour into a run.
///
/// `${{ matrix.target }}` is expanded with the job's own matrix, so the names compared here are
/// the names that reach the artefact store.
#[test]
fn every_artefact_downloaded_was_uploaded_by_an_earlier_job() {
    let script = r##"
        y = YAML.load_file(ARGV[0])
        def targets(job)
          m = (job['strategy'] || {})['matrix']
          return [nil] unless m && m['include']
          m['include'].map { |e| e['target'] }
        end
        up = []
        down = []
        y['jobs'].each do |_, job|
          targets(job).each do |t|
            (job['steps'] || []).each do |s|
              u = s['uses'].to_s
              w = s['with'] || {}
              n = (w['name'] || w['pattern']).to_s
              n = n.gsub(/\$\{\{\s*matrix\.target\s*\}\}/, t) if t
              up << n if u.start_with?('actions/upload-artifact')
              down << n if u.start_with?('actions/download-artifact')
            end
          end
        end
        puts up.uniq.sort
        puts '---'
        puts down.uniq.sort
    "##;
    let Some(out) = ruby_over("release.yml", script) else {
        return;
    };
    let (uploaded, downloaded) = out
        .split_once("---")
        .expect("the ruby script printed the separator");
    let uploaded: Vec<&str> = uploaded
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let downloaded: Vec<&str> = downloaded
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    let mut expected: Vec<String> = TARGETS.iter().map(|t| format!("crypto-{t}")).collect();
    expected.push("deb-aarch64-unknown-linux-gnu".into());
    expected.push("deb-x86_64-unknown-linux-gnu".into());
    expected.push("packages".into());
    expected.sort();
    assert_eq!(uploaded, expected, "the uploaded artefacts changed");

    assert!(!downloaded.is_empty(), "nothing is downloaded at all");
    for want in &downloaded {
        // `pattern:` may end in `*`; `name:` never does.
        let matched = uploaded.iter().any(|have| match want.strip_suffix('*') {
            Some(prefix) => have.starts_with(prefix),
            None => have == want,
        });
        assert!(matched, "{want} is downloaded but never uploaded");
    }
}

/// The package job packs every target the build matrix produced, from the artefact layout
/// `upload-artifact@v4` actually creates.
#[test]
fn the_package_job_packs_every_target_the_build_matrix_produces() {
    let script = r##"
        y = YAML.load_file(ARGV[0])
        puts y['jobs']['package']['steps'].map { |s| s['run'].to_s }.join("\n")
    "##;
    let Some(out) = ruby_over("release.yml", script) else {
        return;
    };
    for target in TARGETS {
        assert!(
            out.contains(target),
            "the package job never mentions {target}"
        );
    }
    // The layout `upload-artifact@v4` produces for a single-file upload: the artefact's own
    // directory, the bare file name, no `target/<triple>/release` in between.
    assert!(
        out.contains("artifacts/crypto-$t/crypto"),
        "the package job does not read the binaries from artifacts/crypto-<triple>/crypto"
    );
}

/// A release is created as a draft: somebody looks at it before it is announced.
#[test]
fn the_release_is_a_draft_with_notes_from_the_changelog() {
    let script = r##"
        y = YAML.load_file(ARGV[0])
        s = y['jobs']['release']['steps']
             .find { |x| x['uses'].to_s.start_with?('softprops/action-gh-release') }
        w = s['with']
        puts w['draft'].inspect
        puts w['generate_release_notes'].inspect
        puts w['fail_on_unmatched_files'].inspect
        puts w['body_path'].to_s
        puts w['files'].to_s.split("\n").map(&:strip).reject(&:empty?).sort.join(' ')
    "##;
    let Some(out) = ruby_over("release.yml", script) else {
        return;
    };
    let mut lines = out.lines();
    assert_eq!(lines.next().map(str::trim), Some("true"), "draft");
    assert_eq!(
        lines.next().map(str::trim),
        Some("false"),
        "generate_release_notes"
    );
    assert_eq!(
        lines.next().map(str::trim),
        Some("true"),
        "fail_on_unmatched_files"
    );
    assert!(
        lines.next().unwrap_or("").contains("notes"),
        "the release body does not come from a file"
    );
    assert_eq!(
        lines.next().map(str::trim),
        Some("deb/*.deb packages/*.tar.gz packages/SHA256SUMS packages/crypto.rb")
    );
}

/// The one script in either workflow that is *run* here rather than only read: the release notes.
///
/// It is lifted out of the YAML at test time and executed by bash over the repository's own
/// `CHANGELOG.md`, so the file and the extraction cannot drift apart -- which they silently did
/// once already, when the empty `## Unreleased` heading that now lives permanently on top of the
/// changelog made the notes of the first release one byte long.
///
/// Two shapes, because both happen: the versioned section is the last one in the file (today's
/// changelog), and it has an older release under it (every changelog after the second release).
#[test]
fn the_release_notes_are_the_first_versioned_section_of_the_changelog() {
    let ruby = r##"
        y = YAML.load_file(ARGV[0])
        s = y['jobs']['release']['steps'].find { |x| x['name'].to_s.include?('release notes') }
        abort 'no release step takes the release notes from CHANGELOG.md' if s.nil?
        print s['run']
    "##;
    let Some(script) = ruby_over("release.yml", ruby) else {
        return;
    };
    assert!(
        script.contains("CHANGELOG.md") && script.contains("notes.md"),
        "not the extraction step: {script}"
    );

    let dir = tempfile::tempdir().expect("a temporary directory");
    let changelog = dir.path().join("CHANGELOG.md");
    std::fs::copy(root().join("CHANGELOG.md"), &changelog).expect("CHANGELOG.md is committed");
    let script_path = dir.path().join("release-notes.sh");
    std::fs::write(&script_path, &script).expect("the script is written");

    // The version being released is the one the notes have to describe; the changelog section for
    // it is written in the version-bump commit, before the tag (`docs/release.md`).
    let version = workspace_version();
    let heading = format!("## {version}");

    let Some(notes) = extract_notes(dir.path(), &script_path) else {
        return;
    };
    assert!(
        notes.starts_with(&heading),
        "the notes do not start with {heading:?}: {:?}",
        notes.chars().take(80).collect::<String>()
    );
    assert!(
        notes.len() > 100,
        "{} bytes of release notes is the empty-section bug again",
        notes.len()
    );
    assert!(
        !notes.lines().any(|line| line.starts_with("## Unreleased")),
        "the empty Unreleased section leaked into the release notes"
    );

    // Now with an older release below it: the extraction has to stop at that heading.
    let with_predecessor = std::fs::read_to_string(&changelog).expect("the copy is readable")
        + "\n## 0.0.9 – 2020-01-01\n\nThe release before the first one.\n";
    std::fs::write(&changelog, with_predecessor).expect("the copy is writable");
    let Some(bounded) = extract_notes(dir.path(), &script_path) else {
        return;
    };
    assert!(
        !bounded.contains("0.0.9"),
        "the notes run on into the previous release"
    );
    assert_eq!(
        bounded.trim_end(),
        notes.trim_end(),
        "a successor section changes the notes of the release being made"
    );
}

/// Runs the extracted script in `dir` and returns the `notes.md` it writes -- the file
/// `action-gh-release` is handed as `body_path`. `None` means bash is missing, like `ruby_with`.
fn extract_notes(dir: &Path, script: &Path) -> Option<String> {
    let out = match Command::new("bash").arg(script).current_dir(dir).output() {
        Ok(out) => out,
        Err(err) => {
            println!("skipped: cannot run bash ({err}); the release notes are not extracted here");
            return None;
        }
    };
    assert!(
        out.status.success(),
        "the release-notes script failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(std::fs::read_to_string(dir.join("notes.md")).expect("the script writes notes.md"))
}

/// `[workspace.package] version` from the root manifest: what a `v<version>` tag will carry.
fn workspace_version() -> String {
    let manifest: toml_edit::DocumentMut = std::fs::read_to_string(root().join("Cargo.toml"))
        .expect("the workspace manifest is committed")
        .parse()
        .expect("the workspace manifest is valid TOML");
    manifest
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .expect("[workspace.package] version is set")
        .to_string()
}

// -- The CI matrix, the supply chain and the MSRV floor ------------------------------------------

/// The spec's CI matrix, complete: two macOS architectures and two Linux ones. Until M8 only
/// macos-15 and ubuntu-22.04 ran, so an x86_64-only or an arm-only failure had nowhere to show up.
/// `fail-fast: false` belongs to the same statement -- with it on, the first red row cancels the
/// other three and the matrix stops answering the question it exists for.
#[test]
fn the_ci_test_job_runs_on_all_four_runners() {
    let script = r##"
        s = YAML.load_file(ARGV[0])['jobs']['test']['strategy']
        puts s['matrix']['os'].sort.join(' ')
        puts s['fail-fast'].inspect
    "##;
    let Some(out) = ruby_over("ci.yml", script) else {
        return;
    };
    let mut lines = out.lines();
    assert_eq!(
        lines.next().map(str::trim),
        Some("macos-13 macos-15 ubuntu-22.04 ubuntu-22.04-arm")
    );
    assert_eq!(
        lines.next().map(str::trim),
        Some("false"),
        "fail-fast would cancel the other three runners on the first red one"
    );
}

/// Advisories, licences, bans and sources in one job (M8 ruling 6: no separate `cargo audit`),
/// and a job that compiles the workspace on the version the manifest promises.
#[test]
fn ci_checks_the_supply_chain_and_the_msrv() {
    let Some(out) = ruby_over(
        "ci.yml",
        "puts YAML.load_file(ARGV[0])['jobs'].keys.sort.join(' ')",
    ) else {
        return;
    };
    let jobs: Vec<&str> = out.trim().split(' ').collect();
    assert!(
        jobs.contains(&"supply-chain"),
        "no supply-chain job: {jobs:?}"
    );
    assert!(jobs.contains(&"msrv"), "no msrv job: {jobs:?}");
    assert!(
        !jobs.contains(&"audit"),
        "cargo audit is subsumed by cargo deny (M8 ruling 6)"
    );
}

/// The supply-chain job runs cargo-deny with no sub-command, which is what makes it run *all* of
/// cargo-deny's checks. Naming three of the four -- or naming today's four and missing one added
/// later -- is how a check quietly stops running while the job stays green.
#[test]
fn the_supply_chain_job_runs_every_cargo_deny_check() {
    let script = r##"
        s = YAML.load_file(ARGV[0])['jobs']['supply-chain']['steps']
             .find { |x| x['uses'].to_s.start_with?('EmbarkStudios/cargo-deny-action') }
        abort 'no cargo-deny step' if s.nil?
        puts s['uses']
        puts (s['with'] || {})['command'].to_s
    "##;
    let Some(out) = ruby_over("ci.yml", script) else {
        return;
    };
    let mut lines = out.lines();
    assert_eq!(
        lines.next().map(str::trim),
        Some("EmbarkStudios/cargo-deny-action@v2")
    );
    let command = lines.next().unwrap_or("").trim();
    assert!(
        command == "check"
            || ["advisories", "bans", "licenses", "sources"]
                .iter()
                .all(|check| command.split_whitespace().any(|word| word == *check)),
        "`command: {command}` does not run all four checks"
    );
}

/// The MSRV job has to pin the *declared* MSRV, or it checks nothing. Reading it out of the
/// workspace manifest keeps the two from drifting apart silently: raising `rust-version` without
/// touching the job turns this red.
#[test]
fn the_msrv_job_pins_the_declared_rust_version() {
    let manifest =
        std::fs::read_to_string(root().join("Cargo.toml")).expect("the workspace manifest");
    let declared = manifest
        .lines()
        .find_map(|line| line.strip_prefix("rust-version = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("the workspace declares rust-version");
    let script = r##"
        steps = YAML.load_file(ARGV[0])['jobs']['msrv']['steps']
        puts steps.map { |s| s['uses'] }.compact.grep(/rust-toolchain/).join(' ')
        puts steps.map { |s| s['run'] }.compact.join("\n")
    "##;
    let Some(out) = ruby_over("ci.yml", script) else {
        return;
    };
    let mut lines = out.lines();
    assert_eq!(
        lines.next().map(str::trim),
        Some(format!("dtolnay/rust-toolchain@{declared}").as_str()),
        "the msrv job does not pin the declared rust-version"
    );
    let commands: Vec<&str> = lines.collect();
    assert!(
        commands
            .iter()
            .any(|c| c.contains("cargo check --workspace --all-targets --locked")),
        "the msrv job does not check the whole workspace: {commands:?}"
    );
}

/// The licence allow-list, read as TOML rather than grepped: `deny.toml` has to parse, and
/// "Apache-2.0" must be an entry of the list and not merely a substring of one.
#[test]
fn the_licence_allow_list_is_explicit() {
    let allowed = licence_allow_list();
    for licence in [
        "AGPL-3.0-only",
        "MIT",
        "Apache-2.0",
        "Apache-2.0 WITH LLVM-exception",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "Unicode-3.0",
        "Unlicense",
        "Zlib",
    ] {
        assert!(
            allowed.iter().any(|entry| entry == licence),
            "deny.toml does not allow {licence}: {allowed:?}"
        );
    }
    let deny = deny_toml();
    let licenses = deny
        .get("licenses")
        .and_then(|table| table.as_table())
        .expect("deny.toml has a [licenses] section");
    assert!(
        licenses.get("allow-osi-fsf-free").is_none(),
        "the allow list must be explicit, not whatever an SPDX database calls free"
    );
    let sources = deny
        .get("sources")
        .and_then(|table| table.as_table())
        .expect("deny.toml has a [sources] section");
    for key in ["unknown-registry", "unknown-git"] {
        assert_eq!(
            sources.get(key).and_then(|v| v.as_str()),
            Some("deny"),
            "a crate from an unvetted {key} would be pulled in without anyone deciding to"
        );
    }
}

/// The behavioural half: every licence expression in the resolved tree is satisfiable from the
/// allow-list. A new dependency under a licence nobody allowed fails here, on this machine,
/// rather than in CI -- and the allow-list stays measured rather than guessed.
#[test]
fn every_licence_in_the_tree_is_allowed() {
    let allowed = licence_allow_list();
    let Some(packages) = packages_with_licences() else {
        return;
    };
    assert!(
        packages.len() > 100,
        "only {} packages came back from cargo metadata",
        packages.len()
    );
    let mut checked = 0usize;
    for (package, expression) in &packages {
        if expression.is_empty() {
            // Nothing in the tree carries a `license-file` instead of a `license` today. If one
            // ever does, cargo-deny needs an `[licenses] exceptions` entry and a reason, and the
            // reason belongs here rather than in a silent skip.
            panic!("{package} declares no licence; deny.toml needs an exception with a reason");
        }
        let parsed = Spdx::parse(expression)
            .unwrap_or_else(|err| panic!("{package}: cannot read `{expression}`: {err}"));
        assert!(
            parsed.satisfied_by(&allowed),
            "{package} is `{expression}`, which the allow-list does not cover"
        );
        checked += 1;
    }
    println!(
        "{checked} packages checked against {} allowed licences",
        allowed.len()
    );
}

/// The evaluator above is the load-bearing part of that test, so it is checked against the forms
/// the tree actually contains -- including the pre-SPDX slash spelling and the parenthesised
/// `AND` that `unicode-ident` carries.
#[test]
fn the_spdx_evaluator_understands_the_expressions_cargo_manifests_use() {
    let allowed: Vec<String> = [
        "MIT",
        "Apache-2.0",
        "Apache-2.0 WITH LLVM-exception",
        "Unicode-3.0",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    for expression in [
        "MIT",
        "MIT OR Apache-2.0",
        "MIT/Apache-2.0",
        "Apache-2.0 / MIT / MPL-2.0",
        "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
        "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
        "(MIT OR Apache-2.0) AND Unicode-3.0",
    ] {
        let parsed = Spdx::parse(expression).expect("the expression parses");
        assert!(
            parsed.satisfied_by(&allowed),
            "{expression} should be allowed"
        );
    }
    for expression in [
        "MPL-2.0",
        "MIT AND MPL-2.0",
        "(MIT OR Apache-2.0) AND GPL-3.0-only",
        // The exception is part of the identity: allowing `Apache-2.0` alone does not allow it.
        "Apache-2.0 WITH Bison-exception-2.2",
    ] {
        let parsed = Spdx::parse(expression).expect("the expression parses");
        assert!(
            !parsed.satisfied_by(&allowed),
            "{expression} should not be allowed"
        );
    }
    assert!(
        Spdx::parse("(MIT OR Apache-2.0").is_err(),
        "an unclosed group is an error"
    );
    assert!(Spdx::parse("MIT OR").is_err(), "a dangling OR is an error");
    assert!(
        Spdx::parse("Apache-2.0 WITH").is_err(),
        "a dangling WITH is an error"
    );
}

fn deny_toml() -> toml_edit::DocumentMut {
    std::fs::read_to_string(root().join("deny.toml"))
        .expect("deny.toml is committed at the workspace root")
        .parse()
        .expect("deny.toml is valid TOML")
}

fn licence_allow_list() -> Vec<String> {
    deny_toml()
        .get("licenses")
        .and_then(|licenses| licenses.get("allow"))
        .and_then(|allow| allow.as_array())
        .expect("deny.toml has a [licenses] allow list")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("every allow-list entry is a string")
                .to_string()
        })
        .collect()
}

/// `("<name> <version>", "<licence expression>")` for every package in the resolved tree, read
/// from `cargo metadata` -- the same source cargo-deny reads, so the two cannot disagree about
/// what is in the tree. The JSON is parsed by Ruby, for the same reason the YAML is.
fn packages_with_licences() -> Option<Vec<(String, String)>> {
    let metadata = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root())
        .output()
        .expect("cargo metadata runs");
    assert!(
        metadata.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let mut json = tempfile::NamedTempFile::new().expect("a temporary file for the metadata");
    std::io::Write::write_all(&mut json, &metadata.stdout).expect("the metadata is written out");
    let script = r##"
        require 'json'
        JSON.parse(File.read(ARGV[0]))['packages'].each do |p|
          puts "#{p['name']} #{p['version']}\t#{p['license']}"
        end
    "##;
    let out = ruby_with(script, json.path())?;
    Some(
        out.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| match line.split_once('\t') {
                Some((package, licence)) => (package.to_string(), licence.trim().to_string()),
                None => (line.trim().to_string(), String::new()),
            })
            .collect(),
    )
}

/// One SPDX licence expression, in the subset Cargo manifests use: identifiers, `WITH`
/// exceptions, `AND`, `OR`, parentheses, and the pre-SPDX `/` that older crates still spell.
#[derive(Debug)]
enum Spdx {
    /// A licence id, or an `<id> WITH <exception>` pair. The pair is matched whole: an exception
    /// changes the terms, so allowing the bare licence must not allow it.
    Leaf(String),
    /// `OR`: one satisfied branch is enough.
    Any(Vec<Spdx>),
    /// `AND`: every part has to be satisfied.
    All(Vec<Spdx>),
}

impl Spdx {
    fn parse(expression: &str) -> Result<Self, String> {
        let spaced = expression
            .replace('(', " ( ")
            .replace(')', " ) ")
            .replace('/', " OR ");
        let tokens: Vec<&str> = spaced.split_whitespace().collect();
        let mut at = 0;
        let parsed = Self::parse_any(&tokens, &mut at)?;
        if at != tokens.len() {
            return Err(format!("trailing {:?}", &tokens[at..]));
        }
        Ok(parsed)
    }

    fn parse_any(tokens: &[&str], at: &mut usize) -> Result<Self, String> {
        let mut branches = vec![Self::parse_all(tokens, at)?];
        while tokens.get(*at) == Some(&"OR") {
            *at += 1;
            branches.push(Self::parse_all(tokens, at)?);
        }
        Ok(Self::fold(branches, Self::Any))
    }

    fn parse_all(tokens: &[&str], at: &mut usize) -> Result<Self, String> {
        let mut parts = vec![Self::parse_leaf(tokens, at)?];
        while tokens.get(*at) == Some(&"AND") {
            *at += 1;
            parts.push(Self::parse_leaf(tokens, at)?);
        }
        Ok(Self::fold(parts, Self::All))
    }

    fn parse_leaf(tokens: &[&str], at: &mut usize) -> Result<Self, String> {
        match tokens.get(*at) {
            None => Err("the expression ends where a licence was expected".to_string()),
            Some(&"(") => {
                *at += 1;
                let inner = Self::parse_any(tokens, at)?;
                if tokens.get(*at) != Some(&")") {
                    return Err("a group is never closed".to_string());
                }
                *at += 1;
                Ok(inner)
            }
            Some(&(")" | "OR" | "AND" | "WITH")) => {
                Err(format!("`{}` where a licence was expected", tokens[*at]))
            }
            Some(id) => {
                let id = (*id).to_string();
                *at += 1;
                if tokens.get(*at) == Some(&"WITH") {
                    let exception = tokens
                        .get(*at + 1)
                        .ok_or_else(|| "`WITH` without an exception".to_string())?;
                    *at += 2;
                    return Ok(Self::Leaf(format!("{id} WITH {exception}")));
                }
                Ok(Self::Leaf(id))
            }
        }
    }

    /// A one-element `OR`/`AND` is just its element; keeping the wrapper would only make the
    /// debug output harder to read when a test fails.
    fn fold(mut parts: Vec<Self>, wrap: fn(Vec<Self>) -> Self) -> Self {
        if parts.len() == 1 {
            parts.remove(0)
        } else {
            wrap(parts)
        }
    }

    fn satisfied_by(&self, allowed: &[String]) -> bool {
        match self {
            Self::Leaf(id) => allowed.iter().any(|entry| entry == id),
            Self::Any(branches) => branches.iter().any(|b| b.satisfied_by(allowed)),
            Self::All(parts) => parts.iter().all(|p| p.satisfied_by(allowed)),
        }
    }
}
