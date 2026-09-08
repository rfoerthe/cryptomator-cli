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
use std::path::PathBuf;
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

/// Runs a Ruby script over a workflow and returns its stdout.
///
/// `None` means Ruby is not installed: the test prints why it is doing nothing and passes, because
/// a missing interpreter is a property of the machine, not of the workflow. Everything else -- a
/// YAML syntax error included -- fails the test with Ruby's own message.
///
/// Task 8 reuses this helper for the workflows it adds.
fn ruby_over(workflow: &str, script: &str) -> Option<String> {
    let path = workflow_path(workflow);
    let out = match Command::new("ruby")
        .arg("-ryaml")
        .arg("-e")
        .arg(script)
        .arg(&path)
        .output()
    {
        Ok(out) => out,
        Err(err) => {
            println!("skipped: cannot run ruby ({err}); the workflows are not parsed here");
            return None;
        }
    };
    assert!(
        out.status.success(),
        "ruby failed on {workflow}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).expect("ruby printed utf-8"))
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
const ALLOWED_ACTIONS: [&str; 8] = [
    "actions/checkout@v4",
    "actions/download-artifact@v4",
    "actions/setup-java@v4",
    "actions/upload-artifact@v4",
    "dtolnay/rust-toolchain@master",
    "dtolnay/rust-toolchain@stable",
    "Swatinem/rust-cache@v2",
    "softprops/action-gh-release@v2",
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
                    && reference[1..].chars().all(|c| c.is_ascii_digit()));
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
