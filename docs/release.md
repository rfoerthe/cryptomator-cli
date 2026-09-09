# Cutting a release

`.github/workflows/release.yml` does the building. This file is the part a person has to do — the
version bump, the tag, the look at the draft, and the two things CI deliberately does not do:
signing and writing the Homebrew formula back into the repository.

## Before the tag

1. **`main` is clean and green.** Every job of `ci.yml` has passed on the commit that is about to
   be tagged: `test` on all three runners (`ubuntu-22.04`, `ubuntu-22.04-arm`, `macos-15`),
   `interop-java`, the mount, WebDAV and keychain end-to-end jobs, and — the two that are easy to
   forget because nothing else depends on them — **`supply-chain`** (`cargo deny check` over
   advisories, bans, licences and sources) and **`msrv`** (`cargo check --workspace --all-targets
   --locked` on 1.89). A red `supply-chain` is usually a new RustSec advisory rather than a code
   change; fix it or record the decision in `deny.toml`, do not tag around it.

   There is no x86_64 macOS runner in the matrix: `macos-13` was the last such image and it has
   been retired. The `x86_64-apple-darwin` binary is still built and shipped — cross-compiled on
   `macos-15` — but no test suite runs on that architecture any more. The CHANGELOG lists it under
   known limitations.

2. **Bump the version — three files, in this order.**

       # 1. the single source of truth
       $EDITOR Cargo.toml                        # [workspace.package] version = "0.1.0"

       # 2. Cargo.lock carries its own copy of every workspace member's version, so a bump
       #    invalidates it and every `--locked` build (CI, `xtask dist`, `release.yml`) fails
       #    with "cannot update the lock file ... because --locked was passed".
       cargo update --workspace --offline        # touches exactly the five workspace members

       # 3. the committed Homebrew formula names the version on six lines (`version`, the four
       #    `url`s and the `test` assertion), and regenerating the whole file is the only way it
       #    is edited: `the_committed_formula_is_what_the_renderer_produces` in
       #    xtask/src/formula.rs compares it against the renderer's output for the *current*
       #    version.
       cargo xtask formula --write

   All four crates and `xtask` inherit `workspace.package.version`; nothing else in the tree
   names it.

3. **`CHANGELOG.md`: write the `## <version> – <date>` section.** It becomes the body of the
   GitHub release verbatim, heading and all: the `release` job takes the first section whose
   heading is a version number and everything down to the next `## ` heading (or to the end of the
   file). The empty `## Unreleased` above it is skipped and **stays where it is** — nothing in the
   changelog has to be edited for the tag, and nothing has to be put back after it.

   `the_release_notes_are_the_first_versioned_section_of_the_changelog` in
   `xtask/tests/workflows.rs` runs the job's own extraction script over this file, so an empty or
   misplaced section fails `cargo test` rather than the release. Should it reach the release
   anyway, the job stops there: an extraction that finds no versioned section exits 1 with the
   reason, rather than creating a draft whose notes nobody wrote.

4. **The local gate**, on the commit that will be tagged:

       cargo fmt --all --check
       cargo clippy --workspace --all-targets --locked -- -D warnings
       cargo test --workspace --locked
       cargo clippy -p cryptomator-mount --no-default-features --all-targets --locked -- -D warnings
       cargo +1.89 check --workspace --all-targets --locked
       cargo deny check
       cargo test -p crypto --test java_interop --locked -- --ignored     # needs a JDK 25+ and Maven

5. **One dry run of the packaging**, so the first tarball a human sees is not the one users
   download:

       cargo xtask dist                          # host target, release profile, a few minutes
       tar xzf target/dist/crypto-<version>-<host triple>.tar.gz -C /tmp
       /tmp/crypto-<version>-<host triple>/crypto --version

   The version and the short commit in that line are the ones being released. `target/dist` is not
   cleaned between runs and `SHA256SUMS` is *appended* to, so delete the directory first if an
   older run left archives in it.

## The tag

The tag is created by a person, never by CI:

    git tag -a v0.1.0 -m "crypto 0.1.0"
    git push origin v0.1.0

`v<version>` — the workflow strips the `v` and, in the `package` job's "render the Homebrew
formula" step, checks that `target/dist/crypto-<version>-aarch64-apple-darwin.tar.gz` is one of the
tarballs it just packed. A tag that disagrees with `Cargo.toml` fails there, with the archive
names printed — after the builds, but before a release exists.

## What the workflow produces

Pushing the tag starts `release.yml`. Four `build` jobs compile one target each and upload nothing
but the bare binary; `package` (macOS, because `lipo` is) turns those four binaries into the
tarballs and the checksums; two `deb` jobs run `cargo-deb` natively on each Linux architecture and
**install the package on their own runner and run the binary out of it** before uploading it; the
`release` job collects everything.

The assets of the resulting release, nine files:

| Asset | From |
|---|---|
| `crypto-<version>-aarch64-apple-darwin.tar.gz` | `package` |
| `crypto-<version>-x86_64-apple-darwin.tar.gz` | `package` |
| `crypto-<version>-universal-apple-darwin.tar.gz` | `package`, via `xtask lipo` |
| `crypto-<version>-aarch64-unknown-linux-gnu.tar.gz` | `package` |
| `crypto-<version>-x86_64-unknown-linux-gnu.tar.gz` | `package` |
| `crypto_<version>-1_arm64.deb` | `deb` on `ubuntu-22.04-arm` |
| `crypto_<version>-1_amd64.deb` | `deb` on `ubuntu-22.04` |
| `SHA256SUMS` | `package` for the five tarballs, `release` appends the two `.deb`s |
| `crypto.rb` | `package`, rendered by `cargo xtask formula` with the real checksums |

Each tarball holds the binary, `README.md`, `CHANGELOG.md`, `LICENSE`, `man/` (43 pages) and
`completions/` (five scripts).

**The release is a draft.** Nothing is announced and nothing is written back into the repository:
the workflow's default permission is `contents: read`, only the `release` job gets
`contents: write`, and the rendered formula is attached and printed into the job summary rather
than committed. A workflow with push access to `main` is an attack surface this project does not
need.

**A run that failed halfway can be repeated without a new tag.** *Actions → Release → Run workflow*
takes the tag name as its input, and every job checks out `${{ inputs.tag || github.ref }}`, so the
re-run builds the tag and not the default branch. The two runs do not race — `concurrency` groups
them by `inputs.tag || github.ref_name`, so a tag push (`refs/tags/v0.1.0`) and a dispatched re-run
(`v0.1.0`) land in the same group — but a re-run replaces the draft's assets, so let the first one
finish or cancel it by hand.

## After the workflow

1. **Verify the artefacts** on a machine that is not the one they were built on — see the
   checklist below. This is the last point at which a broken release costs nothing.

2. **Read the draft release and publish it.** The notes are the CHANGELOG section from step 3
   above; fix them in the release editor if they read badly, then hit *Publish release*.

3. **Back-port the formula**, as its own pull request:

       # the rendered formula is a release asset, and also in the `package` job summary
       curl -sLO https://github.com/rfoerthe/cryptomator-cli/releases/download/v0.1.0/crypto.rb
       mv crypto.rb packaging/homebrew/crypto.rb
       cargo test -p xtask                       # the_committed_formula_is_what_the_renderer_produces

   That test reads the four `sha256` values back out of the committed file and re-renders
   everything around them, so it passes both before the back-port (placeholders) and after it (the
   release's hashes). Mind what a bare `cargo xtask formula --write` does, though: it puts the
   placeholders back. That is what step 2.3 above wants -- a version whose release does not exist
   yet has no checksums -- but for the version that was just released it undoes this back-port,
   so re-render *that* one with the four `--sha256-…` flags or not at all.

   Until that pull request is merged, `packaging/homebrew/crypto.rb` carries checksums of nothing
   but zeroes and no `brew install` of it can succeed. If the formula also lives in
   a tap, push it there in the same round. The changelog needs nothing: `## Unreleased` never left.

## Verifying on a clean VM

A virtual machine (or a container, for the Debian part) that has never seen this project. The
point is to catch a missing runtime dependency, not to test the code.

**From a tarball, any platform:**

    curl -sLO https://github.com/rfoerthe/cryptomator-cli/releases/download/v0.1.0/SHA256SUMS
    curl -sLO .../crypto-0.1.0-x86_64-unknown-linux-gnu.tar.gz
    sha256sum --ignore-missing -c SHA256SUMS       # shasum -a 256 --ignore-missing -c on macOS
    tar xzf crypto-0.1.0-x86_64-unknown-linux-gnu.tar.gz
    cd crypto-0.1.0-x86_64-unknown-linux-gnu
    ./crypto --version                            # version, short commit and target triple
    ./crypto completions zsh > /dev/null          # the generator runs
    ./crypto mounters --all                       # says what this machine can and cannot mount
    man ./man/crypto.1                            # `mandoc man/crypto.1` on macOS, whose man(1) has no -l

**The Debian package:**

    sudo dpkg -i crypto_0.1.0-1_amd64.deb
    sudo apt-get install -f                       # pulls fuse3 and the recommends, if dpkg complained
    crypto --version
    man crypto && man crypto-vault-create
    dpkg -L crypto                                # binary, 43 manpages, three completion scripts

**The Homebrew formula**, once the back-port of step 3 is merged. Homebrew installs a formula only
from a tap, so it goes through a throwaway one:

    brew tap-new "$USER/crypto"
    cp packaging/homebrew/crypto.rb "$(brew --repository)/Library/Taps/$USER/homebrew-crypto/Formula/"
    brew install "$USER/crypto/crypto"
    crypto --version
    brew test "$USER/crypto/crypto"
    brew uninstall crypto && brew untap "$USER/crypto"

Finally, one real vault: `crypto vault create`, `crypto unlock`, write a file through the mount,
`crypto lock`. A packaging mistake that survives everything above shows up there.

## Signing and notarisation (manual, optional)

Not part of the workflow: there is no Developer-ID certificate in CI, and a signing step that can
only ever be red is worse than none. Done by hand, on a Mac with the certificate in its keychain,
on the Universal binary unpacked from `crypto-<version>-universal-apple-darwin.tar.gz`:

    # 1. Sign. `--options runtime` is the hardened runtime, which notarisation requires;
    #    `--timestamp` fetches a secure timestamp and needs network.
    codesign --force --options runtime --timestamp \
      --sign "Developer ID Application: <NAME> (<TEAMID>)" crypto

    # 2. Notarisation takes an archive, not a bare binary.
    ditto -c -k --keepParent crypto crypto-notarize.zip

    # 3. Submit and wait. The keychain profile is created once, with
    #    `xcrun notarytool store-credentials`.
    xcrun notarytool submit crypto-notarize.zip --keychain-profile "AC_PASSWORD" --wait

    # 4. Verify, then re-pack the signed binary into the tarball and re-do its SHA256SUMS line.
    codesign --verify --deep --strict --verbose=2 crypto
    spctl --assess --type execute -vvv crypto

**A bare Mach-O cannot be stapled.** `xcrun stapler staple` needs a `.app`, `.pkg` or `.dmg`; there
is nowhere in a plain executable to put the ticket. A notarised loose binary is checked online at
first launch instead, which is fine on a machine with a network and a visible delay on one without.
If offline first launch matters, build a `.pkg` around the binary and staple that.

**The `.deb` is not signed.** Neither the package (`dpkg-sig`) nor a repository (`Release.gpg`,
`InRelease`): there is no repository, and a signature on a file downloaded over HTTPS from a GitHub
release adds a key to distribute for very little. `SHA256SUMS` is what a careful user checks.

**Why signing is worth doing at all.** macOS ties an "Always Allow" on a keychain item to the
program's *code identity*. An unsigned binary has none that survives a rebuild, so every new build
of `crypto` counts as a different program and macOS asks again — which is exactly the dialog the
README's keychain section warns about. A stable Developer-ID identity makes the question a
one-time one. The same is true after re-signing with a different certificate.
