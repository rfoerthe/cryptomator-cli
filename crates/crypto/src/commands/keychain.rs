//! `crypto keychain test`: what the keychain is, and whether it actually works.
//!
//! The round trip writes, reads, compares and deletes a throwaway entry under a random key. It
//! never touches a vault's entry, so it is safe to run at any time -- and it is the one command
//! that answers "why did my unlock not find the stored password?" without guessing.
use crate::commands::Ctx;
use crate::exit;
use anyhow::{Context, Result};
use cryptomator_app::keychain::{
    all_providers, call, canonical_provider_class, with_timeout_for, KEYCHAIN_PROBE_TIMEOUT,
};
use cryptomator_app::settings::SettingsJson;
use cryptomator_app::{resolve_keychain_provider, AppError, Keychain, KeychainError};
use serde_json::json;
use std::sync::Arc;

/// The self-test key's prefix. It is not a vault id, so it can never collide with a real entry.
pub const SELFTEST_PREFIX: &str = "crypto-selftest-";
/// What is stored and read back. Not a passphrase of anything, and it is deleted again
/// immediately -- but it is never printed either, because a diagnosis has no business showing
/// what it wrote into a keychain.
const SELFTEST_VALUE: &str = "selftest";
/// Random bytes behind [`SELFTEST_PREFIX`], as hex -- 8 bytes, so 16 characters. Enough that two
/// runs (or two machines sharing a keyring) cannot pick the same key.
const SELFTEST_KEY_BYTES: usize = 8;
/// The width the human output's labels are padded to, so the values line up in a column.
const LABEL_WIDTH: usize = 12;

/// `crypto-selftest-<16 hex>`.
///
/// # Errors
/// Whatever [`getrandom::fill`] reports. A machine without randomness gets an error, never a
/// fixed or zeroed key: two concurrent runs would then fight over one entry, and the "it survived
/// its own deletion" check below would start lying.
fn selftest_key() -> Result<String> {
    let mut bytes = [0u8; SELFTEST_KEY_BYTES];
    getrandom::fill(&mut bytes).context("no randomness for the self-test key")?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{SELFTEST_PREFIX}{hex}"))
}

/// The provider `crypto keychain test` reports on, or `None` when there is nothing to report on.
///
/// Deliberately **not** [`Ctx::keychain`]: that is `for_settings`, which filters by
/// `is_supported()` and therefore answers `None` for exactly the machine whose keychain the user
/// is trying to diagnose. [`all_providers`] is unfiltered, so an unsupported provider can still be
/// named and reported (`supported: false`) instead of disappearing behind one error line. The
/// choice itself mirrors `for_settings`: the provider `keychainProvider` names, else the
/// highest-priority one this build has.
///
/// `None` means there is genuinely nothing to diagnose -- `--no-keychain`, `useKeychain = false`,
/// or a build with no provider at all -- and the caller turns that into the exit-code-8 error that
/// names which of the three it was.
fn provider_to_test(ctx: &Ctx, settings: &SettingsJson) -> Option<Arc<dyn Keychain>> {
    if ctx.no_keychain || !settings.use_keychain {
        return None;
    }
    // An unresolvable value is not an error here, exactly as in `for_settings`: it simply matches
    // no provider and the highest-priority one is reported instead.
    let wanted = resolve_keychain_provider(&settings.keychain_provider)
        .unwrap_or_else(|_| settings.keychain_provider.clone());
    let wanted = canonical_provider_class(&wanted);
    let mut providers = all_providers();
    if providers.is_empty() {
        return None;
    }
    // `all_providers` is sorted by priority, so index 0 is what `for_settings` would fall back to.
    let index = providers
        .iter()
        .position(|provider| provider.java_class_name() == wanted)
        .unwrap_or(0);
    Some(Arc::from(providers.remove(index)))
}

/// One `is_supported()` / `is_locked()` probe under [`KEYCHAIN_PROBE_TIMEOUT`].
///
/// Both are documented as "must not throw and must fail fast", but on Linux they are a D-Bus round
/// trip and on macOS they can wake `securityd`, so they get the same short budget the registry
/// gives them. A probe that does not answer counts as `false` -- the way `for_settings` skips a
/// provider that cannot say whether it exists -- and the reason is logged rather than dropped.
fn probe(keychain: &Arc<dyn Keychain>, what: &str, op: fn(&dyn Keychain) -> bool) -> bool {
    let provider = keychain.display_name();
    let keychain = Arc::clone(keychain);
    match with_timeout_for(provider, KEYCHAIN_PROBE_TIMEOUT, move || {
        Ok(op(keychain.as_ref()))
    }) {
        Ok(answer) => answer,
        Err(err) => {
            log::warn!("{provider}: {what} did not answer: {err}");
            false
        }
    }
}

/// `crypto keychain test`.
///
/// Prints one document -- `provider`, `displayName`, `supported`, `locked`, `roundTrip` -- and
/// *then* fails, so the diagnosis is on stdout even when the answer is "it does not work".
///
/// # Errors
/// [`AppError::Keychain`] (exit code 8) when there is no usable provider at all, when the provider
/// says it is not supported, and when the round trip fails. Whatever reading `settings.json`
/// reports, and whatever the operating system's randomness reports.
pub fn test(ctx: &Ctx) -> Result<u8> {
    let settings = ctx.store.load()?;
    let Some(keychain) = provider_to_test(ctx, &settings) else {
        // Nothing to describe. `keychain_required()` is the same "no keychain here" error every
        // other keychain command gives, and it names what is in the way; it can only fail in this
        // branch, because `provider_to_test` answers `None` only where `for_settings` does too.
        return ctx.keychain_required().map(|_| exit::KEYCHAIN_UNAVAILABLE);
    };
    let provider = keychain.java_class_name().to_string();
    let display_name = keychain.display_name().to_string();
    let supported = probe(&keychain, "isSupported()", |keychain| {
        keychain.is_supported()
    });
    let locked = probe(&keychain, "isLocked()", |keychain| keychain.is_locked());

    let round_trip = if supported {
        // A machine with no randomness has no self-test key, which is a failure of its own rather
        // than a keychain diagnosis -- so it ends the command instead of becoming `roundTrip`.
        round_trip(&keychain, &selftest_key()?)
    } else {
        Err(RoundTripError {
            what: "not attempted",
            cause: KeychainError::Unsupported {
                provider: display_name.clone(),
                hint: "isSupported() said no".to_string(),
            },
        })
    };
    let round_trip_text = match &round_trip {
        Ok(()) => "ok".to_string(),
        // What happened, then what the provider said about it. The provider names itself in its
        // own error, so it is not repeated here -- and neither is what was stored.
        Err(err) => format!("error: {}: {}", err.what, err.cause),
    };

    ctx.out.emit(
        json!({
            "provider": provider,
            "displayName": display_name,
            "supported": supported,
            "locked": locked,
            "roundTrip": round_trip_text,
        }),
        || {
            [
                format!("{:<LABEL_WIDTH$}{provider}", "provider:"),
                format!("{:<LABEL_WIDTH$}{display_name}", "name:"),
                format!("{:<LABEL_WIDTH$}{supported}", "supported:"),
                format!("{:<LABEL_WIDTH$}{locked}", "locked:"),
                format!("{:<LABEL_WIDTH$}{round_trip_text}", "round trip:"),
            ]
            .join("\n")
        },
    )?;

    match round_trip {
        Ok(()) => Ok(exit::OK),
        // The provider's own error, not a wrapper around it: a locked keyring stays
        // `KeychainError::Locked` and keeps the sentence that says what to do about it. Which step
        // it failed at is already on stdout, in `roundTrip`.
        Err(err) => Err(AppError::Keychain(err.cause).into()),
    }
}

/// A round trip that did not work: which step it was, and what the provider said about it.
///
/// The two are kept apart on purpose. `what` is ours (`store failed`, `not attempted`, ...) and
/// goes into the `roundTrip` field; `cause` is the provider's own [`KeychainError`], which already
/// names the provider and carries the exit code -- so nothing has to name the provider twice, and
/// the error the command ends with is the real one rather than a `Backend` wrapper around its text.
struct RoundTripError {
    what: &'static str,
    cause: KeychainError,
}

type RoundTrip = std::result::Result<(), RoundTripError>;

/// Store, load, compare, delete -- and delete again even when a step in between failed.
fn round_trip(keychain: &Arc<dyn Keychain>, key: &str) -> RoundTrip {
    let result = round_trip_inner(keychain, key);
    // Whatever happened, do not leave the throwaway entry behind.
    let cleanup_key = key.to_string();
    let cleanup = call(keychain, move |keychain| keychain.delete(&cleanup_key));
    if let Err(err) = cleanup {
        // Only interesting on its own when the round trip itself was fine; otherwise the first
        // error is the one that explains everything, including why the cleanup could not work
        // either -- but it must not vanish silently, so it is logged (the key name only, never
        // the self-test value) for whoever has to explain a leftover entry later.
        if result.is_ok() {
            return Err(RoundTripError {
                what: "the self-test entry could not be removed",
                cause: KeychainError::Backend {
                    provider: keychain.display_name().to_string(),
                    message: format!("{key} may still be there: {err}"),
                },
            });
        }
        log::warn!("{key} may still be there after a failed round trip: {err}");
    }
    result
}

/// The four steps, in order: store, load and compare, delete, load again.
///
/// Every call goes through [`cryptomator_app::keychain::call`], so each step has the full
/// [`cryptomator_app::KEYCHAIN_TIMEOUT`] and a dialog nobody answers ends the test instead of
/// hanging it.
fn round_trip_inner(keychain: &Arc<dyn Keychain>, key: &str) -> RoundTrip {
    let provider = keychain.display_name().to_string();
    // What the provider itself reported, at the step it happened.
    let refused = |what: &'static str| move |cause: KeychainError| RoundTripError { what, cause };
    // A step that answered, but not with what it was supposed to.
    let wrong = |what: &'static str, message: &str| RoundTripError {
        what,
        cause: KeychainError::Backend {
            provider: provider.clone(),
            message: message.to_string(),
        },
    };

    let write_key = key.to_string();
    call(keychain, move |keychain| {
        keychain.store(&write_key, Some("crypto self-test"), SELFTEST_VALUE)
    })
    .map_err(refused("store failed"))?;

    let read_key = key.to_string();
    let loaded =
        call(keychain, move |keychain| keychain.load(&read_key)).map_err(refused("load failed"))?;
    match loaded.as_deref().map(String::as_str) {
        Some(SELFTEST_VALUE) => {}
        // Neither branch prints what came back: it is a keychain value, whatever it turned out to
        // be.
        Some(_) => {
            return Err(wrong(
                "load mismatch",
                "what came back is not what store wrote",
            ))
        }
        None => {
            return Err(wrong(
                "load mismatch",
                "store reported success but nothing was stored",
            ))
        }
    }

    let delete_key = key.to_string();
    let deleted = call(keychain, move |keychain| keychain.delete(&delete_key))
        .map_err(refused("delete failed"))?;
    if !deleted {
        return Err(wrong("delete failed", "there was nothing to delete"));
    }

    let gone_key = key.to_string();
    let gone = call(keychain, move |keychain| keychain.load(&gone_key))
        .map_err(refused("load after delete failed"))?;
    if gone.is_some() {
        return Err(wrong(
            "load after delete failed",
            "the entry survived its own deletion",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_self_test_key_is_random_and_recognisable() {
        let key = selftest_key().expect("randomness");
        assert!(key.starts_with(SELFTEST_PREFIX), "{key}");
        let hex = &key[SELFTEST_PREFIX.len()..];
        assert_eq!(hex.len(), SELFTEST_KEY_BYTES * 2, "{key}");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{key}");
        // A vault id is base64url and never carries this prefix, so the key cannot collide with a
        // real entry -- and two runs cannot collide with each other either.
        assert_ne!(key, selftest_key().expect("randomness"));
    }

    /// A locked provider refuses every call, including the best-effort cleanup delete after the
    /// round trip has already failed at `store`. That second failure must not replace the first
    /// (the store error is what actually explains things) and, since the fix above, must not
    /// vanish silently either -- covered here by checking the returned error stays the original
    /// one; the `log::warn!` itself has no capturing harness in this crate, so it is exercised but
    /// not asserted on.
    #[test]
    fn a_failed_round_trip_whose_cleanup_also_fails_still_reports_the_original_error() {
        use cryptomator_app::keychain::fake::{FakeKeychain, FAKE_LOCKED_ENV};
        // Process-wide, like every other `CRYPTO_KEYCHAIN_FAKE_*` switch -- but this is the only
        // test in this crate that touches it, so there is nothing to race with.
        std::env::set_var(FAKE_LOCKED_ENV, "1");
        let keychain: Arc<dyn Keychain> = Arc::new(FakeKeychain::at("/nonexistent/keychain.json"));
        let result = round_trip(&keychain, "crypto-selftest-does-not-matter");
        std::env::remove_var(FAKE_LOCKED_ENV);
        let err =
            result.expect_err("a locked keychain refuses the store, and then the cleanup too");
        assert_eq!(
            err.what, "store failed",
            "the store step is what really failed"
        );
        assert!(
            matches!(err.cause, KeychainError::Locked { .. }),
            "{:?}",
            err.cause
        );
    }
}
