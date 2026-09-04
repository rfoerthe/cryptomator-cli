//! Spike B: read a Cryptomator desktop keychain entry.
//! Usage: cargo run -p cryptomator-app --example spike_keychain -- <vault-id>
//! Prints only the byte length and UTF-8 validity of the stored passphrase, never the passphrase.

#[cfg(target_os = "macos")]
fn main() {
    let account = std::env::args()
        .nth(1)
        .expect("usage: spike_keychain <vault-id>");
    match security_framework::passwords::get_generic_password("Cryptomator", &account) {
        Ok(bytes) => {
            println!(
                "found entry for account {account}: {} bytes, valid utf-8: {}",
                bytes.len(),
                std::str::from_utf8(&bytes).is_ok()
            );
        }
        Err(err) => {
            eprintln!("keychain lookup failed: {err} (code {})", err.code());
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("this spike only runs on macOS");
    std::process::exit(2);
}
