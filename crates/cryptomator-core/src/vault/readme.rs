//! RTF readme files written on vault creation (`ui/addvaultwizard/ReadmeGenerator.java`,
//! texts from `i18n/strings.properties` keys `addvault.new.readme.*`).

pub const STORAGE_LOCATION_README_FILE_NAME: &str = "IMPORTANT.rtf";
pub const ACCESS_LOCATION_README_FILE_NAME: &str = "WELCOME.rtf";

const RTF_HEADER: &str = "{\\rtf1\\fbidis\\ansi\\uc0\\fs32\n";
const RTF_FOOTER: &str = "}";
const HELP_URL: &str = "{\\field{\\*\\fldinst HYPERLINK \"http://docs.cryptomator.org/\"}{\\fldrslt http://docs.cryptomator.org}}";

fn heading(text: &str) -> String {
    format!("\\fs40\\qc {text}")
}

fn bold(text: &str) -> String {
    format!("\\b {text}")
}

fn indented(text: &str) -> String {
    format!("    {text}")
}

/// `IMPORTANT.rtf`, written next to the vault (storage location).
pub fn storage_location_readme_rtf() -> String {
    create_document(&[
        heading("⚠️  VAULT FILES  ⚠️"),
        "This is your vault's storage location.".to_string(),
        String::new(),
        bold("DO NOT"),
        indented("•  alter any files within this directory or"),
        indented("•  paste any files for encryption into this directory."),
        String::new(),
        "If you want to encrypt files and view the content of the vault, do the following:"
            .to_string(),
        indented("1.  Add this vault to Cryptomator."),
        indented("2.  Unlock the vault in Cryptomator."),
        indented("3.  Open the access location by clicking the \"Reveal\" button."),
        String::new(),
        format!("If you need help, visit the documentation: {HELP_URL}"),
    ])
}

/// `WELCOME.rtf`, written inside the vault (access location).
pub fn access_location_readme_rtf() -> String {
    create_document(&[
        heading("🔐️  ENCRYPTED VOLUME  🔐️"),
        "This is your vault's access location.".to_string(),
        String::new(),
        "Any files added to this volume will be encrypted by Cryptomator. You can work on it like on any other drive/folder. This is only a decrypted view of its content, your files stay encrypted on your hard drive all the time.".to_string(),
        String::new(),
        "Feel free to remove this file.".to_string(),
    ])
}

pub fn create_document(paragraphs: &[String]) -> String {
    let mut out = String::from(RTF_HEADER);
    for paragraph in paragraphs {
        out.push_str("{\\sa80 ");
        out.push_str(&escape_non_ascii(paragraph));
        out.push_str("}\\par \n");
    }
    out.push_str(RTF_FOOTER);
    out
}

/// Java iterates `String.chars()` (UTF-16 code units); surrogate halves are escaped individually.
pub fn escape_non_ascii(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for unit in input.encode_utf16() {
        match unit {
            u if u < 128 => out.push(u as u8 as char),
            u if u <= 0xFF => out.push_str(&format!("\\'{u:02X}")),
            u if u < 0xFFFF => out.push_str(&format!("\\u{u}")),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ReadmeGenerator.appendEscaped iterates UTF-16 code units: <128 verbatim, <=0xFF as \'XX, <0xFFFF as \u<decimal>, 0xFFFF dropped.
    #[test]
    fn escapes_like_java() {
        assert_eq!(escape_non_ascii("abc"), "abc");
        assert_eq!(escape_non_ascii("é"), "\\'E9");
        assert_eq!(escape_non_ascii("⚠️"), "\\u9888\\u65039");
        assert_eq!(escape_non_ascii("🔐️"), "\\u55357\\u56592\\u65039");
        assert_eq!(escape_non_ascii("•"), "\\u8226");
        assert_eq!(escape_non_ascii("\u{ffff}"), "");
    }

    #[test]
    fn document_has_header_paragraphs_and_footer() {
        let doc = create_document(&["a".to_string(), "".to_string(), "é".to_string()]);
        assert_eq!(doc, "{\\rtf1\\fbidis\\ansi\\uc0\\fs32\n{\\sa80 a}\\par \n{\\sa80 }\\par \n{\\sa80 \\'E9}\\par \n}");
    }

    #[test]
    fn storage_readme_matches_desktop_app() {
        let doc = storage_location_readme_rtf();
        assert!(doc.is_ascii());
        assert!(doc.starts_with("{\\rtf1\\fbidis\\ansi\\uc0\\fs32\n{\\sa80 \\fs40\\qc \\u9888\\u65039  VAULT FILES  \\u9888\\u65039}\\par \n{\\sa80 This is your vault's storage location.}\\par \n{\\sa80 }\\par \n{\\sa80 \\b DO NOT}\\par \n{\\sa80     \\u8226  alter any files within this directory or}\\par \n"));
        assert!(doc.contains(
            "{\\sa80     3.  Open the access location by clicking the \"Reveal\" button.}\\par \n"
        ));
        assert!(doc.ends_with("{\\sa80 If you need help, visit the documentation: {\\field{\\*\\fldinst HYPERLINK \"http://docs.cryptomator.org/\"}{\\fldrslt http://docs.cryptomator.org}}}\\par \n}"));
        assert_eq!(doc.matches("\\par \n").count(), 13);
    }

    #[test]
    fn access_readme_matches_desktop_app() {
        let doc = access_location_readme_rtf();
        assert!(doc.is_ascii());
        assert!(doc.starts_with("{\\rtf1\\fbidis\\ansi\\uc0\\fs32\n{\\sa80 \\fs40\\qc \\u55357\\u56592\\u65039  ENCRYPTED VOLUME  \\u55357\\u56592\\u65039}\\par \n{\\sa80 This is your vault's access location.}\\par \n"));
        assert!(doc.ends_with("{\\sa80 Feel free to remove this file.}\\par \n}"));
        assert_eq!(doc.matches("\\par \n").count(), 6);
        assert_eq!(STORAGE_LOCATION_README_FILE_NAME, "IMPORTANT.rtf");
        assert_eq!(ACCESS_LOCATION_README_FILE_NAME, "WELCOME.rtf");
    }
}
