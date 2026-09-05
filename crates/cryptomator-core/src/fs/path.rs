//! Cleartext paths inside a vault (`CryptoPath` + `CryptoPathFactory`): always absolute, every
//! component NFC-normalised, empty and `.` components dropped, `..` resolved lexically and never
//! above the root.
use crate::error::{CoreError, Result};
use std::fmt;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CleartextPath {
    elements: Vec<String>,
}

impl CleartextPath {
    pub fn root() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    /// A leading `/` is optional; `a/b` and `/a/b` are the same path.
    pub fn parse(path: &str) -> Self {
        Self::root().join_path(path)
    }

    pub fn elements(&self) -> &[String] {
        &self.elements
    }

    pub fn is_root(&self) -> bool {
        self.elements.is_empty()
    }

    pub fn depth(&self) -> usize {
        self.elements.len()
    }

    /// `None` for the root.
    pub fn parent(&self) -> Option<CleartextPath> {
        if self.elements.is_empty() {
            None
        } else {
            Some(Self {
                elements: self.elements[..self.elements.len() - 1].to_vec(),
            })
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        self.elements.last().map(String::as_str)
    }

    /// Appends one name (NFC-normalised). Rejects empty names, `.`, `..` and names containing `/`.
    pub fn join(&self, name: &str) -> Result<CleartextPath> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(CoreError::InvalidArgument(format!(
                "invalid file name {name:?}"
            )));
        }
        let mut elements = self.elements.clone();
        elements.push(name.nfc().collect());
        Ok(Self { elements })
    }

    /// Resolves a relative path against `self`; an absolute path (leading `/`) replaces it.
    pub fn join_path(&self, path: &str) -> CleartextPath {
        let mut elements = if path.starts_with('/') {
            Vec::new()
        } else {
            self.elements.clone()
        };
        for raw in path.split('/') {
            match raw {
                "" | "." => {}
                ".." => {
                    elements.pop();
                }
                other => elements.push(other.nfc().collect()),
            }
        }
        Self { elements }
    }

    pub fn starts_with(&self, prefix: &CleartextPath) -> bool {
        self.elements.starts_with(&prefix.elements)
    }

    /// Replaces the prefix `old` by `new`; `None` if `self` does not start with `old`.
    pub fn rebase(&self, old: &CleartextPath, new: &CleartextPath) -> Option<CleartextPath> {
        let rest = self.elements.strip_prefix(old.elements.as_slice())?;
        let mut elements = new.elements.clone();
        elements.extend_from_slice(rest);
        Some(Self { elements })
    }
}

impl fmt::Display for CleartextPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.elements.is_empty() {
            f.write_str("/")
        } else {
            for element in &self.elements {
                write!(f, "/{element}")?;
            }
            Ok(())
        }
    }
}

/// `dir.resolve(name)` for display purposes (the name is not validated, it comes from a listing).
pub fn child_display(dir: &CleartextPath, name: &str) -> String {
    if dir.is_root() {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalises() {
        assert_eq!(CleartextPath::parse("/").to_string(), "/");
        assert_eq!(CleartextPath::parse("").to_string(), "/");
        assert_eq!(CleartextPath::parse("a/b").to_string(), "/a/b");
        assert_eq!(CleartextPath::parse("/a//b/./c/../d").to_string(), "/a/b/d");
        assert_eq!(CleartextPath::parse("/../../x").to_string(), "/x");
        // NFD "café" (e + combining acute) becomes NFC
        let nfd = "cafe\u{301}.txt";
        assert_eq!(CleartextPath::parse(nfd).file_name(), Some("caf\u{e9}.txt"));
    }

    #[test]
    fn parent_and_file_name() {
        let p = CleartextPath::parse("/docs/notes.md");
        assert_eq!(p.file_name(), Some("notes.md"));
        assert_eq!(p.parent().unwrap().to_string(), "/docs");
        assert_eq!(p.parent().unwrap().parent().unwrap(), CleartextPath::root());
        assert!(CleartextPath::root().parent().is_none());
        assert!(CleartextPath::root().file_name().is_none());
        assert_eq!(p.depth(), 2);
    }

    #[test]
    fn join_rejects_bad_names() {
        let root = CleartextPath::root();
        assert_eq!(root.join("a").unwrap().to_string(), "/a");
        for bad in ["", ".", "..", "a/b"] {
            assert!(root.join(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            root.join("cafe\u{301}").unwrap().file_name(),
            Some("caf\u{e9}")
        );
    }

    #[test]
    fn join_path_resolves_relative_and_absolute() {
        let dir = CleartextPath::parse("/a/b");
        assert_eq!(dir.join_path("c/d").to_string(), "/a/b/c/d");
        assert_eq!(dir.join_path("../x").to_string(), "/a/x");
        assert_eq!(dir.join_path("/y").to_string(), "/y");
    }

    #[test]
    fn prefix_and_rebase() {
        let a = CleartextPath::parse("/a");
        let ab = CleartextPath::parse("/a/b");
        let abc = CleartextPath::parse("/a/b/c");
        assert!(abc.starts_with(&ab));
        assert!(abc.starts_with(&CleartextPath::root()));
        assert!(!ab.starts_with(&abc));
        assert!(!CleartextPath::parse("/ab").starts_with(&a));
        let moved = abc.rebase(&ab, &CleartextPath::parse("/x")).unwrap();
        assert_eq!(moved.to_string(), "/x/c");
        assert!(abc.rebase(&CleartextPath::parse("/z"), &a).is_none());
        assert_eq!(child_display(&CleartextPath::root(), "f"), "/f");
        assert_eq!(child_display(&ab, "f"), "/a/b/f");
    }
}
