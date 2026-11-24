//! The reader of `pdm.lock`.

use super::pypi::{Files, pypi_files, pypi_name, text_version, toml_lock};
use super::{Parsed, Source};
use std::cell::Cell;
use toml::de::DeTable;

pub(super) const READ: Option<super::Reader> = Some(|text, _| pdm(text));

/// The keys that make an entry a requirement of version control, in the order PDM's
/// `Requirement.from_req_dict` tries them (`VCS_SCHEMA`).
const VCS: [&str; 4] = ["git", "hg", "svn", "bzr"];

/// The versions of the format PDM 2.17 and later read: `metadata.lock_version` 4.0 to 4.5, with
/// any third part (`PDMLock.compatibility`, `spec_version` 4.5.1).
fn known(version: &str) -> bool {
    let minor = |m: &str| matches!(m, "0" | "1" | "2" | "3" | "4" | "5");
    match version.split('.').collect::<Vec<_>>()[..] {
        ["4", m] => minor(m),
        ["4", m, micro] => {
            minor(m) && !micro.is_empty() && micro.bytes().all(|c| c.is_ascii_digit())
        }
        _ => false,
    }
}

/// `pdm.lock` of a version `known` takes: every table of the array `package`, by its name
/// normalised, at the line of its name. What PDM does is read in its own source,
/// `src/pdm/models/requirements.py` and `src/pdm/models/repositories/lock.py`. PDM reads an entry
/// as `Requirement.from_req_dict` does: the first key of version control present makes it one
/// (`git` is git), else `path` (a path) or `url` (another registry), else it is a named
/// requirement, which PDM installs from the index the project configures, checking each file
/// against its hash in `files`. No
/// requirement takes an index and `_read_pdm_lock` reads none, so the lockfile never records it,
/// and what a named entry is comes from its `files` (`pypi_files`). With the strategy
/// `static_urls` each row is a file's address: all PyPI's files of the entry's name and version
/// make it PyPI's, any other another registry's. By default each row is a file's name, which a
/// private index serves as PyPI does: names all of PyPI's form make it an entry of an
/// unrecorded index, compared under its plain name and never known not to be affected. A file
/// that is not TOML, no `lock_version` as a string, a `package` that is not an array of tables,
/// an entry whose name, or version where there is one, is not a string, and an address in
/// `files` without `static_urls`, which `_read_pdm_lock` refuses, fail the reading. Another
/// `lock_version` is a kind with no reader. Left not told: a name that is not valid, version
/// control other than git, both `path` and `url`, `editable` with neither, and a named entry
/// with no version, no file, names and addresses together, or names not of PyPI's form.
fn pdm(text: &str) -> Parsed {
    let static_urls = Cell::new(false);
    let head = |lock: &DeTable| {
        let metadata = lock.get("metadata").map(|m| m.get_ref());
        let strategy = metadata.and_then(|m| m.get("strategy")?.get_ref().as_array());
        static_urls.set(strategy.is_some_and(|s| {
            (s.iter()).any(|flag| flag.get_ref().as_str() == Some("static_urls"))
        }));
        let version = metadata.and_then(|m| m.get("lock_version"));
        text_version(version, "pdm.lock", known).map(|()| "package")
    };
    toml_lock(text, head, |package, name| {
        let version = match package.get("version") {
            None => None,
            Some(v) => Some(v.get_ref().as_str()?),
        };
        let files = package.get("files").map(|f| f.get_ref());
        let rows = files
            .and_then(|f| f.as_array())
            .map_or(&[][..], |rows| &rows[..]);
        let addressed = rows.iter().any(|row| row.get_ref().get("url").is_some());
        if !static_urls.get() && addressed {
            return None;
        }
        let name = pypi_name(name);
        let has = |key: &str| package.contains_key(key);
        let source = match VCS.iter().find(|key| has(key)) {
            Some(&"git") => Some(Source::Git),
            Some(_) => None,
            None if has("path") && has("url") => None,
            None if has("path") => Some(Source::Path),
            None if has("url") => Some(Source::OtherRegistry),
            None if has("editable") => None,
            None => match version.zip(name.as_deref()) {
                Some((v, n)) => match pypi_files(files, n, v) {
                    Some(Files::Addresses(true)) => Some(Source::Registry),
                    Some(Files::Addresses(false)) => Some(Source::OtherRegistry),
                    Some(Files::Names(true)) => Some(Source::UnrecordedIndex),
                    _ => None,
                },
                None => None,
            },
        };
        Some(
            name.zip(source)
                .map(|(name, source)| (name, version.map(str::to_string), source)),
        )
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{Dir, one_not_told, read_one};
    use crate::store::Cause;

    const HASH: &str = "abababababababababababababababababababababababababababababababab";
    /// Where PyPI keeps a file, as its paths are: two parts of two hex digits and one of sixty.
    const PYPI: &str = "https://files.pythonhosted.org/packages/3a/1b/0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab";

    /// The `files` of an entry as PDM writes them: by name, or with `at` by address under it.
    fn files(names: &[&str], at: Option<&str>) -> String {
        let rows: Vec<String> = (names.iter())
            .map(|name| match at {
                None => format!("    {{file = \"{name}\", hash = \"sha256:{HASH}\"}},\n"),
                Some(at) => format!("    {{url = \"{at}/{name}\", hash = \"sha256:{HASH}\"}},\n"),
            })
            .collect();
        format!("files = [\n{}]\n", rows.concat())
    }

    /// The two files of PyPI's that `friendly-bard` 1.2.0 lists.
    const BARD: [&str; 2] = [
        "friendly_bard-1.2.0-py3-none-any.whl",
        "friendly_bard-1.2.0.tar.gz",
    ];

    /// A `pdm.lock` of `lock_version` 4.5.0 as PDM 2.17 writes it, with every source an entry can
    /// have: by default, or with `static_urls` true as `pdm lock --static-urls` writes it, each
    /// file by its address. `Gadget` comes from a private index. Names and addresses are
    /// invented.
    pub(in super::super) fn lock(static_urls: bool) -> String {
        let (strategy, pypi, private, fetched) = match static_urls {
            false => ("", None, None, None),
            true => (
                ", \"static_urls\"",
                Some(PYPI),
                Some("https://pypi.example.invalid/packages"),
                Some("https://example.invalid"),
            ),
        };
        format!(
            r#"# This file is @generated by PDM.
# It is not intended for manual editing.

[metadata]
groups = ["default", "dev"]
strategy = ["inherit_metadata"{strategy}]
lock_version = "4.5.0"
content_hash = "sha256:{HASH}"

[[metadata.targets]]
requires_python = ">=3.9"

[[package]]
name = "friendly-bard"
version = "1.2.0"
requires_python = ">=3.9"
summary = "An invented package"
groups = ["default"]
{bard}
[[package]]
name = "Gadget"
version = "2.0.0"
summary = ""
groups = ["dev"]
marker = "sys_platform == \"darwin\""
{gadget}
[[package]]
name = "tool"
version = "0.3.0"
git = "https://example.invalid/tool.git"
ref = "main"
revision = "{commit}"
summary = ""
groups = ["default"]

[[package]]
name = "fetched"
version = "1.0.0"
url = "https://example.invalid/fetched-1.0.0.tar.gz"
summary = ""
groups = ["default"]
{fetched}
[[package]]
name = "vendored"
version = "1.0.0"
path = "./vendor/vendored-1.0.0.tar.gz"
summary = ""
groups = ["default"]

[[package]]
name = "sibling"
path = "./packages/sibling"
editable = true
summary = ""
groups = ["default"]
"#,
            bard = files(&BARD, pypi),
            gadget = files(&["gadget-2.0.0.tar.gz"], private),
            fetched = files(&["fetched-1.0.0.tar.gz"], fetched),
            commit = "c".repeat(40),
        )
    }

    #[test]
    fn a_pdm_entry_is_pypi_s_only_by_pypi_s_addresses_and_by_file_names_its_index_is_unrecorded() {
        // An entry from git, an address, an archive or a folder can share a name with PyPI's at
        // will. A named one carries the bare name an advisory gives only when its files are at
        // PyPI's addresses; by name alone a private index's file looks like PyPI's, so it is of
        // an unrecorded index. Two spellings are one name.
        let at = "dev/shop/pdm.lock";
        for (static_urls, bard, gadget) in [
            (
                false,
                "friendly-bard (unrecorded index)",
                "gadget (unrecorded index)",
            ),
            (true, "friendly-bard", "gadget (other registry)"),
        ] {
            let (said, reason) = read_one("pdm", "pdm.lock", &lock(static_urls));
            let expected = [
                format!("PyPI/fetched (other registry)|part_of|checkout|{at}:44"),
                format!("PyPI/fetched (other registry)|has_version|1.0.0|{at}:44"),
                format!("PyPI/{bard}|part_of|checkout|{at}:14"),
                format!("PyPI/{bard}|has_version|1.2.0|{at}:14"),
                format!("PyPI/{gadget}|part_of|checkout|{at}:25"),
                format!("PyPI/{gadget}|has_version|2.0.0|{at}:25"),
                format!("PyPI/sibling (path)|part_of|checkout|{at}:61"),
                format!("PyPI/tool (git)|part_of|checkout|{at}:35"),
                format!("PyPI/tool (git)|has_version|0.3.0|{at}:35"),
                format!("PyPI/vendored (path)|part_of|checkout|{at}:54"),
                format!("PyPI/vendored (path)|has_version|1.0.0|{at}:54"),
            ];
            assert_eq!(said, expected, "static_urls {static_urls}");
            assert_eq!(reason, None, "static_urls {static_urls}");
        }
    }

    #[test]
    fn a_pdm_entry_whose_files_name_or_keys_do_not_tell_it_is_not_told_never_dropped() {
        // Each changes the first package only, at line 14, and that package is left not told.
        let (lock, at_pypi) = (lock(false), lock(true));
        let (bard, addresses) = (files(&BARD, None), files(&BARD, Some(PYPI)));
        let mixed = addresses.replacen(
            &format!("url = \"{PYPI}/friendly_bard-1.2.0.tar.gz\""),
            "file = \"friendly_bard-1.2.0.tar.gz\"",
            1,
        );
        let summary = "summary = \"An invented package\"\n";
        let with = |key: &str| format!("{summary}{key}\n");
        let another = files(&["friendly_bard-1.2.1.tar.gz"], None);
        for (case, text, from, to) in [
            ("no files", &lock, bard.clone(), "files = []\n".to_string()),
            ("no files key", &lock, bard.clone(), String::new()),
            ("a name of another version", &lock, bard, another),
            ("names and addresses", &at_pypi, addresses, mixed),
            (
                "no version",
                &lock,
                "version = \"1.2.0\"\n".into(),
                String::new(),
            ),
            (
                "a name not valid",
                &lock,
                "\"friendly-bard\"".into(),
                "\"friendly-bard-\"".into(),
            ),
            (
                "mercurial",
                &lock,
                summary.into(),
                with("hg = \"https://example.invalid/bard\""),
            ),
            (
                "an editable with no path",
                &lock,
                summary.into(),
                with("editable = true"),
            ),
            (
                "both a path and an address",
                &lock,
                summary.into(),
                with("path = \"./bard\"\nurl = \"https://example.invalid/bard.tar.gz\""),
            ),
        ] {
            let changed = text.replacen(&from, &to, 1);
            assert_ne!(&changed, text, "{case}");
            let (said, reason) = read_one("pdm-told", "pdm.lock", &changed);
            assert_eq!(reason, one_not_told("pdm.lock#L14"), "{case}");
            assert_eq!(said.len(), 9, "{case}");
        }
        // Git is taken before any other key, as PDM takes it.
        let text = lock.replacen(
            summary,
            &with("git = \"https://example.invalid/bard.git\""),
            1,
        );
        let (said, reason) = read_one("pdm-git", "pdm.lock", &text);
        let git = "PyPI/friendly-bard (git)|has_version|1.2.0|dev/shop/pdm.lock:14";
        assert!(said.contains(&git.to_string()), "{said:?}");
        assert_eq!(reason, None);
    }

    #[test]
    fn a_pdm_lock_pdm_would_refuse_fails_and_another_lock_version_is_a_kind_with_no_reader() {
        let addressed = lock(true).replace(", \"static_urls\"", "");
        let lock = lock(false);
        for (case, text) in [
            ("not toml", lock.replacen("[[package]]", "[[package]", 1)),
            (
                "a duplicate key",
                lock.replacen(
                    "version = \"1.2.0\"",
                    "version = \"1.2.0\"\nversion = \"1.2.0\"",
                    1,
                ),
            ),
            (
                "a version not a string",
                lock.replacen("version = \"1.2.0\"", "version = 1", 1),
            ),
            (
                "no name",
                lock.replacen("name = \"friendly-bard\"\n", "", 1),
            ),
            (
                "a name not a string",
                lock.replacen("name = \"friendly-bard\"", "name = 1", 1),
            ),
            (
                "no lock_version",
                lock.replacen("lock_version = \"4.5.0\"\n", "", 1),
            ),
            (
                "a lock_version not a string",
                lock.replacen("lock_version = \"4.5.0\"", "lock_version = 4.5", 1),
            ),
            (
                "a lock_version of no shape",
                lock.replacen("lock_version = \"4.5.0\"", "lock_version = \"4 5\"", 1),
            ),
            ("addresses without static_urls", addressed),
            (
                "package not an array",
                "package = 1\n[metadata]\nlock_version = \"4.5.0\"\n".into(),
            ),
            (
                "package of rows",
                "package = [1]\n[metadata]\nlock_version = \"4.5.0\"\n".into(),
            ),
        ] {
            assert_ne!(text, lock, "{case}");
            let dir = Dir::new("pdm-failed", &[("pdm.lock", &text)]);
            let (o, said) = dir.read();
            assert!(said.is_empty(), "{case}: {said:?}");
            assert_eq!(
                (o.reason.as_deref(), o.gap.cause),
                (Some("could not be read: pdm.lock"), Some(Cause::Failed)),
                "{case}"
            );
        }
        for version in ["4.0", "4.5", "4.0.0", "4.4.2", "4.5.12"] {
            let text = lock.replace("\"4.5.0\"", &format!("\"{version}\""));
            let (said, reason) = read_one("pdm-read", "pdm.lock", &text);
            assert_eq!((said.len(), reason), (11, None), "{version}");
        }
        for version in [
            "3.1", "4.6", "4.6.0", "5.0", "4", "4.5.0.1", "4.5.", "4.5.x", "4.x",
        ] {
            let text = lock.replace("\"4.5.0\"", &format!("\"{version}\""));
            let (said, reason) = read_one("pdm-version", "pdm.lock", &text);
            assert!(said.is_empty(), "{version}");
            let named = format!("not supported yet: pdm.lock version {version}");
            assert_eq!(reason, Some(named), "{version}");
        }
    }
}
