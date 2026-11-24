//! The reader of `Pipfile.lock`.

use super::pypi::{PYPI_INDEX, canonical_version, pypi_name};
use super::{At, Dep, Parsed, Source};
use serde_json::{Map, Value};

pub(super) const READ: Option<super::Reader> = Some(pipfile);

/// The keys of a version control system in an entry (pipenv's `VCS_LIST`).
const VCS: [&str; 4] = ["git", "hg", "svn", "bzr"];

/// `Pipfile.lock` of `_meta.pipfile-spec` 6, read as pipenv reads it: JSON, after a UTF-8 byte
/// order mark is dropped (`utils/lockfile.py`, `Lockfile.load`, encoding `utf-8-sig`). Python's
/// `json` and `serde_json` both keep the last of two equal keys, so a file with equal keys is
/// read as pipenv reads it. Every top-level key but `_meta` is a category of packages (`default`,
/// `develop` and the categories a Pipfile names), and every entry of each is recorded, at
/// `<category>/<name>`, under its name normalised.
///
/// An entry is PyPI's when it has no key of another source, no `pip_args`, a `version` of `==`
/// and a canonical version, a list of `hashes` that is not empty, and its `index`, or the first
/// source of `_meta.sources` when it has none, names a source whose `url` is PyPI's simple
/// index. pipenv installs each entry with pip from that source alone, the first of its name,
/// with a `--hash` for each hash (`routines/install.py`, `batch_install`; `utils/sources.py`,
/// `Sources.default`). The format keeps no file names, so no file is checked: the tie rests on
/// the source and on pip installing only a file whose hash the entry lists. A key of a version
/// control system is git; `path`, and a `file` that is a path or a `file:` address, are a path;
/// a `file` of another address, and an index of another source, are another registry.
///
/// The reading fails on text that is not JSON, a `_meta` with no integer `pipfile-spec` or no
/// list of `sources`, a category that is not an object, and an entry that is neither an object
/// nor a string. Another `pipfile-spec` is named as a kind with no reader. Left not told: an
/// entry that is a string, a name `pypi_name` refuses, an entry from an index whose version is
/// not pinned to a canonical one, PyPI's entry with no hashes, `pip_args`, `editable` or `ref`
/// with no source beside them, an index that names no source, and a source whose `url` is not a
/// string or holds `$`, which pipenv expands from the environment.
fn pipfile(text: &str, kind: &str) -> Parsed {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Ok(Value::Object(lock)) = serde_json::from_str::<Value>(text) else {
        return Parsed::Failed;
    };
    let Some(meta) = lock.get("_meta").and_then(Value::as_object) else {
        return Parsed::Failed;
    };
    match meta.get("pipfile-spec").and_then(Value::as_u64) {
        Some(6) => {}
        Some(n) => return Parsed::NoReader(format!("{kind} version {n}")),
        None => return Parsed::Failed,
    }
    let Some(sources) = meta.get("sources").and_then(Value::as_array) else {
        return Parsed::Failed;
    };
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    for (category, entries) in lock.iter().filter(|(key, _)| *key != "_meta") {
        let Value::Object(entries) = entries else {
            return Parsed::Failed;
        };
        for (name, entry) in entries {
            let key = format!("{category}/{name}");
            let dep = match entry {
                Value::Object(entry) => pipfile_entry(name, entry, sources),
                // pipenv never writes a string, and what it installs for one is not settled here.
                Value::String(_) => None,
                _ => return Parsed::Failed,
            };
            match dep {
                Some((name, version, source)) => out.push(Dep {
                    at: At::Key(key),
                    name,
                    version,
                    source,
                }),
                None => unknown.push(key),
            }
        }
    }
    Parsed::Deps("PyPI", out, unknown)
}

/// The package an entry is, normalised, its version and its source; `None` when the lockfile
/// does not tell.
fn pipfile_entry(
    name: &str,
    entry: &Map<String, Value>,
    sources: &[Value],
) -> Option<(String, Option<String>, Source)> {
    let name = pypi_name(name)?;
    let has = |key: &str| entry.contains_key(key);
    let source = match entry.get("file") {
        _ if VCS.iter().any(|key| has(key)) => return Some((name, None, Source::Git)),
        _ if has("path") => return Some((name, None, Source::Path)),
        Some(file) => {
            let file = file.as_str()?;
            let on_disk = file.starts_with("file:") || !file.contains("://");
            let source = if on_disk {
                Source::Path
            } else {
                Source::OtherRegistry
            };
            return Some((name, None, source));
        }
        None if has("editable") || has("ref") || has("pip_args") => return None,
        None => index_source(entry, sources)?,
    };
    let version = (entry.get("version").and_then(Value::as_str))
        .and_then(|v| v.strip_prefix("=="))
        .filter(|v| canonical_version(v))?;
    let hashes = (entry.get("hashes").and_then(Value::as_array))
        .is_some_and(|h| !h.is_empty() && h.iter().all(Value::is_string));
    if source == Source::Registry && !hashes {
        return None;
    }
    Some((name, Some(version.to_string()), source))
}

/// The index pipenv installs an entry from: the first source of the name its `index` gives, or
/// the first source when it gives none; `None` when that is no source or its `url` does not say.
fn index_source(entry: &Map<String, Value>, sources: &[Value]) -> Option<Source> {
    let source = match entry.get("index") {
        None => sources.first(),
        Some(index) => {
            let index = index.as_str()?;
            (sources.iter()).find(|s| s.get("name").and_then(Value::as_str) == Some(index))
        }
    };
    match source?.get("url")?.as_str()? {
        url if PYPI_INDEX.contains(&url) => Some(Source::Registry),
        url if url.contains('$') => None,
        _ => Some(Source::OtherRegistry),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{one_not_told, read_one};

    /// A `Pipfile.lock` as pipenv writes it, with every source an entry can come from, a
    /// category of a Pipfile's own and one package in two categories at two versions. Names
    /// and addresses other than PyPI's are invented.
    pub(in super::super) const PIPFILE: &str = r#"{
    "_meta": {
        "hash": {
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.12"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            },
            {
                "name": "private",
                "url": "https://pypi.example.invalid/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "gadget": {
            "hashes": [
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            ],
            "version": "==2.0.1"
        },
        "internal-lib": {
            "hashes": [
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            ],
            "index": "private",
            "version": "==0.4.0"
        },
        "local-pkg": {
            "editable": true,
            "path": "."
        },
        "vcs-tool": {
            "git": "https://example.invalid/vcs-tool.git",
            "ref": "0123456789abcdef0123456789abcdef01234567"
        },
        "vendored": {
            "file": "vendor/vendored-1.0.0.tar.gz"
        },
        "web-archive": {
            "file": "https://example.invalid/web-archive-1.0.0.tar.gz"
        },
        "widget_tools": {
            "hashes": [
                "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                "sha256:4444444444444444444444444444444444444444444444444444444444444444"
            ],
            "index": "pypi",
            "markers": "python_version >= '3.9'",
            "version": "==1.2.0"
        }
    },
    "develop": {
        "gadget": {
            "hashes": [
                "sha256:5555555555555555555555555555555555555555555555555555555555555555"
            ],
            "index": "pypi",
            "version": "==2.1.0"
        }
    },
    "docs": {
        "Sphinx.Theme": {
            "extras": ["fonts"],
            "hashes": [
                "sha256:6666666666666666666666666666666666666666666666666666666666666666"
            ],
            "index": "pypi",
            "version": "==3.0.0rc1"
        }
    }
}
"#;

    #[test]
    fn every_category_of_a_pipfile_lock_is_read_and_each_entry_says_where_it_comes_from() {
        // A package of another index, git, a path or a web address shares names with PyPI's at
        // will: only an entry from PyPI's index is named bare. A file pipenv reads after a byte
        // order mark says the same.
        let at = "dev/shop/Pipfile.lock#";
        let expected = [
            format!("PyPI/gadget|part_of|checkout|{at}default/gadget"),
            format!("PyPI/gadget|has_version|2.0.1|{at}default/gadget"),
            format!("PyPI/gadget|has_version|2.1.0|{at}develop/gadget"),
            format!("PyPI/internal-lib (other registry)|part_of|checkout|{at}default/internal-lib"),
            format!(
                "PyPI/internal-lib (other registry)|has_version|0.4.0|{at}default/internal-lib"
            ),
            format!("PyPI/local-pkg (path)|part_of|checkout|{at}default/local-pkg"),
            format!("PyPI/sphinx-theme|part_of|checkout|{at}docs/Sphinx.Theme"),
            format!("PyPI/sphinx-theme|has_version|3.0.0rc1|{at}docs/Sphinx.Theme"),
            format!("PyPI/vcs-tool (git)|part_of|checkout|{at}default/vcs-tool"),
            format!("PyPI/vendored (path)|part_of|checkout|{at}default/vendored"),
            format!("PyPI/web-archive (other registry)|part_of|checkout|{at}default/web-archive"),
            format!("PyPI/widget-tools|part_of|checkout|{at}default/widget_tools"),
            format!("PyPI/widget-tools|has_version|1.2.0|{at}default/widget_tools"),
        ];
        for text in [PIPFILE.to_string(), format!("\u{feff}{PIPFILE}")] {
            let (said, reason) = read_one("pipfile", "Pipfile.lock", &text);
            assert_eq!(said, expected);
            assert_eq!(reason, None);
        }
    }

    const PYPI: &str = r#"{"name": "pypi", "url": "https://pypi.org/simple"}"#;
    const PRIVATE: &str = r#"{"name": "private", "url": "https://pypi.example.invalid/simple"}"#;
    const HASHES: &str =
        r#""hashes": ["sha256:7777777777777777777777777777777777777777777777777777777777777777"]"#;

    #[test]
    fn a_pipfile_entry_is_pypi_s_only_when_its_source_is_pypi_s_index_its_version_pinned_and_hashed()
     {
        // No false calm. pipenv installs an entry from the source its `index` names, or from
        // the first source, with pip, only a file of a listed hash: anything less than PyPI's
        // index, a pinned canonical version and hashes is another registry or not told.
        let pinned = format!(r#"{HASHES}, "version": "==1.2.0""#);
        let slash = r#"{"name": "pypi", "url": "https://pypi.org/simple/"}"#;
        let fake = r#"{"name": "pypi", "url": "https://pypi.example.invalid/simple"}"#;
        let named = r#"{"name": "pypi", "url": "${PYPI_URL}"}"#;
        let bare = r#"{"name": "pypi"}"#;
        let git = r#""git": "https://example.invalid/widget.git", "ref": "0123456789abcdef""#;
        let (registry, other) = (Some("PyPI/widget|"), Some("PyPI/widget (other registry)|"));
        let (in_git, in_path) = (Some("PyPI/widget (git)|"), Some("PyPI/widget (path)|"));
        for (sources, entry, expected) in [
            (PYPI, format!(r#"{pinned}, "index": "pypi""#), registry),
            (slash, pinned.clone(), registry),
            (
                &format!("{PRIVATE}, {PYPI}"),
                format!(r#"{pinned}, "index": "pypi""#),
                registry,
            ),
            (
                &format!("{PYPI}, {PRIVATE}"),
                format!(r#"{pinned}, "index": "private""#),
                other,
            ),
            (&format!("{PRIVATE}, {PYPI}"), pinned.clone(), other),
            (
                &format!("{fake}, {PYPI}"),
                format!(r#"{pinned}, "index": "pypi""#),
                other,
            ),
            (PRIVATE, r#""version": "==1.2.0""#.to_string(), other),
            // From elsewhere, whatever else the entry says.
            (PYPI, format!("{pinned}, {git}"), in_git),
            (
                PYPI,
                r#""hg": "https://example.invalid/widget""#.to_string(),
                in_git,
            ),
            (
                PYPI,
                format!(r#"{pinned}, "editable": true, "path": ".""#),
                in_path,
            ),
            (
                PYPI,
                r#""file": "file:///opt/wheels/widget-1.2.0.tar.gz""#.into(),
                in_path,
            ),
            (
                PYPI,
                format!(r#"{pinned}, "file": "https://example.invalid/w.whl""#),
                other,
            ),
            (
                PYPI,
                r#""file": "ftp://example.invalid/w.whl""#.to_string(),
                other,
            ),
            // Not told.
            (PYPI, format!(r#"{HASHES}, "version": ">=1.2.0""#), None),
            (PYPI, format!(r#"{HASHES}, "version": "===1.2.0""#), None),
            (
                PYPI,
                format!(r#"{HASHES}, "version": "==1.2.0+local""#),
                None,
            ),
            (PYPI, format!(r#"{HASHES}, "version": "1.2.0""#), None),
            (PYPI, format!(r#"{HASHES}, "version": 1"#), None),
            (PYPI, HASHES.to_string(), None),
            (PRIVATE, r#""version": "==v1.2""#.to_string(), None),
            (PYPI, r#""version": "==1.2.0""#.to_string(), None),
            (
                PYPI,
                r#""hashes": [], "version": "==1.2.0""#.to_string(),
                None,
            ),
            (
                PYPI,
                r#""hashes": [1], "version": "==1.2.0""#.to_string(),
                None,
            ),
            (PYPI, format!(r#"{pinned}, "index": "nowhere""#), None),
            (PYPI, format!(r#"{pinned}, "index": 1"#), None),
            ("", pinned.clone(), None),
            (named, pinned.clone(), None),
            (bare, pinned.clone(), None),
            (
                PYPI,
                format!(r#"{pinned}, "pip_args": ["--index-url", "x"]"#),
                None,
            ),
            (PYPI, format!(r#"{pinned}, "editable": true"#), None),
            (PYPI, format!(r#"{pinned}, "ref": "main""#), None),
            (PYPI, r#""file": 1"#.to_string(), None),
        ] {
            let text = format!(
                r#"{{"_meta": {{"pipfile-spec": 6, "sources": [{sources}]}},
                    "default": {{"widget": {{{entry}}}}}}}"#
            );
            let (said, reason) = read_one("pipfile-entry", "Pipfile.lock", &text);
            let first = said.first().map(|s| &s[..s.find('|').unwrap_or(0) + 1]);
            assert_eq!(first, expected, "{sources} {entry}");
            let not_told = one_not_told("Pipfile.lock#default/widget");
            let want = if expected.is_some() { None } else { not_told };
            assert_eq!(reason, want, "{sources} {entry}");
        }
        // An entry that is a string, or a name that is no project's, is not told either.
        let whole = format!(r#"{{{HASHES}, "version": "==1.2.0"}}"#);
        for (name, entry) in [("widget", r#""==1.2.0""#), ("wid get", &whole)] {
            let text = format!(
                r#"{{"_meta": {{"pipfile-spec": 6, "sources": [{PYPI}]}},
                    "default": {{"{name}": {entry}}}}}"#
            );
            let (said, reason) = read_one("pipfile-name", "Pipfile.lock", &text);
            assert!(said.is_empty(), "{name}");
            let at = format!("Pipfile.lock#default/{name}");
            assert_eq!(reason, one_not_told(&at), "{name}");
        }
    }

    #[test]
    fn a_pipfile_lock_pipenv_would_not_read_fails_and_another_spec_is_named_with_its_number() {
        let meta = format!(r#""_meta": {{"pipfile-spec": 6, "sources": [{PYPI}]}}"#);
        for text in [
            "not json".to_string(),
            "[]".to_string(),
            format!("\u{feff}\u{feff}{{{meta}}}"),
            r#"{"default": {}}"#.to_string(),
            format!(r#"{{"_meta": {{"sources": [{PYPI}]}}}}"#),
            format!(r#"{{"_meta": {{"pipfile-spec": "6", "sources": [{PYPI}]}}}}"#),
            r#"{"_meta": {"pipfile-spec": 6}}"#.to_string(),
            r#"{"_meta": {"pipfile-spec": 6, "sources": {}}}"#.to_string(),
            format!(r#"{{{meta}, "default": []}}"#),
            format!(r#"{{{meta}, "default": {{"widget": 1}}}}"#),
        ] {
            let (said, reason) = read_one("pipfile-failed", "Pipfile.lock", &text);
            assert!(said.is_empty(), "{text}");
            let failed = Some("could not be read: Pipfile.lock".to_string());
            assert_eq!(reason, failed, "{text}");
        }
        for n in [5, 7] {
            let text = format!(r#"{{"_meta": {{"pipfile-spec": {n}, "sources": []}}}}"#);
            let (said, reason) = read_one("pipfile-spec", "Pipfile.lock", &text);
            assert!(said.is_empty());
            let named = format!("not supported yet: Pipfile.lock version {n}");
            assert_eq!(reason.as_deref(), Some(named.as_str()));
        }
    }
}
