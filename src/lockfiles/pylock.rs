//! The reader of `pylock.toml` and `pylock.<name>.toml` (PEP 751).

use super::pypi::{PYPI_INDEX, Told, pypi_file, pypi_name, text_version, toml_lock};
use super::{Parsed, Source};
use toml::de::{DeTable, DeValue};

pub(super) const READ: Option<super::Reader> = Some(|text, _| pylock(text));

/// `pylock.toml` of `lock-version = "1.0"`, as packaging.python.org's "pylock.toml
/// specification" gives it: every table of the array `packages`, at the line of its name. Any
/// other `lock-version` is named as a kind with no reader, `pylock.toml version <v>`. An entry
/// is PyPI's package only when its `index`, where given, is PyPI's, it has a `version`, and it
/// lists at least one `sdist` or wheel, each with no `path`, an address `pypi_file` takes and a
/// `name`, where given, that is the address's file name, since an installer takes `path` before
/// `url` and believes `name` over the address. An `index` that is not PyPI's makes it another
/// registry's; `vcs` is git, `directory` a path, and `archive` a path with its `path` and
/// another registry's without. A file that is not TOML, a `lock-version` that is not text,
/// no array `packages`, an entry with no name, a value of another type than the specification
/// gives, and an entry of two kinds of source, which an installer refuses, fail the reading. An
/// entry of files that do not prove its name and version, or with no `version`, and a name not
/// written normalised, as the specification requires, are left not told, keyed `L<line>`.
fn pylock(text: &str) -> Parsed {
    let head = |lock: &DeTable| {
        text_version(lock.get("lock-version"), "pylock.toml", |v| v == "1.0")?;
        match lock.get("packages").map(|p| p.get_ref()) {
            Some(DeValue::Array(_)) => Ok("packages"),
            _ => Err(Parsed::Failed),
        }
    };
    toml_lock(text, head, pylock_entry)
}

/// One `[[packages]]` with its name: what it is, `None` inside when the lockfile does not tell
/// its package; `None` when it is not of the specification's shape.
fn pylock_entry(package: &DeTable, name: &str) -> Option<Told> {
    let text = |key: &str| match package.get(key) {
        None => Some(None),
        Some(v) => v.get_ref().as_str().map(Some),
    };
    let table = |key: &str| match package.get(key) {
        None => Some(None),
        Some(v) => v.get_ref().as_table().map(Some),
    };
    let (version, index) = (text("version")?, text("index")?);
    let (vcs, directory, archive) = (table("vcs")?, table("directory")?, table("archive")?);
    let mut files: Vec<&DeTable> = table("sdist")?.into_iter().collect();
    if let Some(wheels) = package.get("wheels") {
        for wheel in wheels.get_ref().as_array()? {
            files.push(wheel.get_ref().as_table()?);
        }
    }
    let wheels_or_sdist = package.contains_key("sdist") || package.contains_key("wheels");
    let kinds = [
        vcs.is_some(),
        directory.is_some(),
        archive.is_some(),
        wheels_or_sdist,
    ];
    if kinds.iter().filter(|k| **k).count() > 1 {
        return None;
    }
    if pypi_name(name).as_deref() != Some(name) {
        return Some(None);
    }
    let from = match archive {
        _ if vcs.is_some() => Source::Git,
        _ if directory.is_some() => Source::Path,
        Some(archive) if archive.contains_key("path") => Source::Path,
        Some(_) => Source::OtherRegistry,
        None if index.is_some_and(|i| !PYPI_INDEX.contains(&i)) => Source::OtherRegistry,
        None => {
            let proved = |v| !files.is_empty() && files.iter().all(|f| pypi_s(f, name, v));
            if !version.is_some_and(proved) {
                return Some(None);
            }
            Source::Registry
        }
    };
    Some(Some((name.to_string(), version.map(str::to_string), from)))
}

/// Whether an `sdist` or a wheel is PyPI's file of `name` at `version`: no `path`, an address
/// `pypi_file` takes, and a `name`, where given, that is the address's file name.
fn pypi_s(file: &DeTable, name: &str, version: &str) -> bool {
    let url = file.get("url").and_then(|u| u.get_ref().as_str());
    let named = |file_name: Option<&str>| {
        (file.get("name")).is_none_or(|n| n.get_ref().as_str() == file_name)
    };
    !file.contains_key("path")
        && url.is_some_and(|u| pypi_file(u, name, version) && named(u.rsplit('/').next()))
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::uv::tests::told;
    use super::pylock;

    /// The start of an invented `pylock.toml`; the name of the package after it is on line 6.
    const HEAD: &str = "lock-version = \"1.0\"\ncreated-by = \"invented-tool\"\nrequires-python = \">=3.12\"\n\n[[packages]]\n";

    /// An entry of `widget` 1.2.0 from PyPI as the specification's example writes one.
    const WIDGET: &str = r#"name = "widget"
version = "1.2.0"
index = "https://pypi.org/simple"
sdist = { url = "https://files.pythonhosted.org/packages/3a/1b/0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab/widget-1.2.0.tar.gz", hashes = { sha256 = "1111111111111111111111111111111111111111111111111111111111111111" } }
wheels = [
    { url = "https://files.pythonhosted.org/packages/4c/2d/0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab/widget-1.2.0-py3-none-any.whl", hashes = { sha256 = "2222222222222222222222222222222222222222222222222222222222222222" } },
]
"#;

    /// A `pylock.toml` of one package from PyPI, for the tests of all kinds.
    pub(in super::super) fn sample() -> String {
        format!("{HEAD}{WIDGET}")
    }

    /// The one line `told` gives for a `pylock.toml` of `HEAD` and `entry`.
    fn one(entry: &str) -> String {
        let said = told(pylock(&format!("{HEAD}{entry}")));
        assert_eq!(said.len(), 1, "{entry}: {said:?}");
        said[0].clone()
    }

    /// `name`, `version` and a source of an entry that lists no file.
    fn elsewhere(source: &str) -> String {
        format!("name = \"widget\"\nversion = \"1.2.0\"\n{source}\n")
    }

    #[test]
    fn a_pylock_entry_is_pypi_s_package_only_when_every_file_proves_name_and_version() {
        let sdist = WIDGET.lines().nth(3).unwrap();
        let wheel = "    { url = \"https://files.pythonhosted.org/packages/4c/2d";
        let index = "index = \"https://pypi.org/simple\"\n";
        let registry = "PyPI/widget Registry 1.2.0 :6";
        for (case, entry) in [
            ("as the example writes it", WIDGET.to_string()),
            ("no index", WIDGET.replace(index, "")),
            ("the index with its slash", WIDGET.replace("simple\"", "simple/\"")),
            ("wheels only", WIDGET.replace(sdist, "")),
            ("an sdist only", WIDGET.replace("wheels = [", "x = [")),
            ("a wheel's name its address's", WIDGET.replace(wheel, "    { name = \"widget-1.2.0-py3-none-any.whl\", url = \"https://files.pythonhosted.org/packages/4c/2d")),
        ] {
            assert_eq!(one(&entry), registry, "{case}");
        }
        // No false calm: each of these says less than PyPI's file of `widget` 1.2.0.
        for (case, entry) in [
            ("no version", WIDGET.replace("version = \"1.2.0\"\n", "")),
            ("no file", WIDGET.replace(sdist, "").replace("wheels = [", "x = [")),
            ("a wheel of another version", WIDGET.replace("widget-1.2.0-py3", "widget-1.1.0-py3")),
            ("an sdist on another host", WIDGET.replace("files.pythonhosted.org/packages/3a", "mirror.example.invalid/packages/3a")),
            ("a wheel with a path", WIDGET.replace(wheel, "    { path = \"dist/widget-1.2.0-py3-none-any.whl\", url = \"https://files.pythonhosted.org/packages/4c/2d")),
            ("a wheel with no address", WIDGET.replace(wheel, "    { x = \"https://files.pythonhosted.org/packages/4c/2d")),
            ("a wheel's name another file's", WIDGET.replace(wheel, "    { name = \"widget-1.2.0-cp312-abi3-macosx_11_0_arm64.whl\", url = \"https://files.pythonhosted.org/packages/4c/2d")),
            ("a name not normalised", WIDGET.replace("name = \"widget\"", "name = \"Widget\"")),
        ] {
            assert_eq!(one(&entry), "not told #L6", "{case}");
        }
    }

    #[test]
    fn a_pylock_entry_from_elsewhere_is_recorded_with_where_it_comes_from() {
        let other = "index = \"https://pypi.example.invalid/simple\"\n";
        let index = "index = \"https://pypi.org/simple\"\n";
        assert_eq!(
            one(&WIDGET.replace(index, other)),
            "PyPI/widget OtherRegistry 1.2.0 :6"
        );
        for (source, said) in [
            (
                "vcs = { type = \"git\", url = \"https://example.invalid/widget.git\", commit-id = \"0123456789abcdef0123456789abcdef01234567\" }",
                "Git",
            ),
            (
                "directory = { path = \"packages/widget\", editable = true }",
                "Path",
            ),
            (
                "archive = { url = \"https://example.invalid/widget-1.2.0.tar.gz\", hashes = { sha256 = \"11\" } }",
                "OtherRegistry",
            ),
            (
                "archive = { path = \"dist/widget-1.2.0.tar.gz\", hashes = { sha256 = \"11\" } }",
                "Path",
            ),
        ] {
            assert_eq!(
                one(&elsewhere(source)),
                format!("PyPI/widget {said} 1.2.0 :6"),
                "{source}"
            );
        }
        let project = "name = \"shop\"\ndirectory = { path = \".\", editable = true }\n";
        assert_eq!(one(project), "PyPI/shop Path - :6");
        let member = "name = \"Shop_Tool\"\ndirectory = { path = \"tool\" }\n";
        assert_eq!(one(member), "not told #L6");
    }

    #[test]
    fn a_pylock_not_of_the_specification_s_shape_is_a_failed_reading_never_one_with_fewer_entries()
    {
        let entry = |text: &str| format!("{HEAD}{text}");
        let vcs = "vcs = { type = \"git\", url = \"https://example.invalid/widget.git\", commit-id = \"0123456789abcdef0123456789abcdef01234567\" }\n";
        let archive =
            "archive = { path = \"dist/widget-1.2.0.tar.gz\", hashes = { sha256 = \"11\" } }\n";
        for (case, text) in [
            ("not TOML", entry(&WIDGET.replace("]\n", ""))),
            (
                "a key twice",
                entry(&WIDGET.replace(
                    "version = \"1.2.0\"\n",
                    "version = \"1.2.0\"\nversion = \"1.2.0\"\n",
                )),
            ),
            (
                "no lock-version",
                entry(WIDGET).replace("lock-version = \"1.0\"\n", ""),
            ),
            (
                "a lock-version not text",
                entry(WIDGET).replace("\"1.0\"", "1.0"),
            ),
            (
                "a lock-version of no shape",
                entry(WIDGET).replace("\"1.0\"", "\"1 0\""),
            ),
            (
                "no packages",
                "lock-version = \"1.0\"\ncreated-by = \"x\"\n".to_string(),
            ),
            (
                "packages not an array",
                "lock-version = \"1.0\"\npackages = 1\n".to_string(),
            ),
            (
                "an entry not a table",
                "lock-version = \"1.0\"\npackages = [1]\n".to_string(),
            ),
            ("no name", entry(&WIDGET.replace("name = \"widget\"\n", ""))),
            (
                "a name not text",
                entry(&WIDGET.replace("name = \"widget\"", "name = 1")),
            ),
            (
                "a version not text",
                entry(&WIDGET.replace("version = \"1.2.0\"", "version = 1")),
            ),
            (
                "an index not text",
                entry(&WIDGET.replace("index = \"https://pypi.org/simple\"", "index = 1")),
            ),
            (
                "an sdist not a table",
                entry(&WIDGET.replace("sdist = {", "sdist = \"x\"\ny = {")),
            ),
            (
                "wheels not an array",
                entry(&WIDGET.replace("wheels = [", "wheels = 1\nx = [")),
            ),
            (
                "a wheel not a table",
                entry(&WIDGET.replace("wheels = [", "wheels = [1,")),
            ),
            ("a vcs not a table", entry(&elsewhere("vcs = \"git\""))),
            (
                "a directory not a table",
                entry(&elsewhere("directory = \".\"")),
            ),
            (
                "an archive not a table",
                entry(&elsewhere("archive = \"x\"")),
            ),
            (
                "vcs and directory",
                entry(&elsewhere(&format!("{vcs}directory = {{ path = \".\" }}"))),
            ),
            ("an archive and files", entry(&format!("{archive}{WIDGET}"))),
            (
                "vcs and wheels",
                entry(&format!(
                    "{vcs}{}",
                    WIDGET.replace(WIDGET.lines().nth(3).unwrap(), "")
                )),
            ),
        ] {
            assert_eq!(told(pylock(&text)), ["failed"], "{case}");
        }
    }

    #[test]
    fn a_pylock_is_read_at_lock_version_1_0_and_any_other_is_named() {
        assert!(
            told(pylock(
                "lock-version = \"1.0\"\ncreated-by = \"x\"\npackages = []\n"
            ))
            .is_empty()
        );
        let text = format!("{HEAD}{WIDGET}");
        for version in ["1.1", "2.0", "0.9"] {
            let text = text.replace("\"1.0\"", &format!("\"{version}\""));
            assert_eq!(
                told(pylock(&text)),
                [format!("no reader: pylock.toml version {version}")]
            );
        }
    }
}
