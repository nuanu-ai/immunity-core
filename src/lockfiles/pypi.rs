//! What ties an entry of a Python lockfile to PyPI's own package of a name and a version.

use super::{At, Dep, Parsed, Source};
use std::sync::OnceLock;

/// The addresses of PyPI's simple index.
pub(super) const PYPI_INDEX: [&str; 2] = ["https://pypi.org/simple", "https://pypi.org/simple/"];

/// Where PyPI keeps its files: a path of three parts of a hash, then the file's name.
const FILES: &str = "https://files.pythonhosted.org/packages/";

/// The canonical form of a public version, copied from the specification's own expression
/// (packaging.python.org, "Version specifiers", "Appendix: Parsing version strings with regular
/// expressions", `is_canonical`). It holds no local label, which PyPI does not allow.
const CANONICAL: &str = r"^([1-9][0-9]*!)?(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*((a|b|rc)(0|[1-9][0-9]*))?(\.post(0|[1-9][0-9]*))?(\.dev(0|[1-9][0-9]*))?$";

/// A project's name normalised, `None` for a name that is not valid (packaging.python.org,
/// "Names and normalization"; PEP 503). Valid is ASCII letters and digits, with `.`, `_` and
/// `-` between them, as `^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$` ignoring case. That
/// expression is written out here because a regular expression ignoring case under Unicode also
/// takes the Kelvin sign for `k`. Normalised is lowercase with each run of `.`, `-` and `_` one
/// `-` (`pypi_normalized`).
pub(super) fn pypi_name(name: &str) -> Option<String> {
    let edge = |c: Option<&u8>| c.is_some_and(u8::is_ascii_alphanumeric);
    let bytes = name.as_bytes();
    let valid = edge(bytes.first())
        && edge(bytes.last())
        && (bytes.iter()).all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c));
    valid.then(|| pypi_normalized(name))
}

/// A name normalised, valid or not: lowercase with each run of `.`, `-` and `_` one `-`. The
/// vulnerability data's names go through this alone (`osv::normalized`), so a record whose name
/// is not valid is kept rather than dropped. Its form never equals a valid name's, which holds
/// only `a-z`, `0-9` and `-` inside, so it matches no lockfile entry.
pub fn pypi_normalized(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        match c {
            '.' | '_' | '-' if out.ends_with('-') => {}
            '.' | '_' | '-' => out.push('-'),
            c => out.push(c.to_ascii_lowercase()),
        }
    }
    out
}

/// Whether `version` is a public version in canonical form, as `CANONICAL` says.
pub(super) fn canonical_version(version: &str) -> bool {
    static RULE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    let rule = RULE.get_or_init(|| regex::Regex::new(CANONICAL).ok());
    rule.as_ref().is_some_and(|rule| rule.is_match(version))
}

/// Whether `address` is PyPI's own file of the project `name`, normalised, at `version`, in
/// canonical form: `FILES`, two parts of two lowercase hex digits and one of sixty, then a file
/// name of letters, digits and `._!-` only, so no query, fragment or escape, that
/// `pypi_file_name` takes. PyPI serves nothing for another file name at a hash's path.
pub(super) fn pypi_file(address: &str, name: &str, version: &str) -> bool {
    let hex = |part: &str, n: usize| {
        part.len() == n && part.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    };
    let Some(path) = address.strip_prefix(FILES) else {
        return false;
    };
    let [a, b, hash, file] = path.split('/').collect::<Vec<_>>()[..] else {
        return false;
    };
    hex(a, 2)
        && hex(b, 2)
        && hex(hash, 60)
        && (file.bytes()).all(|c| c.is_ascii_alphanumeric() || b"._!-".contains(&c))
        && pypi_file_name(file, name, version)
}

/// Whether `file` is the name of a file of the project `name`, normalised, at `version`, in
/// canonical form. It checks both itself: a version not canonical is never a match, and a name
/// not normalised never equals the normalised name of a file's distribution. A wheel is
/// `{distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl` ("Binary
/// distribution format"), no part empty, its build tag starting with a digit; a source
/// distribution is `{name}-{version}.tar.gz` ("Source distribution format"), or `.zip` as older
/// ones are, split at its last `-`, since a canonical version holds none.
/// Versions are compared as text: `1.0` is not `1.0.0` here, which only leaves an entry not told.
pub(super) fn pypi_file_name(file: &str, name: &str, version: &str) -> bool {
    let named = |distribution: &str| pypi_name(distribution).as_deref() == Some(name);
    if !canonical_version(version) {
        return false;
    }
    if let Some(stem) = file.strip_suffix(".whl") {
        let parts: Vec<&str> = stem.split('-').collect();
        if parts.contains(&"") {
            return false;
        }
        return match parts[..] {
            [distribution, v, _, _, _] => named(distribution) && v.to_ascii_lowercase() == version,
            [distribution, v, build, _, _, _] => {
                build.starts_with(|c: char| c.is_ascii_digit())
                    && named(distribution)
                    && v.to_ascii_lowercase() == version
            }
            _ => false,
        };
    }
    let Some(stem) = (file.strip_suffix(".tar.gz")).or_else(|| file.strip_suffix(".zip")) else {
        return false;
    };
    // A segment of the name after its first that begins as a version does (a digit, or `v` or
    // `V` and a digit) lets the file name be read as another project at another version, as
    // `widget-1.0-2.zip` is `widget-1-0` at `2` and `widget` at `1.0-2`, so such a name is not
    // told; this only ever leaves an entry not told.
    let versionlike = |segment: &str| {
        let rest = segment.strip_prefix(['v', 'V']).unwrap_or(segment);
        rest.starts_with(|c: char| c.is_ascii_digit())
    };
    stem.rsplit_once('-').is_some_and(|(distribution, v)| {
        v == version && named(distribution) && !distribution.split('-').skip(1).any(versionlike)
    })
}

#[cfg(test)]
mod tests {
    use super::{PYPI_INDEX, canonical_version, pypi_file, pypi_file_name, pypi_name};

    #[test]
    fn a_project_name_is_valid_only_as_the_specification_says_and_normalises_to_one_form() {
        // The specification's own examples all name one project.
        for name in [
            "friendly-bard",
            "Friendly-Bard",
            "FRIENDLY-BARD",
            "friendly.bard",
            "friendly_bard",
            "friendly--bard",
            "FrIeNdLy-._.-bArD",
        ] {
            assert_eq!(pypi_name(name).as_deref(), Some("friendly-bard"), "{name}");
        }
        assert_eq!(pypi_name("W").as_deref(), Some("w"));
        // A name another tool could read as another project's is no name: an edge that is not
        // a letter or digit, a character outside ASCII, the Kelvin sign among them, a space.
        for name in [
            "",
            "-widget",
            "widget-",
            ".widget",
            "widget_",
            "wid get",
            "wid\u{212a}et",
            "widgét",
            "wid/get",
        ] {
            assert_eq!(pypi_name(name), None, "{name}");
        }
    }

    #[test]
    fn a_version_is_canonical_only_in_the_form_the_specification_gives_and_never_with_a_local_label()
     {
        for version in [
            "1.0",
            "1.0a1",
            "1.0rc1",
            "1.0.post1",
            "1.0.dev1",
            "1!2.0",
            "0",
            "2.0b3.post4.dev5",
        ] {
            assert!(canonical_version(version), "{version}");
        }
        // The specification's examples of forms that normalise to another, a local label, and
        // anything around a canonical version.
        for version in [
            "1.1RC1",
            "1.1.a1",
            "1.0a.1",
            "1.2-post2",
            "1.2.post",
            "1.0-r4",
            "1.2.dev",
            "v1.0",
            "1.0\n",
            "1.0+local",
            "01.0",
            "0!1.0",
            "x1.0",
            "",
        ] {
            assert!(!canonical_version(version), "{version:?}");
        }
    }

    /// Two parts of two hex digits and one of sixty, as PyPI's paths are.
    const HASH: &str = "3a/1b/0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab";

    fn address(file: &str) -> String {
        format!("https://files.pythonhosted.org/packages/{HASH}/{file}")
    }

    #[test]
    fn an_address_is_pypi_s_file_of_a_project_and_version_only_in_exactly_its_shape() {
        let wheel = "widget-1.2.0-py3-none-any.whl";
        assert!(pypi_file(&address(wheel), "widget", "1.2.0"));
        assert!(pypi_file(
            &address("widget-1.2.0.tar.gz"),
            "widget",
            "1.2.0"
        ));
        let long = &HASH[..HASH.len() - 1];
        for (case, at) in [
            ("another host", address(wheel).replace("files.", "mirror.")),
            ("http", address(wheel).replace("https:", "http:")),
            (
                "a host that only begins with it",
                address(wheel).replace(".org/", ".org.example.invalid/"),
            ),
            ("dot segments", address(&format!("x/../{wheel}"))),
            ("an escape", address(wheel).replace("-1.2.0", "%2d1.2.0")),
            (
                "an escaped slash",
                address("widget-1.2.0-py3-none-x%2fany.whl"),
            ),
            ("a query", address(&format!("{wheel}?x=.whl"))),
            ("a fragment", address(&format!("{wheel}#.whl"))),
            ("an uppercase digit", address(wheel).replace("3a/", "3A/")),
            ("a short first part", address(wheel).replace("3a/", "3/")),
            ("a short second part", address(wheel).replace("/1b/", "/1/")),
            ("a hash too short", address(wheel).replace(HASH, long)),
            (
                "a hash too long",
                address(wheel).replace(HASH, &format!("{HASH}8")),
            ),
            ("no file", address("")),
            ("another project", address("gadget-1.2.0-py3-none-any.whl")),
        ] {
            assert!(!pypi_file(&at, "widget", "1.2.0"), "{case}: {at}");
        }
    }

    #[test]
    fn a_file_name_is_of_a_project_and_version_only_when_its_own_parts_say_both() {
        for file in [
            "widget-1.2.0-py3-none-any.whl",
            "Widget-1.2.0-py3-none-any.whl",
            "widget-1.2.0-1-py3-none-any.whl",
            "widget-1.2.0-12x-cp312-cp312-macosx_11_0_arm64.whl",
            "widget-1.2.0.tar.gz",
            "widget-1.2.0.zip",
        ] {
            assert!(pypi_file_name(file, "widget", "1.2.0"), "{file}");
        }
        assert!(pypi_file_name(
            "my_widget-1.0RC1-py3-none-any.whl",
            "my-widget",
            "1.0rc1"
        ));
        assert!(pypi_file_name(
            "my_widget-1.0RC1-1-py3-none-any.whl",
            "my-widget",
            "1.0rc1"
        ));
        assert!(pypi_file_name("my.widget-1.0.tar.gz", "my-widget", "1.0"));
        assert!(pypi_file_name("my-widget-1.0.tar.gz", "my-widget", "1.0"));
        for (file, name, version) in [
            ("widget-1.2.0-none-any.whl", "widget", "1.2.0"),
            ("widget-1.2.0-1-x-py3-none-any.whl", "widget", "1.2.0"),
            ("widget-1.2.0-x-py3-none-any.whl", "widget", "1.2.0"),
            ("widget-1.2.0-py3-none-any.whl", "gadget", "1.2.0"),
            ("gadget-1.2.0-1-py3-none-any.whl", "widget", "1.2.0"),
            ("widget-1.2-1-py3-none-any.whl", "widget", "1.2.0"),
            ("widget_extra-1.2.0-py3-none-any.whl", "widget", "1.2.0"),
            ("widget-extra-1.2.0-py3-none-any.whl", "widget", "1.2.0"),
            ("widget-1.2.0-py3-none-any.whl", "widget", "1.2"),
            ("widget-1.2-py3-none-any.whl", "widget", "1.2.0"),
            ("widget-1.2.0.tar.gz", "widget", "1.2"),
            ("widget-1.2.tar.gz", "widget", "1.2.0"),
            ("widget-1.0RC1.tar.gz", "widget", "1.0rc1"),
            ("widget-extra-1.2.0.tar.gz", "widget", "1.2.0"),
            ("gadget-1.2.0.zip", "widget", "1.2.0"),
            ("widget-1.2.0.tar.bz2", "widget", "1.2.0"),
            ("widget-1.2.0.egg", "widget", "1.2.0"),
            ("widget1.2.0.tar.gz", "widget", "1.2.0"),
        ] {
            assert!(
                !pypi_file_name(file, name, version),
                "{file} {name} {version}"
            );
        }
    }

    #[test]
    fn a_file_name_proves_a_project_and_version_only_when_it_has_one_reading() {
        // Each sample that passes beside its nearest that must not: a wheel with an empty
        // part, a call with a version not canonical or a name not normalised, and an sdist
        // whose name could be split into another project at another version.
        for (file, name, version) in [
            ("widget-1.0-py3-none-any.whl", "widget", "1.0"),
            ("widget-1.0.tar.gz", "widget", "1.0"),
            ("my_widget-1.0-py3-none-any.whl", "my-widget", "1.0"),
            ("python-dateutil-2.8.2.tar.gz", "python-dateutil", "2.8.2"),
            ("3d-widget-1.0.tar.gz", "3d-widget", "1.0"),
            ("widget-vx-2.tar.gz", "widget-vx", "2"),
        ] {
            assert!(
                pypi_file_name(file, name, version),
                "{file} {name} {version}"
            );
        }
        for (file, name, version) in [
            ("widget-1.0---.whl", "widget", "1.0"),
            ("widget--py3-none-any.whl", "widget", ""),
            ("widget--py3-none-any.whl", "widget", "1.0"),
            ("widget-.tar.gz", "widget", ""),
            ("widget-1.0+local.tar.gz", "widget", "1.0+local"),
            ("my_widget-1.0-py3-none-any.whl", "My_Widget", "1.0"),
            ("widget-1.0-2.zip", "widget-1-0", "2"),
            ("widget-v1-2.tar.gz", "widget-v1", "2"),
            ("widget-V1-2.tar.gz", "widget-v1", "2"),
        ] {
            assert!(
                !pypi_file_name(file, name, version),
                "{file} {name} {version}"
            );
        }
    }

    #[test]
    fn pypi_s_simple_index_is_named_with_and_without_its_trailing_slash() {
        assert_eq!(
            PYPI_INDEX,
            ["https://pypi.org/simple", "https://pypi.org/simple/"]
        );
    }
}

/// What one entry of a Python lockfile in TOML is: its name, its version and its source; `None`
/// when the lockfile does not tell its package.
pub(super) type Told = Option<(String, Option<String>, Source)>;

/// What the Python lockfiles in TOML share: the file is parsed whole by the `toml` crate, `head`
/// checks the format's version and gives the key of the array of entries, and each entry is a
/// table with a string `name`, at whose line it is recorded. `head` gives `Err` with what the
/// reading is instead: a kind with no reader, or failed. `entry` tells from a table and its
/// name what the entry is (`Told`), and gives `None` when the tool would refuse it, which fails
/// the reading. An entry not told is keyed `L<line of its name>`. A file that is not TOML, an
/// array of entries that is not an array of tables, and an entry with no string `name` fail too;
/// no array is no entry.
pub(super) fn toml_lock(
    text: &str,
    head: impl Fn(&toml::de::DeTable) -> Result<&'static str, Parsed>,
    entry: impl Fn(&toml::de::DeTable, &str) -> Option<Told>,
) -> Parsed {
    use toml::de::{DeTable, DeValue};
    let Ok(lock) = DeTable::parse(text) else {
        return Parsed::Failed;
    };
    let lock = lock.get_ref();
    let key = match head(lock) {
        Ok(key) => key,
        Err(parsed) => return parsed,
    };
    let packages = match lock.get(key).map(|p| p.get_ref()) {
        None => &[][..],
        Some(DeValue::Array(packages)) => &packages[..],
        Some(_) => return Parsed::Failed,
    };
    // Where each line break is, to tell the line of a name from its offset.
    let breaks: Vec<usize> = text.match_indices('\n').map(|(i, _)| i).collect();
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    for package in packages {
        let Some(package) = package.get_ref().as_table() else {
            return Parsed::Failed;
        };
        let Some((at, Some(name))) =
            (package.get_key_value("name")).map(|(k, v)| (k.span().start, v.get_ref().as_str()))
        else {
            return Parsed::Failed;
        };
        let line = breaks.partition_point(|&b| b < at) + 1;
        match entry(package, name) {
            None => return Parsed::Failed,
            Some(Some((name, version, source))) => out.push(Dep {
                at: At::Line(line),
                name,
                version,
                source,
            }),
            Some(None) => unknown.push(format!("L{line}")),
        }
    }
    Parsed::Deps("PyPI", out, unknown)
}

/// A format's version written as a string: `Ok` when `known` takes it, the kind `<kind> version
/// <v>` with no reader for another of a version's shape, and a failed reading for none or any
/// other value.
pub(super) fn text_version(
    version: Option<&toml::Spanned<toml::de::DeValue>>,
    kind: &str,
    known: fn(&str) -> bool,
) -> Result<(), Parsed> {
    match version.map(|v| v.get_ref().as_str()) {
        Some(Some(v)) if known(v) => Ok(()),
        Some(Some(v)) if super::version_shape(v) => {
            Err(Parsed::NoReader(format!("{kind} version {v}")))
        }
        _ => Err(Parsed::Failed),
    }
}

/// Whether the array `files` of a `poetry.lock` or `pdm.lock` entry lists only PyPI's files of
/// the project `name`, normalised, at `version`: at least one, each a table with a string `file`
/// that `pypi_file_name` takes or, as PDM writes with static URLs, a string `url` that
/// `pypi_file` takes, never both. Anything else is not known to be PyPI's.
pub(super) fn pypi_files(files: Option<&toml::de::DeValue>, name: &str, version: &str) -> bool {
    let Some(files) = files.and_then(|f| f.as_array()) else {
        return false;
    };
    !files.is_empty()
        && files.iter().all(|row| {
            let text = |key: &str| row.get_ref().get(key).map(|v| v.get_ref().as_str());
            match (text("file"), text("url")) {
                (Some(Some(file)), None) => pypi_file_name(file, name, version),
                (None, Some(Some(url))) => pypi_file(url, name, version),
                _ => false,
            }
        })
}

#[cfg(test)]
mod toml_lock_tests {
    use super::pypi_files;

    #[test]
    fn an_entry_s_files_are_pypi_s_only_when_each_row_names_one_of_its_files_in_one_way() {
        let at = "https://files.pythonhosted.org/packages/3a/1b/0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab";
        let rows = |rows: &str| {
            let text = format!("files = [{rows}]");
            let table = toml::de::DeTable::parse(&text).unwrap().into_inner();
            pypi_files(table.get("files").map(|f| f.get_ref()), "widget", "1.2.0")
        };
        let wheel = "file = \"widget-1.2.0-py3-none-any.whl\"";
        let sdist = format!("url = \"{at}/widget-1.2.0.tar.gz\"");
        assert!(rows(&format!("{{{wheel}}}, {{{sdist}}}")));
        for (case, text) in [
            ("no row", String::new()),
            (
                "a row of another version",
                "{file = \"widget-1.2.1.tar.gz\"}".to_string(),
            ),
            (
                "one row of two",
                format!("{{{wheel}}}, {{file = \"gadget-1.2.0.tar.gz\"}}"),
            ),
            (
                "an address elsewhere",
                "{url = \"https://example.invalid/widget-1.2.0.tar.gz\"}".to_string(),
            ),
            ("both keys", format!("{{{wheel}, {sdist}}}")),
            ("neither key", "{hash = \"sha256:00\"}".to_string()),
            ("a file not a string", "{file = 1}".to_string()),
            ("a row not a table", "\"widget-1.2.0.tar.gz\"".to_string()),
        ] {
            assert!(!rows(&text), "{case}");
        }
        assert!(!pypi_files(None, "widget", "1.2.0"));
    }
}
