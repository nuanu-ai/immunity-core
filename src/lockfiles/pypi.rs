//! What ties an entry of a Python lockfile to PyPI's own package of a name and a version.
// No reader calls these yet: the change that adds the first Python reader removes this line.
#![allow(dead_code)]

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
/// `-`.
pub(super) fn pypi_name(name: &str) -> Option<String> {
    let edge = |c: Option<&u8>| c.is_some_and(u8::is_ascii_alphanumeric);
    let bytes = name.as_bytes();
    let valid = edge(bytes.first())
        && edge(bytes.last())
        && (bytes.iter()).all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c));
    valid.then(|| {
        let mut out = String::new();
        for c in name.chars() {
            match c {
                '.' | '_' | '-' if out.ends_with('-') => {}
                '.' | '_' | '-' => out.push('-'),
                c => out.push(c.to_ascii_lowercase()),
            }
        }
        out
    })
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
/// canonical form. A wheel is `{distribution}-{version}(-{build tag})?-{python tag}-{abi
/// tag}-{platform tag}.whl` ("Binary distribution format"), its build tag starting with a digit;
/// a source distribution is `{name}-{version}.tar.gz` ("Source distribution format"), or
/// `.zip` as older ones are, split at its last `-`, since a canonical version holds none.
/// Versions are compared as text: `1.0` is not `1.0.0` here, which only leaves an entry not told.
pub(super) fn pypi_file_name(file: &str, name: &str, version: &str) -> bool {
    let named = |distribution: &str| pypi_name(distribution).as_deref() == Some(name);
    if let Some(stem) = file.strip_suffix(".whl") {
        return match stem.split('-').collect::<Vec<_>>()[..] {
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
    stem.rsplit_once('-')
        .is_some_and(|(distribution, v)| v == version && named(distribution))
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
    fn pypi_s_simple_index_is_named_with_and_without_its_trailing_slash() {
        assert_eq!(
            PYPI_INDEX,
            ["https://pypi.org/simple", "https://pypi.org/simple/"]
        );
    }
}
