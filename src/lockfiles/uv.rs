//! The reader of `uv.lock`.

use super::pypi::{PYPI_INDEX, pypi_file, pypi_name};
use super::{At, Dep, Parsed, Source};
use toml::de::{DeTable, DeValue};

/// The kinds of `source` uv reads (`SourceWire` in uv's `crates/uv-lock/src/lock/mod.rs`).
const SOURCES: [&str; 7] = [
    "registry",
    "git",
    "url",
    "path",
    "directory",
    "editable",
    "virtual",
];

pub(super) const READ: Option<super::Reader> = Some(|text, _| uv(text));

/// `uv.lock` of `version = 1`, with any `revision`, as uv's `crates/uv-lock/src/lock/mod.rs`
/// reads it: every table of the array `package`, which uv also takes as `distribution`, at the
/// line of its name. uv refuses any other `version`, and such a file is named as a kind with no
/// reader, `uv.lock version <n>`. An entry is PyPI's package only from the source `registry`
/// at PyPI's index, with a version, at least one file, and every `sdist` and wheel at an
/// address `pypi_file` takes. Another index's address is another registry, an index on disk a
/// path; `git` is git, `url` another registry, and `path`, `directory`, `editable` and
/// `virtual`, the project itself and its workspace members among them, are paths. A file that
/// is not TOML, a key given twice, a `version` that is not a whole number, both `package` and
/// `distribution`, and an entry with no name, no source or a value of another type than uv
/// reads fail the reading. An entry from PyPI's index whose files do not prove its name and
/// version, one whose `source` names no kind or two, and a name not written normalised, as uv
/// writes it, are left not told, keyed `L<line>`.
fn uv(text: &str) -> Parsed {
    let Ok(lock) = DeTable::parse(text) else {
        return Parsed::Failed;
    };
    let lock = lock.get_ref();
    match lock.get("version").map(|v| v.get_ref()) {
        Some(DeValue::Integer(n)) => match u64::from_str_radix(n.as_str(), n.radix()) {
            Ok(1) => {}
            Ok(n) => return Parsed::NoReader(format!("uv.lock version {n}")),
            Err(_) => return Parsed::Failed,
        },
        _ => return Parsed::Failed,
    }
    let packages = match (lock.get("package"), lock.get("distribution")) {
        (None, None) => &[][..],
        (Some(p), None) | (None, Some(p)) => match p.get_ref() {
            DeValue::Array(packages) => &packages[..],
            _ => return Parsed::Failed,
        },
        (Some(_), Some(_)) => return Parsed::Failed,
    };
    // Where each line break is, to tell the line of a name from its offset.
    let breaks: Vec<usize> = text.match_indices('\n').map(|(i, _)| i).collect();
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    for package in packages {
        let Some((at, told)) = package.get_ref().as_table().and_then(uv_entry) else {
            return Parsed::Failed;
        };
        let line = breaks.partition_point(|&b| b < at) + 1;
        match told {
            Some((name, version, source)) => out.push(Dep {
                at: At::Line(line),
                name: name.to_string(),
                version: version.map(str::to_string),
                source,
            }),
            None => unknown.push(format!("L{line}")),
        }
    }
    Parsed::Deps("PyPI", out, unknown)
}

/// An entry's name, version and source as `uv` reads them.
type Told<'a> = Option<(&'a str, Option<&'a str>, Source)>;

/// One `[[package]]`: the offset of its name and what it is, `None` inside when the lockfile
/// does not tell its package; `None` when uv would refuse it.
fn uv_entry<'a>(package: &'a DeTable) -> Option<(usize, Told<'a>)> {
    let (key, name) = package.get_key_value("name")?;
    let name = name.get_ref().as_str()?;
    let version = match package.get("version") {
        None => None,
        Some(v) => Some(v.get_ref().as_str()?),
    };
    let source = package.get("source")?.get_ref().as_table()?;
    // Each file's address, `None` for a file with none.
    let mut files = Vec::new();
    if let Some(sdist) = package.get("sdist") {
        files.push(address(sdist.get_ref())?);
    }
    if let Some(wheels) = package.get("wheels") {
        for wheel in wheels.get_ref().as_array()? {
            files.push(address(wheel.get_ref())?);
        }
    }
    let kinds: Vec<_> = (source.iter())
        .filter(|(k, _)| SOURCES.contains(&k.get_ref().as_ref()))
        .collect();
    let at = key.span().start;
    let [(kind, value)] = kinds[..] else {
        return Some((at, None));
    };
    let value = value.get_ref().as_str()?;
    if pypi_name(name).as_deref() != Some(name) {
        return Some((at, None));
    }
    let from = match kind.get_ref().as_ref() {
        "registry" if PYPI_INDEX.contains(&value) => {
            let proved = |v| {
                !files.is_empty()
                    && files
                        .iter()
                        .all(|f| f.is_some_and(|f| pypi_file(f, name, v)))
            };
            if !version.is_some_and(proved) {
                return Some((at, None));
            }
            Source::Registry
        }
        "registry" if value.contains("://") => Source::OtherRegistry,
        "git" => Source::Git,
        "url" => Source::OtherRegistry,
        _ => Source::Path,
    };
    Some((at, Some((name, version, from))))
}

/// The address of an `sdist` or a wheel, `None` inside for a file with none; `None` when uv
/// would refuse it.
fn address<'a>(file: &'a DeValue) -> Option<Option<&'a str>> {
    match file.as_table()?.get("url") {
        None => Some(None),
        Some(url) => url.get_ref().as_str().map(Some),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::Dir;
    use super::super::{At, Parsed};
    use super::uv;

    /// What a reader gives, one line an entry: `<ecosystem>/<name> <source> <version> :<line>`,
    /// `not told #<key>`, `no reader: <kind>` or `failed`.
    pub(in super::super) fn told(parsed: Parsed) -> Vec<String> {
        match parsed {
            Parsed::Failed => vec!["failed".to_string()],
            Parsed::NoReader(kind) => vec![format!("no reader: {kind}")],
            Parsed::Deps(ecosystem, deps, unknown) => (deps.iter())
                .map(|d| {
                    let at = match &d.at {
                        At::Line(n) => n.to_string(),
                        At::Key(key) => key.clone(),
                    };
                    let version = d.version.as_deref().unwrap_or("-");
                    format!("{ecosystem}/{} {:?} {version} :{at}", d.name, d.source)
                })
                .chain(unknown.iter().map(|key| format!("not told #{key}")))
                .collect(),
        }
    }

    /// The start of an invented `uv.lock`; the name of the package after it is on line 6.
    const HEAD: &str = "version = 1\nrevision = 3\nrequires-python = \">=3.12\"\n\n[[package]]\n";

    /// An entry of `widget` 1.2.0 from PyPI as uv writes it.
    const WIDGET: &str = r#"name = "widget"
version = "1.2.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/3a/1b/0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab/widget-1.2.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 2048, upload-time = "2026-01-02T03:04:05Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/4c/2d/0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab/widget-1.2.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1024, upload-time = "2026-01-02T03:04:05Z" },
]
"#;

    /// A `uv.lock` of one package from PyPI, for the tests of all kinds.
    pub(in super::super) fn sample() -> String {
        format!("{HEAD}{WIDGET}")
    }

    /// The one line `told` gives for a `uv.lock` of `HEAD` and `entry`.
    fn one(entry: &str) -> String {
        let said = told(uv(&format!("{HEAD}{entry}")));
        assert_eq!(said.len(), 1, "{entry}: {said:?}");
        said[0].clone()
    }

    /// `WIDGET` with its `source` line replaced.
    fn widget_from(source: &str) -> String {
        WIDGET.replace(
            "source = { registry = \"https://pypi.org/simple\" }",
            &format!("source = {source}"),
        )
    }

    #[test]
    fn a_uv_entry_is_pypi_s_package_only_from_pypi_s_index_with_every_file_proving_name_and_version()
     {
        let sdist = WIDGET.lines().nth(3).unwrap();
        let wheel = "    { url = \"https://files.pythonhosted.org/packages/4c/2d";
        let registry = "PyPI/widget Registry 1.2.0 :6";
        for (case, entry) in [
            ("as uv writes it", WIDGET.to_string()),
            (
                "the index with its slash",
                widget_from("{ registry = \"https://pypi.org/simple/\" }"),
            ),
            ("wheels only", WIDGET.replace(sdist, "")),
            ("an sdist only", WIDGET.replace("wheels = [", "x = [")),
        ] {
            assert_eq!(one(&entry), registry, "{case}");
        }
        // No false calm: each of these says less than PyPI's file of `widget` 1.2.0.
        for (case, entry) in [
            ("no version", WIDGET.replace("version = \"1.2.0\"\n", "")),
            (
                "no file",
                WIDGET.replace(sdist, "").replace("wheels = [", "x = ["),
            ),
            (
                "a wheel of another version",
                WIDGET.replace("widget-1.2.0-py3", "widget-1.1.0-py3"),
            ),
            (
                "an sdist of another package",
                WIDGET.replace("widget-1.2.0.tar.gz", "gadget-1.2.0.tar.gz"),
            ),
            (
                "a wheel on another host",
                WIDGET.replace(
                    wheel,
                    "    { url = \"https://mirror.example.invalid/packages/4c/2d",
                ),
            ),
            (
                "an sdist with no address",
                WIDGET.replace(sdist, "sdist = { hash = \"sha256:11\" }"),
            ),
            (
                "a wheel by path",
                WIDGET.replace(
                    wheel,
                    "    { path = \"https://files.pythonhosted.org/packages/4c/2d",
                ),
            ),
            (
                "a name not normalised",
                WIDGET.replace("name = \"widget\"", "name = \"Widget\""),
            ),
            (
                "two kinds of source",
                widget_from(
                    "{ registry = \"https://pypi.org/simple\", url = \"https://example.invalid/widget-1.2.0.tar.gz\" }",
                ),
            ),
            (
                "no kind of source",
                widget_from("{ subdirectory = \"widget\" }"),
            ),
        ] {
            assert_eq!(one(&entry), "not told #L6", "{case}");
        }
    }

    #[test]
    fn a_uv_entry_from_elsewhere_is_recorded_with_where_it_comes_from() {
        for (source, said) in [
            (
                "{ registry = \"https://pypi.example.invalid/simple\" }",
                "OtherRegistry 1.2.0",
            ),
            ("{ registry = \"../index\" }", "Path 1.2.0"),
            (
                "{ git = \"https://example.invalid/widget.git?rev=main#0123456789abcdef0123456789abcdef01234567\" }",
                "Git 1.2.0",
            ),
            (
                "{ url = \"https://example.invalid/widget-1.2.0.tar.gz\", subdirectory = \"py\" }",
                "OtherRegistry 1.2.0",
            ),
            (
                "{ path = \"dist/widget-1.2.0-py3-none-any.whl\" }",
                "Path 1.2.0",
            ),
            ("{ directory = \"../widget\" }", "Path 1.2.0"),
            ("{ editable = \".\" }", "Path 1.2.0"),
            ("{ virtual = \"packages/widget\" }", "Path 1.2.0"),
        ] {
            assert_eq!(
                one(&widget_from(source)),
                format!("PyPI/widget {said} :6"),
                "{source}"
            );
        }
        // The project itself, its version dynamic, and a member whose name is not normalised.
        let project = "name = \"shop\"\nsource = { virtual = \".\" }\n";
        assert_eq!(one(project), "PyPI/shop Path - :6");
        let member = "name = \"Shop_Tool\"\nsource = { editable = \"tool\" }\n";
        assert_eq!(one(member), "not told #L6");
    }

    #[test]
    fn a_uv_lock_uv_would_refuse_is_a_failed_reading_never_one_with_fewer_entries() {
        let entry = |text: &str| format!("{HEAD}{text}");
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
                "no version of the format",
                entry(WIDGET).replace("version = 1\n", ""),
            ),
            (
                "a version of the format as text",
                entry(WIDGET).replace("version = 1\n", "version = \"1\"\n"),
            ),
            (
                "a negative version of the format",
                entry(WIDGET).replace("version = 1\n", "version = -1\n"),
            ),
            (
                "package not an array",
                "version = 1\npackage = 1\n".to_string(),
            ),
            (
                "an entry not a table",
                "version = 1\npackage = [1]\n".to_string(),
            ),
            (
                "package and distribution",
                format!("{}\n[[distribution]]\n{WIDGET}", entry(WIDGET)),
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
                "no source",
                entry(&widget_from("1").replace("source = 1\n", "")),
            ),
            ("a source not a table", entry(&widget_from("\"registry\""))),
            (
                "a source's value not text",
                entry(&widget_from("{ git = 1 }")),
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
            (
                "an address not text",
                entry(&WIDGET.replace("sdist = { url = \"", "sdist = { url = 1, x = \"")),
            ),
        ] {
            assert_eq!(told(uv(&text)), ["failed"], "{case}");
        }
    }

    #[test]
    fn a_uv_lock_is_read_at_version_1_with_any_revision_and_any_other_version_is_named() {
        let text = format!("{HEAD}{WIDGET}");
        let revision = text.replace("revision = 3", "revision = 99");
        assert_eq!(told(uv(&revision)), ["PyPI/widget Registry 1.2.0 :6"]);
        let distribution = text.replace("[[package]]", "[[distribution]]");
        assert_eq!(told(uv(&distribution)), ["PyPI/widget Registry 1.2.0 :6"]);
        assert!(told(uv("version = 1\n")).is_empty());
        for (version, kind) in [("2", "2"), ("0", "0"), ("0x10", "16")] {
            let text = text.replace("version = 1\n", &format!("version = {version}\n"));
            assert_eq!(
                told(uv(&text)),
                [format!("no reader: uv.lock version {kind}")]
            );
        }
    }

    #[test]
    fn a_uv_lock_names_each_package_once_by_source_and_says_which_entries_cannot_be_told() {
        // A package from PyPI and the same name from git are two components; an entry not told
        // is named by its line and leaves the reading partial.
        let git = widget_from(
            "{ git = \"https://example.invalid/widget.git#0123456789abcdef0123456789abcdef01234567\" }",
        );
        let text = format!(
            "{HEAD}{WIDGET}\n[[package]]\n{git}\n[[package]]\n{}",
            WIDGET.replace("widget-1.2.0-py3", "widget-1.1.0-py3")
        );
        let dir = Dir::new("uv", &[("uv.lock", &text)]);
        let (o, said) = dir.read();
        let at = "dev/shop/uv.lock";
        assert_eq!(
            said,
            [
                format!("PyPI/widget|part_of|checkout|{at}:6"),
                format!("PyPI/widget|has_version|1.2.0|{at}:6"),
                format!("PyPI/widget (git)|part_of|checkout|{at}:15"),
                format!("PyPI/widget (git)|has_version|1.2.0|{at}:15"),
            ]
        );
        assert_eq!(
            o.reason.as_deref(),
            Some("the package of 1 entry cannot be told: dev/shop/uv.lock#L24")
        );
    }
}
