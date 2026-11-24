//! The reader of `requirements.txt`: a port of pip's own parser, `src/pip/_internal/req/req_file.py`
//! of github.com/pypa/pip at commit 5b4d4510, with the options it takes from `cli/cmdoptions.py`
//! and the split of a requirement from `req/constructors.py`. pip defines the format by that
//! parser, so this is our own code: the crate uv uses, `uv-requirements-txt`, is an internal part
//! of uv with 16 direct dependencies, and the crate `requirements` knows no `--hash`, no marker
//! and no joined line. It is tested on pip's own test file, `tests/requirements/test_req_file.py`.
//!
//! The lines, comments, joins, options and their values are pip's. Where pip reads what this
//! reader cannot know, or where Python and Rust could split a text differently, it refuses:
//! - a coding declaration in the first two lines naming anything but UTF-8, which pip decodes by;
//! - a character Python takes for whitespace or a line break beyond space, tab, `\n` and `\r`
//!   (`\v`, `\f`, `\x1c` to `\x1f`, U+0085, U+00A0, U+2028, U+2029 and the Unicode spaces), since
//!   `str.splitlines`, `str.strip` and `\s` take them and Rust's own rules do not all agree;
//! - an option pip does not know, a value its option refuses, a quote not closed, and a
//!   requirement that is not `name[extras] spec, spec` (markers after `;` are not checked).
//!
//! What would replace this reader: a tested implementation of pip's format that refuses what it
//! does not understand.

use super::pypi::{PYPI_INDEX, canonical_version, pypi_name};
use super::{At, Dep, Parsed, Source};
use std::collections::VecDeque;

pub(super) const READ: Option<super::Reader> = Some(|text, _| requirements(text));

/// What an option does, of those pip takes in a requirements file (`SUPPORTED_OPTIONS` and
/// `SUPPORTED_OPTIONS_REQ`, defined in `cli/cmdoptions.py`).
#[derive(Clone, Copy, PartialEq)]
enum Opt {
    Index,
    /// Packages may come from another place than the index: an extra index, links.
    Elsewhere,
    /// `--no-index`: a flag, and packages come from links only.
    NoIndex,
    Requirement,
    Constraint,
    Editable,
    /// A list of names, `:all:` or `:none:`, which pip refuses when it begins with `-`.
    Names,
    /// `--use-feature`, one of `FEATURES`.
    Feature,
    /// `algorithm:digest`, the algorithm one of `STRONG_HASHES`.
    Hash,
    /// `KEY=VALUE`.
    Config,
    NoRequireHashes,
    /// An option that changes no package and takes no value.
    Flag,
    /// An option that changes no package and takes any value.
    Value,
}

/// The names of each option, as `optparse` is given them; only the flags take no value.
const OPTIONS: [(&str, Opt); 13] = [
    ("-i --index-url --pypi-url", Opt::Index),
    ("--extra-index-url -f --find-links", Opt::Elsewhere),
    ("--no-index", Opt::NoIndex),
    ("-c --constraint", Opt::Constraint),
    ("-r --requirement", Opt::Requirement),
    ("-e --editable", Opt::Editable),
    (
        "--no-binary --only-binary --all-releases --only-final",
        Opt::Names,
    ),
    ("--prefer-binary --require-hashes --pre", Opt::Flag),
    ("--no-require-hashes", Opt::NoRequireHashes),
    ("--trusted-host", Opt::Value),
    ("--use-feature", Opt::Feature),
    ("--hash", Opt::Hash),
    ("-C --config-settings", Opt::Config),
];
const FEATURES: &str = "fast-deps inprocess-build-deps venv-isolation truststore \
                        no-binary-enable-wheel-cache build-constraint";
const STRONG_HASHES: [&str; 3] = ["sha256", "sha384", "sha512"];
/// The key of what the file leaves out when it is not a lock: what pip resolves anew.
const UNLISTED: &str = "dependencies it does not list";

/// What the options of one line say.
#[derive(Default)]
struct Opts {
    index: Vec<String>,
    elsewhere: bool,
    include: Option<&'static str>,
    editable: bool,
    hashes: usize,
    no_require_hashes: bool,
}

/// `requirements.txt`. It is a lock only in pip's hash-checking mode with every requirement
/// pinned: each requirement line is `name==version` with a canonical version and a `--hash`, and
/// no line says `--no-require-hashes`. Then each is PyPI's package at that version, unless an
/// option line names an index that is not PyPI's, an extra index, `-f` or `--no-index`; then
/// each is from another registry. Otherwise every pinned line is still recorded, and the file is
/// read in part: the dependencies it does not list are not told. Not told too, each by its line:
/// a requirement not pinned, `-e`, an address or a path with no name, a line holding an
/// environment variable, which pip expands and this reader does not, and `-r` or `-c`, whose file
/// is not opened. `name @ address` is git for `git+`, a path for `file:` or no `://`, and
/// another registry otherwise. Extras are dropped and markers decide nothing. A file pip would
/// refuse fails the reading, as the head of this file says.
fn requirements(text: &str) -> Parsed {
    read(text).map_or(Parsed::Failed, |(deps, unknown)| {
        Parsed::Deps("PyPI", deps, unknown)
    })
}

fn read(text: &str) -> Option<(Vec<Dep>, Vec<String>)> {
    // pip decodes by a byte order mark before it looks for a declaration.
    let text = match text.strip_prefix('\u{feff}') {
        Some(rest) => rest,
        None if coding(text).is_some_and(|c| !["utf_8", "utf8"].contains(&&*c)) => return None,
        None => text,
    };
    let odd =
        |c| (char::is_whitespace(c) || ('\x1c'..='\x1f').contains(&c)) && !" \t\n\r".contains(c);
    if text.chars().any(odd) {
        return None;
    }
    let (mut deps, mut unknown) = (Vec::new(), Vec::new());
    let (mut elsewhere, mut lock, mut any) = (false, true, false);
    for (n, line) in lines(text) {
        let not_told = |why: &str| format!("line {n} ({why})");
        if env_var(&line) {
            unknown.push(not_told("an environment variable"));
            continue;
        }
        let (args, options) = break_args_options(&line);
        let o = parse_options(shlex(options)?)?;
        // pip reads a line with no requirement for its options, and of a line that includes a
        // file only that file; on a requirement line only `--hash` and `--config-settings` count.
        if args.is_empty() && !o.editable {
            match o.include {
                Some(option) => unknown.push(not_told(option)),
                None => {
                    elsewhere |= o.elsewhere || o.index.iter().any(|i| !PYPI_INDEX.contains(&&**i));
                    lock &= !o.no_require_hashes;
                }
            }
            continue;
        }
        any = true;
        let found = if o.editable {
            Err("-e")
        } else {
            requirement(args)?
        };
        lock &= o.hashes > 0 && found.as_ref().is_ok_and(|(_, v, _)| v.is_some());
        match found {
            Ok((name, version, source)) => deps.push(Dep {
                at: At::Line(n),
                name,
                version,
                source,
            }),
            Err(why) => unknown.push(not_told(why)),
        }
    }
    for dep in deps
        .iter_mut()
        .filter(|d| elsewhere && d.source == Source::Registry)
    {
        dep.source = Source::OtherRegistry;
    }
    if any && !lock {
        unknown.push(UNLISTED.to_string());
    }
    Some((deps, unknown))
}

/// What a requirement is: a pinned one, its name and version from PyPI; `name @ address`, its
/// name and where the address says, with no version; or why it is not told. `None` for one pip
/// refuses. pip splits off markers at `;` and takes a text holding `/` or beginning with `.` for
/// a path, as its `_looks_like_path` does.
type Found = Result<(String, Option<String>, Source), &'static str>;
fn requirement(args: &str) -> Option<Found> {
    let spec = args.split_once(';').map_or(args, |(s, _)| s);
    let spec = spec.trim_matches([' ', '\t']);
    if let Some((name, url)) = spec.split_once('@')
        && let Some((name, specs)) = specifiers(name)
        && specs.is_empty()
    {
        let url = url.trim_matches([' ', '\t']);
        let source = match url {
            "" => return None,
            _ if url.starts_with("git+") => Source::Git,
            _ if url.starts_with("file:") || !url.contains("://") => Source::Path,
            _ => Source::OtherRegistry,
        };
        return Some(Ok((name, None, source)));
    }
    if spec.contains('/') || spec.starts_with('.') || spec.starts_with("file:") {
        return Some(Err("an address or a path"));
    }
    let (name, specs) = specifiers(spec)?;
    Some(match specs[..] {
        [("==", v)] if canonical_version(v) => Ok((name, Some(v.to_string()), Source::Registry)),
        _ => Err("not pinned"),
    })
}

/// A requirement's name, normalised, and its specifiers as `(operator, version)`, from
/// `name [extras] spec, spec` with or without brackets around the specifiers; `None` for a text
/// of another shape. Versions are only checked for their characters.
fn specifiers(spec: &str) -> Option<(String, Vec<(&str, &str)>)> {
    let ws = [' ', '\t'];
    let end = (spec.find(|c: char| !c.is_ascii_alphanumeric() && !"._-".contains(c)))
        .unwrap_or(spec.len());
    let name = pypi_name(&spec[..end])?;
    let mut rest = spec[end..].trim_start_matches(ws);
    if let Some(inner) = rest.strip_prefix('[') {
        let (extras, after) = inner.split_once(']')?;
        let extras = extras.trim_matches(ws);
        if !extras.is_empty()
            && !extras
                .split(',')
                .all(|e| pypi_name(e.trim_matches(ws)).is_some())
        {
            return None;
        }
        rest = after.trim_start_matches(ws);
    }
    let rest = match rest.strip_prefix('(') {
        Some(inner) => inner.trim_end_matches(ws).strip_suffix(')')?,
        None => rest,
    };
    let rest = rest.trim_matches(ws);
    if rest.is_empty() {
        return Some((name, Vec::new()));
    }
    let specs = rest.split(',').map(|s| {
        let s = s.trim_matches(ws);
        let op = ["===", "==", "!=", "<=", ">=", "~=", "<", ">"]
            .into_iter()
            .find(|op| s.starts_with(op))?;
        let v = s[op.len()..].trim_start_matches(ws);
        let ok = !v.is_empty()
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._*+!-".contains(c));
        ok.then_some((op, v))
    });
    Some((name, specs.collect::<Option<_>>()?))
}

/// The encoding a `#` line among the first two declares, as pip's `coding[:=]\s*([-\w.]+)` finds
/// it, lowercased with `-` as `_`.
fn coding(text: &str) -> Option<String> {
    for line in text.split('\n').take(2).filter(|l| l.starts_with('#')) {
        for (i, _) in line.match_indices("coding") {
            let Some(rest) = line[i + 6..].strip_prefix([':', '=']) else {
                continue;
            };
            let rest = rest.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
            let n = (rest.find(|c: char| !c.is_ascii_alphanumeric() && !"-_.".contains(c)))
                .unwrap_or(rest.len());
            if n > 0 {
                return Some(rest[..n].to_ascii_lowercase().replace('-', "_"));
            }
        }
    }
    None
}

/// pip's `preprocess` up to its environment variables: lines as `str.splitlines` gives them in a
/// text with no other break than `\n`, `\r\n` and `\r`, a line ending in `\` joined to the next
/// with backslashes stripped from both ends unless it is a comment, comments from a `#` at the
/// start or after a space or tab, and blank lines dropped. Each comes with its first line's number.
fn lines(text: &str) -> Vec<(usize, String)> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let (mut out, mut joined) = (Vec::new(), None::<(usize, String)>);
    for (i, line) in text.split('\n').enumerate() {
        let comment = line.trim_start_matches([' ', '\t']).starts_with('#');
        if line.ends_with('\\') && !comment {
            joined
                .get_or_insert((i + 1, String::new()))
                .1
                .push_str(line.trim_matches('\\'));
            continue;
        }
        let line = format!("{}{line}", if comment { " " } else { "" });
        out.push(match joined.take() {
            Some((n, start)) => (n, start + &line),
            None => (i + 1, line),
        });
    }
    out.extend(joined);
    let cut = |line: &str| {
        let hash = line
            .char_indices()
            .find(|&(i, c)| c == '#' && (i == 0 || line[..i].ends_with([' ', '\t'])));
        line[..hash.map_or(line.len(), |(i, _)| i)]
            .trim_matches([' ', '\t'])
            .to_string()
    };
    (out.into_iter().map(|(n, line)| (n, cut(&line))))
        .filter(|(_, line)| !line.is_empty())
        .collect()
}

/// Whether a line holds `${NAME}`, a name of uppercase letters, digits and `_`, which pip replaces
/// from the environment before it reads the line.
fn env_var(line: &str) -> bool {
    line.match_indices("${").any(|(i, _)| {
        let rest = &line[i + 2..];
        let n = (rest.bytes())
            .take_while(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            .count();
        n > 0 && rest[n..].starts_with('}')
    })
}

/// pip's `break_args_options`: the words split at single spaces before the first that begins
/// with `-`, and the rest from there.
fn break_args_options(line: &str) -> (&str, &str) {
    let mut at: usize = 0;
    for word in line.split(' ') {
        if word.starts_with('-') {
            return (&line[..at.saturating_sub(1)], &line[at..]);
        }
        at += word.len() + 1;
    }
    (line, "")
}

/// Python's `shlex.split` in POSIX mode, with no comments: words split at space, tab, `\r` and
/// `\n`; a backslash keeps the next character; single quotes keep everything; in double quotes a
/// backslash escapes only `"` and itself. `None` for a quote not closed or a backslash at the end.
fn shlex(text: &str) -> Option<Vec<String>> {
    let (mut out, mut word, mut chars) = (Vec::new(), None::<String>, text.chars());
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => out.extend(word.take()),
            '\\' => word.get_or_insert_default().push(chars.next()?),
            '\'' | '"' => {
                let word = word.get_or_insert_default();
                loop {
                    match chars.next()? {
                        q if q == c => break,
                        '\\' if c == '"' => {
                            let next = chars.next()?;
                            if next != '"' && next != '\\' {
                                word.push('\\');
                            }
                            word.push(next);
                        }
                        other => word.push(other),
                    }
                }
            }
            other => word.get_or_insert_default().push(other),
        }
    }
    out.extend(word);
    Some(out)
}

/// The options of a line as Python's `optparse` reads them: `--` ends them, a long option may be
/// any prefix of one name only and takes its value after `=` or as the next word, a short option
/// takes the rest of its word or the next one (every short option here takes a value), and words
/// that are no option are left. `None` for what `optparse` or the option's own check refuses.
fn parse_options(words: Vec<String>) -> Option<Opts> {
    let names = || {
        OPTIONS
            .iter()
            .flat_map(|(n, opt)| n.split(' ').map(move |n| (n, *opt)))
    };
    let (mut o, mut words) = (Opts::default(), VecDeque::from(words));
    while let Some(word) = words.pop_front() {
        let (opt, value) = if word == "--" {
            break;
        } else if word.starts_with("--") {
            let (name, explicit) = match word.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (word.as_str(), None),
            };
            let prefixed: Vec<_> = names().filter(|(n, _)| n.starts_with(name)).collect();
            let (_, opt) = match names().find(|(n, _)| *n == name) {
                Some(exact) => exact,
                None => *prefixed.first().filter(|_| prefixed.len() == 1)?,
            };
            let flag = matches!(opt, Opt::Flag | Opt::NoIndex | Opt::NoRequireHashes);
            match explicit {
                Some(_) if flag => return None,
                _ if flag => (opt, String::new()),
                _ => (opt, explicit.or_else(|| words.pop_front())?),
            }
        } else if let Some(rest) = word.strip_prefix('-').filter(|r| !r.is_empty()) {
            let n = rest.chars().next()?.len_utf8();
            let (_, opt) = names().find(|(name, _)| name.strip_prefix('-') == Some(&rest[..n]))?;
            let attached = Some(rest[n..].to_string()).filter(|a| !a.is_empty());
            (opt, attached.or_else(|| words.pop_front())?)
        } else {
            continue;
        };
        let refused = match opt {
            Opt::Names => value.starts_with('-'),
            Opt::Feature => !FEATURES.split_whitespace().any(|f| f == value),
            Opt::Hash => !value
                .split_once(':')
                .is_some_and(|(a, _)| STRONG_HASHES.contains(&a)),
            Opt::Config => !value.contains('='),
            _ => false,
        };
        match opt {
            _ if refused => return None,
            Opt::Index => o.index.push(value),
            Opt::Elsewhere | Opt::NoIndex => o.elsewhere = true,
            Opt::Requirement => o.include = Some("-r"),
            Opt::Constraint => o.include = o.include.or(Some("-c")),
            Opt::Editable => o.editable = true,
            Opt::Hash => o.hashes += 1,
            Opt::NoRequireHashes => o.no_require_hashes = true,
            _ => {}
        }
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::super::tests::Dir;
    use super::super::{NOT_TOLD, partial_for};
    use super::{At, Parsed, break_args_options, lines, parse_options, requirements, shlex};
    use crate::store::Cause;

    /// A hash as pip takes it; the digest is invented.
    const H: &str =
        "--hash=sha256:abababababababababababababababababababababababababababababababab";
    const H384: &str = "--hash=sha384:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    /// What the reader gives for `text`: each entry as `name version source line`, each key not
    /// told after `?`, or `failed`.
    fn read(text: &str) -> Vec<String> {
        let Parsed::Deps("PyPI", deps, unknown) = requirements(text) else {
            return vec!["failed".to_string()];
        };
        let entry = |d: &super::Dep| {
            let At::Line(n) = d.at else { unreachable!() };
            let version = d.version.as_deref().unwrap_or("-");
            format!("{} {version} {:?} {n}", d.name, d.source)
        };
        let unknown = unknown.iter().map(|key| format!("? {key}"));
        deps.iter().map(entry).chain(unknown).collect()
    }

    /// Two pinned and hashed lines, the second joined to the next with extras and a marker.
    fn lock() -> String {
        format!(
            "# a lock\nwidget==1.2.0 {H}\nMy_Gadget[extra]==2.0rc1 ; python_version < \"3.9\" \\\n\t{H} {H384}\n"
        )
    }

    fn check(rows: &[(&str, String, &[&str])]) {
        for (case, text, expected) in rows {
            assert_eq!(read(text), *expected, "{case}: {text:?}");
        }
    }

    #[test]
    fn a_requirements_file_is_a_lock_of_pypi_s_packages_only_pinned_and_hashed_with_no_other_index()
    {
        let lock = lock();
        let pypi = ["widget 1.2.0 Registry 2", "my-gadget 2.0rc1 Registry 3"];
        let other = [
            "widget 1.2.0 OtherRegistry 2",
            "my-gadget 2.0rc1 OtherRegistry 3",
        ];
        let mirror = "https://mirror.example.invalid/simple";
        let unlisted = "? dependencies it does not list";
        check(&[
            ("lock", lock.clone(), &pypi),
            ("crlf", lock.replace('\n', "\r\n"), &pypi),
            ("pypi", format!("{lock}-i https://pypi.org/simple"), &pypi),
            (
                "pypi /",
                format!("{lock}--index-url=https://pypi.org/simple/"),
                &pypi,
            ),
            ("mirror", format!("{lock}-i {mirror}"), &other),
            (
                "mirror, then pypi",
                format!("{lock}-i {mirror}\n-i https://pypi.org/simple"),
                &other,
            ),
            (
                "extra",
                format!("{lock}--extra-index-url https://pypi.org/simple"),
                &other,
            ),
            ("find links", format!("{lock}-f ./wheels"), &other),
            ("no index", format!("{lock}--no-index"), &other),
            // pip takes only `--hash` and `--config-settings` from a requirement line, and only
            // the included file from a line that includes one.
            (
                "index on a requirement line",
                format!("{lock}gizmo==3.0 {H} -i {mirror} --no-index"),
                &[pypi[0], pypi[1], "gizmo 3.0 Registry 5"],
            ),
            (
                "index beside -r",
                format!("{lock}-r base.txt -i {mirror}"),
                &[pypi[0], pypi[1], "? line 5 (-r)"],
            ),
            (
                "options that change no package",
                format!(
                    "--trusted-host=host1 --trusted-host=host2:8080\n--pre\n--all-releases :all:\n\
                     --only-final pkg1,pkg2\n--use-feature=fast-deps\n--prefer-binary\n--require-hashes\n\
                     --no-binary=:all: --only-binary wilma\n--hash=sha512:00\n{lock}"
                ),
                &["widget 1.2.0 Registry 11", "my-gadget 2.0rc1 Registry 12"],
            ),
            (
                "config settings, line 420",
                format!("{lock}gizmo==3.0 {H} --config-settings=\"yo3=yo4\" -C \"yo1=yo2\""),
                &[pypi[0], pypi[1], "gizmo 3.0 Registry 5"],
            ),
            // pip leaves a word after a requirement's options unread.
            (
                "a word after options",
                format!("{lock}gizmo==3.0 {H} extra==1.0"),
                &[pypi[0], pypi[1], "gizmo 3.0 Registry 5"],
            ),
            (
                "brackets",
                format!("gizmo (== 1.0) {H}\ngizmo[] == 1.1 {H}\ngizmo==1!2.0 {H}"),
                &[
                    "gizmo 1.0 Registry 1",
                    "gizmo 1.1 Registry 2",
                    "gizmo 1!2.0 Registry 3",
                ],
            ),
            ("empty", "# Comment ".to_string(), &[]),
            (
                "utf-8 declared",
                format!("# -*- coding: utf-8 -*-\n{lock}"),
                &["widget 1.2.0 Registry 3", "my-gadget 2.0rc1 Registry 4"],
            ),
            (
                "utf8 declared",
                format!("#!x\n# vim: fileencoding=UTF8\n{lock}"),
                &["widget 1.2.0 Registry 4", "my-gadget 2.0rc1 Registry 5"],
            ),
            (
                "bom before a declaration",
                format!("\u{feff}# coding: latin-1\n{lock}"),
                &["widget 1.2.0 Registry 3", "my-gadget 2.0rc1 Registry 4"],
            ),
            (
                "third line",
                format!("\n\n# coding: latin-1\n{lock}"),
                &["widget 1.2.0 Registry 5", "my-gadget 2.0rc1 Registry 6"],
            ),
            (
                "not at the start",
                format!(" # coding: latin-1\n{lock}"),
                &["widget 1.2.0 Registry 3", "my-gadget 2.0rc1 Registry 4"],
            ),
            (
                "no name",
                format!("# coding:\n{lock}"),
                &["widget 1.2.0 Registry 3", "my-gadget 2.0rc1 Registry 4"],
            ),
            // Not a lock: what pip resolves anew is not told, and what is pinned is given.
            (
                "no hash",
                format!("{lock}gizmo==3.0"),
                &[pypi[0], pypi[1], "gizmo 3.0 Registry 5", unlisted],
            ),
            (
                "no-require-hashes",
                format!("{lock}--no-require-hashes"),
                &[pypi[0], pypi[1], unlisted],
            ),
            (
                "lines 966 and 999",
                "\u{feff}Django==1.4.2".to_string(),
                &["django 1.4.2 Registry 1", unlisted],
            ),
        ]);
        for spec in [
            "gizmo",
            "gizmo>=3.0",
            "gizmo >= 2",
            "gizmo===3.0",
            "gizmo==3.*",
            "gizmo==3.0+local",
            "gizmo==3.0.0-1",
            "gizmo==v3.0",
            "gizmo==3.0,<4",
            "gizmo~=3.0",
            "gizmo!=3.0",
            "gizmo==1!2.0+x",
        ] {
            let text = format!("{lock}{spec} {H}");
            assert_eq!(
                read(&text),
                [pypi[0], pypi[1], "? line 5 (not pinned)", unlisted],
                "{spec}"
            );
        }
    }

    #[test]
    fn an_entry_from_elsewhere_is_never_pypi_s_package() {
        let lock = lock();
        let pypi = ["widget 1.2.0 Registry 2", "my-gadget 2.0rc1 Registry 3"];
        let unlisted = "? dependencies it does not list";
        let one = |entry: &'static str| vec![pypi[0], pypi[1], entry, unlisted];
        let path = "? line 5 (an address or a path)";
        for (case, line, expected) in [
            (
                "line 299",
                "SomeProject @ https://url/SomeProject-py2-py3-none-any.whl",
                one("someproject - OtherRegistry 5"),
            ),
            (
                "git",
                "tool@git+https://example.invalid/tool.git@v1",
                one("tool - Git 5"),
            ),
            ("file", "tool[cli] @ file:///src/tool", one("tool - Path 5")),
            ("path", "tool @ ../tool", one("tool - Path 5")),
            (
                "line 326",
                "-e git+https://url#egg=SomeProject",
                vec![pypi[0], pypi[1], "? line 5 (-e)", unlisted],
            ),
            (
                "editable",
                "--editable=.",
                vec![pypi[0], pypi[1], "? line 5 (-e)", unlisted],
            ),
            (
                "line 910",
                "https://example.com/foo.tar.gz # Comment ",
                vec![pypi[0], pypi[1], path, unlisted],
            ),
            (
                "line 929",
                "https://example.com/foo.tar.gz#egg=wat",
                vec![pypi[0], pypi[1], path, unlisted],
            ),
            (
                "folder",
                "./vendor/tool",
                vec![pypi[0], pypi[1], path, unlisted],
            ),
            ("here", ".", vec![pypi[0], pypi[1], path, unlisted]),
            (
                "file url",
                "file:tool.zip",
                vec![pypi[0], pypi[1], path, unlisted],
            ),
        ] {
            let text = format!("{lock}{line} {H}");
            assert_eq!(read(&text), expected, "{case}");
        }
        // Another index leaves an address where it points.
        assert_eq!(
            read(&format!(
                "tool @ git+https://example.invalid/t.git {H}\n--no-index"
            )),
            ["tool - Git 1", unlisted]
        );
    }

    #[test]
    fn an_included_file_or_an_environment_variable_leaves_its_line_not_told() {
        for (case, text, expected) in [
            ("line 340", "-c reqs.txt", &["? line 1 (-c)"][..]),
            (
                "line 357",
                "-r a.txt\n-r b.txt",
                &["? line 1 (-r)", "? line 2 (-r)"],
            ),
            ("both", "-c a.txt --requirement=b.txt", &["? line 1 (-r)"]),
            (
                "both, -r first",
                "-r a.txt --constraint b.txt",
                &["? line 1 (-r)"],
            ),
            (
                "line 792",
                "https://${GITHUB_TOKEN}:x-oauth-basic@github.com/user/${DO_12_FACTOR}/archive/master.zip",
                &["? line 1 (an environment variable)"],
            ),
            (
                "line 829",
                "https://${NON_EXISTENT_VARIABLE}:$WRONG_FORMAT@%WINDOWS_FORMAT%github.com/user/repo/archive/master.zip",
                &["? line 1 (an environment variable)"],
            ),
            (
                "an option",
                "-i https://${HOST}/simple",
                &["? line 1 (an environment variable)"],
            ),
            // Not a variable pip replaces: the line is read as it is.
            (
                "lowercase",
                "--extra-index-url ${lower}\nwidget==1.0",
                &[
                    "widget 1.0 OtherRegistry 2",
                    "? dependencies it does not list",
                ],
            ),
            ("empty", "-f ${}\n-f ${A", &[]),
            // A file with no requirement leaves nothing unlisted.
            ("no requirement", "--no-require-hashes", &[]),
        ] {
            assert_eq!(read(text), expected, "{case}");
        }
    }

    #[test]
    fn a_file_pip_refuses_or_could_split_otherwise_fails_the_reading() {
        let lock = lock();
        let mut texts: Vec<String> = [
            "--bogus",
            "pkg==1.0.0 --hash=somehash",
            "pkg==1.0.0 --hash=md5:abcdef",
            "req1 req2",
            "my-package=1.0",
            "--use-feature=resolvelib",
            "--'data\n",
            "--no-use-wheel",
            "--no",
            "-x",
            "-i",
            "--index-url",
            "--pre=1",
            "--no-binary --pre",
            "--only-final=-x",
            "pkg==1.0 -C novalue",
            "pkg==1.0 --hash=\"sha256:00",
            "tool @ ",
            "widget[bad extra]==1.0",
            "widget[x==1.0",
            "widget==1.0)",
            "wid get==1.0",
            "-widget==1.0",
            "widget==1.0\t--hash=sha256:00",
            "widget-==1.0",
            "gizmo (==1.0",
            "gizmo==",
        ]
        .map(|t| format!("{lock}{t}"))
        .into();
        for c in [
            '\x0b', '\x0c', '\x1c', '\x1f', '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{200a}',
            '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
        ] {
            texts.push(format!("{lock}# a{c}b"));
        }
        // A declaration of another encoding in one of the first two lines, which pip decodes by.
        for head in [
            "# -*- coding: latin-1 -*-\n",
            "# coding=latin1\n",
            "#!x\n# vim: set fileencoding=cp1252 :\n",
        ] {
            texts.push(format!("{head}{lock}"));
        }
        for text in texts {
            assert_eq!(read(&text), ["failed"], "{text:?}");
        }
    }

    #[test]
    fn lines_are_split_joined_and_stripped_of_comments_as_pip_s_own_tests_expect() {
        let pairs = |p: &[(usize, &str)]| -> Vec<(usize, String)> {
            p.iter().map(|(n, l)| (*n, l.to_string())).collect()
        };
        for (case, text, expected) in [
            (
                "line 118",
                "req1 \\\n# comment \\\nreq2\n",
                pairs(&[(1, "req1"), (3, "req2")]),
            ),
            ("line 127", "req1\\\n# comment\n", pairs(&[(1, "req1")])),
            (
                "line 135",
                "req1 \\\n# comment\nreq2\n",
                pairs(&[(1, "req1"), (3, "req2")]),
            ),
            (
                "line 149",
                "\nreq1\nreq2",
                pairs(&[(2, "req1"), (3, "req2")]),
            ),
            (
                "line 154",
                "req1\n# comment\nreq2",
                pairs(&[(1, "req1"), (3, "req2")]),
            ),
            (
                "line 159",
                "req1\nreq # comment\nreq2",
                pairs(&[(1, "req1"), (2, "req"), (3, "req2")]),
            ),
            (
                "line 168",
                "line 1\nline 2:1 \\\nline 2:2\nline 3:1 \\\nline 3:2 \\\nline 3:3\nline 4",
                pairs(&[
                    (1, "line 1"),
                    (2, "line 2:1 line 2:2"),
                    (4, "line 3:1 line 3:2 line 3:3"),
                    (7, "line 4"),
                ]),
            ),
            (
                "line 189",
                "line 1\nline 2 \\",
                pairs(&[(1, "line 1"), (2, "line 2")]),
            ),
            ("line 886", "# Comment ", pairs(&[])),
            (
                "fragment",
                "a.tar.gz#egg=wat\tx #y",
                pairs(&[(1, "a.tar.gz#egg=wat\tx")]),
            ),
            ("backslashes", "\\\\a\\\\\nb", pairs(&[(1, "ab")])),
            (
                "a comment after a backslash",
                "\\#a \\\nb\nc\t# d",
                pairs(&[(3, "c")]),
            ),
            (
                "breaks",
                "a\r\nb\rc\n",
                pairs(&[(1, "a"), (2, "b"), (3, "c")]),
            ),
        ] {
            assert_eq!(lines(text), expected, "{case}");
        }
        for (case, line, expected) in [
            ("line 705", "--option", ("", "--option")),
            ("line 708", "arg arg", ("arg arg", "")),
            ("line 711", "arg arg -s", ("arg arg", "-s")),
            ("line 715", "arg arg --long", ("arg arg", "--long")),
            ("two spaces", "a  -b c", ("a ", "-b c")),
        ] {
            assert_eq!(break_args_options(line), expected, "{case}");
        }
    }

    #[test]
    fn options_are_split_and_read_as_shlex_and_optparse_read_them() {
        // Lines 722 to 750, and what `shlex` and `optparse` do besides.
        for (line, index) in [
            ("-i url", vec!["url"]),
            ("-i 'url'", vec!["url"]),
            ("--index-url=url", vec!["url"]),
            ("--index-url url", vec!["url"]),
            ("--index-url='url'", vec!["url"]),
            ("-iurl", vec!["url"]),
            ("--index url", vec!["url"]),
            ("--pypi-url=url", vec!["url"]),
            ("-i u\\ rl", vec!["u rl"]),
            ("-i \"u\\\"r\\l\\\\\"", vec!["u\"r\\l\\"]),
            ("-i 'u\\' -i u'r'\"l\"", vec!["u\\", "url"]),
            ("-i ''", vec![""]),
            ("x -i url y", vec!["url"]),
            ("-- -i url", vec![]),
        ] {
            let o = parse_options(shlex(line).unwrap()).unwrap();
            assert_eq!(o.index, index, "{line}");
        }
        for line in ["-i 'url", "-i \"url", "-i url\\", "-i \"u\\"] {
            assert!(shlex(line).is_none(), "{line}");
        }
        // A prefix of one name is that option, and a name given whole is itself.
        let words = shlex("--pre --no-req --extra=x --hash sha384:0 --ha=sha512:0").unwrap();
        let o = parse_options(words).unwrap();
        assert!(o.no_require_hashes && o.elsewhere && o.hashes == 2);
        assert!(!o.editable && o.include.is_none());
    }

    #[test]
    fn a_requirements_file_read_in_part_says_so_for_pypi_by_its_kind() {
        let dir = Dir::new("requirements", &[("requirements.txt", &lock())]);
        let (o, said) = dir.read();
        let at = "dev/shop/requirements.txt";
        assert_eq!(
            said,
            [
                format!("PyPI/my-gadget|part_of|checkout|{at}:3"),
                format!("PyPI/my-gadget|has_version|2.0rc1|{at}:3"),
                format!("PyPI/widget|part_of|checkout|{at}:2"),
                format!("PyPI/widget|has_version|1.2.0|{at}:2"),
            ]
        );
        assert_eq!((o.completeness, o.reason), ("full", None));
        let text = format!("{}gizmo>=3.0 {H}\n-r base.txt\n", lock());
        let dir = Dir::new("requirements-part", &[("requirements.txt", &text)]);
        let (o, said) = dir.read();
        assert_eq!(said.len(), 4, "{said:?}");
        let reason = o.reason.unwrap();
        assert_eq!(
            reason,
            format!(
                "the package of 3 entries cannot be told: {at}#line 5 (not pinned), \
                 {at}#line 6 (-r), {at}#dependencies it does not list"
            )
        );
        assert_eq!(o.gap.cause, Some(Cause::NotGiven));
        let names: Vec<Option<String>> = o.gap.lacks.iter().map(|l| l.name.clone()).collect();
        assert_eq!(names, [Some("requirements.txt".to_string())]);
        assert_eq!(o.gap.lacks[0].what, NOT_TOLD);
        assert!(partial_for(&reason, &names, "PyPI"));
        assert!(!partial_for(&reason, &names, "crates.io"));
    }
}
