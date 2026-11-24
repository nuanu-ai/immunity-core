//! The reader of `yarn.lock`, as Yarn 1 and as Yarn 2 and later write it. Yarn 1's grammar
//! is read by `crate::yarn1`.

use super::{
    At, Dep, NPM_REGISTRY, Parsed, Source, WEB, npm_name, registry_tarball, version_shape,
};

/// The values of `__metadata.version` read in a `yarn.lock` of Yarn 2 and later: those found in
/// Yarn's own `Project.ts` at its releases, 4 (2.4 and 3.0), 5 (3.1), 6 (3.2 to 3.6) and 8 to 10
/// (4.0 to 4.19). Version 7 is described only at second hand and is not read. What 9 and 10
/// changed is not known, but nothing this reader uses differs between them: it reads only an
/// entry's `resolution` and `version`, and a resolution of a form it does not know is not told.
const YARN_VERSIONS: [&str; 6] = ["4", "5", "6", "8", "9", "10"];

/// `yarn.lock`. A file with a comment `yarn lockfile v<N>`, as Yarn 1 writes it, is in Yarn 1's
/// grammar (`yarn1`): version 1 is read by `yarn1`, any other is a kind with no reader. Without
/// one it is Yarn 2 and later's, which is YAML: every entry by its `resolution`, which is what
/// Yarn fetches, never by its key. The comment decides the format, as Yarn 2 and later also take
/// a file with it for Yarn 1's; what Yarn 1 would install from a file in the other format is not
/// judged.
///
/// Yarn reads every scalar as text; a value `serde_norway` reads as a number or a boolean where
/// text is expected leaves the entry not told, never converted. A key given twice in one mapping
/// fails the reading, as `serde_norway` refuses it.
pub(super) fn yarn(text: &str) -> Parsed {
    use serde_norway::Value;
    if text.contains("yarn lockfile v") {
        match crate::yarn1::parse(text) {
            Err(_) => return Parsed::Failed,
            Ok(lock) => match lock.version.as_deref() {
                Some("1") => return yarn1(&lock.entries),
                Some(v) if version_shape(v) => {
                    return Parsed::NoReader(format!("yarn.lock version {v}"));
                }
                // A version too long to be one, or the words not in a comment: a file Yarn 1
                // reads without a header, and Yarn 2 and later take for Yarn 1's.
                _ => return Parsed::Failed,
            },
        }
    }
    let Ok(Value::Mapping(lock)) = serde_norway::from_str::<Value>(text) else {
        return Parsed::Failed;
    };
    let version = match lock.get("__metadata").and_then(|m| m.get("version")) {
        Some(Value::String(v)) => v.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => return Parsed::Failed,
    };
    match version.as_str() {
        v if YARN_VERSIONS.contains(&v) => {}
        v if version_shape(v) => return Parsed::NoReader(format!("yarn.lock version {v}")),
        _ => return Parsed::Failed,
    }
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    for (key, entry) in &lock {
        let Some(key) = key.as_str() else {
            return Parsed::Failed;
        };
        if key == "__metadata" {
            continue;
        }
        match yarn_entry(key, entry) {
            Some(Some(dep)) => out.push(dep),
            Some(None) => {}
            None => unknown.push(key.to_string()),
        }
    }
    Parsed::Deps("npm", out, unknown)
}

/// One entry of a `yarn.lock` of Yarn 2 and later, by its resolution `<name>@<reference>`:
/// `Some(None)` for a workspace, which is the project itself, and `None` when the lockfile does
/// not tell what it is. The entry is the registry's only as `npm:<version>` with no `::`
/// parameters, or as a `patch:` of exactly `<name>@npm%3A<version>`, compared as written, by one
/// patch Yarn ships itself (`builtin<…>`); Yarn does not write which registry, and as for pnpm
/// the one the project is set up with is taken for the public one. A patch of the project's own
/// changes the package's files, so that package is a path's. `__archiveUrl` names another
/// registry's address. A `version` field that differs from the resolution's version leaves the
/// entry not told.
fn yarn_entry(key: &str, entry: &serde_norway::Value) -> Option<Option<Dep>> {
    let text = |field: &str| match entry.get(field) {
        None => Some(None),
        Some(v) => v.as_str().map(Some),
    };
    let resolution = text("resolution")??;
    let stated = text("version")?;
    let at = resolution.get(1..)?.find('@')? + 1;
    let (name, reference) = (&resolution[..at], &resolution[at + 1..]);
    // The project itself, whatever it is named.
    if reference.starts_with("workspace:") {
        return Some(None);
    }
    if !npm_name(name) {
        return None;
    }
    let (source, version) = if let Some(npm) = reference.strip_prefix("npm:") {
        match npm.split_once("::") {
            None => (Source::Registry, npm),
            Some((v, params)) if params.starts_with("__archiveUrl=") => (Source::OtherRegistry, v),
            Some(_) => return None,
        }
    } else if let Some(patch) = reference.strip_prefix("patch:") {
        // The patched package's locator, then after `#` the patches, joined by `&`, then the
        // outer `::` parameters.
        let (inner, paths) = patch.split_once('#')?;
        let version = inner.strip_prefix(name)?.strip_prefix("@npm%3A")?;
        let paths = paths.split("::").next().unwrap_or_default();
        // One patch Yarn ships itself, as Yarn 4 and Yarn 3 write it, leaves the registry's
        // package; a patch of the project's own changes it, as a file of the project would.
        let builtin = ["optional!builtin<", "~builtin<"]
            .iter()
            .any(|p| paths.starts_with(p))
            && paths.ends_with('>')
            && !paths.contains('&');
        let source = if builtin {
            Source::Registry
        } else {
            Source::Path
        };
        (source, version)
    } else {
        let source = match reference {
            r if ["file:", "portal:", "link:", "exec:"]
                .iter()
                .any(|p| r.starts_with(p)) =>
            {
                Source::Path
            }
            // Yarn writes every git resolution with the commit it fetched.
            r if r.contains("#commit=") => Source::Git,
            r if WEB.iter().any(|p| r.starts_with(p)) => Source::OtherRegistry,
            _ => return None,
        };
        // Yarn writes this for a soft link, which has no version of its own.
        let version = stated
            .filter(|v| *v != "0.0.0-use.local")
            .map(str::to_string);
        let at = At::Key(key.to_string());
        return Some(Some(Dep {
            at,
            name: name.to_string(),
            version,
            source,
        }));
    };
    if semver::Version::parse(version).is_err() || stated.is_some_and(|s| s != version) {
        return None;
    }
    Some(Some(Dep {
        at: At::Key(key.to_string()),
        name: name.to_string(),
        version: Some(version.to_string()),
        source,
    }))
}

/// The addresses of npm's public registry as Yarn 1 writes them in `resolved`.
const YARN1_REGISTRIES: [&str; 2] = ["https://registry.yarnpkg.com/", NPM_REGISTRY];

/// `yarn.lock` of Yarn 1, as `yarn1::parse` read it. Every top-level entry is a package; one
/// whose value is not a block fails the reading, since Yarn takes text there for a pointer to
/// another entry. Each entry is placed by its keys as written, joined by `, `.
fn yarn1(entries: &[crate::yarn1::Entry]) -> Parsed {
    use crate::yarn1::Value;
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    for entry in entries {
        let Value::Block(fields) = &entry.value else {
            return Parsed::Failed;
        };
        match yarn1_entry(&entry.keys, fields) {
            Some(dep) => out.push(dep),
            None => unknown.push(entry.keys.join(", ")),
        }
    }
    Parsed::Deps("npm", out, unknown)
}

/// One entry of Yarn 1's `yarn.lock`, or `None` when it does not tell what Yarn installs for it.
/// Yarn fetches a locked entry from `resolved` as written and checks nothing, so the entry is the
/// public registry's only when `resolved`, without its `#` fragment, is the registry's file of
/// the entry's name and `version` (`registry_tarball`). The name is the `name` field, else the
/// package all its keys ask for (`asks_for`); a key's name ends at the first `@` after its first
/// character, as Yarn's `normalizePattern` reads a key. An entry with no `resolved` is resolved again by Yarn and is
/// told only when every key names a `file:` or `link:` range, a path.
fn yarn1_entry(keys: &[String], fields: &[crate::yarn1::Entry]) -> Option<Dep> {
    let text = |name: &str| match fields.iter().find(|f| f.keys.iter().any(|k| k == name)) {
        None => Some(None),
        Some(field) => match &field.value {
            crate::yarn1::Value::Text(t) => Some(Some(t.as_str())),
            _ => None,
        },
    };
    fn split(key: &str) -> (&str, &str) {
        match key.get(1..).and_then(|k| k.find('@')) {
            Some(i) => (&key[..=i], &key[i + 2..]),
            None => (key, ""),
        }
    }
    // The package a key asks for: the one its range names when the range is an alias,
    // `npm:<name>@<range>`, else the key's own name. Yarn 1 groups the keys that resolve to one
    // package and writes `name` only for the first of them when its name differs; so a group may
    // mix an alias with plain keys and carry no `name` (the lead's reading of Yarn's
    // `__tests__/lockfile.js`, lines 106 to 219; the alias form is from memory).
    fn asks_for(key: &str) -> &str {
        let (name, range) = split(key);
        range
            .strip_prefix("npm:")
            .map_or(name, |real| split(real).0)
    }
    let name = match text("name")? {
        Some(name) => name,
        None => {
            let name = asks_for(keys.first()?);
            if keys.iter().any(|k| asks_for(k) != name) {
                return None;
            }
            name
        }
    };
    let version = text("version")?;
    if !npm_name(name) || version == Some("") {
        return None;
    }
    let source = match text("resolved")?.and_then(|r| r.split('#').next()) {
        None => {
            let local = |k: &String| ["file:", "link:"].iter().any(|p| split(k).1.starts_with(p));
            if !keys.iter().all(local) {
                return None;
            }
            Source::Path
        }
        Some(r) => match YARN1_REGISTRIES.iter().find_map(|p| r.strip_prefix(p)) {
            Some(path) if registry_tarball(path, name, version?) => Source::Registry,
            Some(_) => return None,
            None if ["git+", "git://", "https://codeload.github.com/"]
                .iter()
                .any(|p| r.starts_with(p)) =>
            {
                Source::Git
            }
            None if r.starts_with("file:") => Source::Path,
            None => Source::OtherRegistry,
        },
    };
    Some(Dep {
        at: At::Key(keys.join(", ")),
        name: name.to_string(),
        version: version.map(str::to_string),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::super::LOCKFILE_KIND;
    use super::super::tests::{Dir, YARN, lacks, one_not_told, read_one, unknown_for};

    #[test]
    fn a_yarn_entry_is_the_package_its_resolution_names_and_says_where_it_comes_from() {
        // Yarn fetches by the resolution: an alias is the package it resolves to, a patch of a
        // registry package is that package, and only an entry from the registry carries the bare
        // name an advisory gives. A workspace is the project itself.
        let dir = Dir::new("yarn", &[("yarn.lock", YARN)]);
        let (o, said) = dir.read();
        let at = "dev/shop/yarn.lock#";
        let patch = "fsevents@patch:fsevents@npm%3A^2.3.2#optional!builtin<compat/fsevents>";
        let git = "left-pad@https://github.com/example/left-pad.git#commit=0123456789abcdef0123456789abcdef01234567";
        let local = "local-tool@file:./vendor/local-tool-1.0.0.tgz::locator=shop%40workspace%3A.";
        let portal = "dev-tool@portal:../dev-tool::locator=shop%40workspace%3A.";
        let exec = "gen-tool@exec:./scripts/gen-tool.js::locator=shop%40workspace%3A.";
        let link = "linked-dir@link:./vendor/linked-dir::locator=shop%40workspace%3A.";
        let remote = "remote-tool@https://example.com/remote-tool-1.0.0.tgz";
        let cjs = "string-width-cjs@npm:string-width@^4.2.0";
        let expected = [
            format!("npm/@jrichman/ink|part_of|checkout|{at}@jrichman/ink@npm:^6.4.6"),
            format!("npm/@jrichman/ink|has_version|6.4.6|{at}@jrichman/ink@npm:^6.4.6"),
            format!("npm/dev-tool (path)|part_of|checkout|{at}{portal}"),
            format!("npm/fsevents|part_of|checkout|{at}{patch}"),
            format!("npm/fsevents|has_version|2.3.3|{at}{patch}"),
            format!("npm/gen-tool (path)|part_of|checkout|{at}{exec}"),
            format!("npm/gen-tool (path)|has_version|1.0.0|{at}{exec}"),
            format!("npm/left-pad (git)|part_of|checkout|{at}{git}"),
            format!("npm/left-pad (git)|has_version|1.3.0|{at}{git}"),
            format!("npm/linked-dir (path)|part_of|checkout|{at}{link}"),
            format!("npm/local-tool (path)|part_of|checkout|{at}{local}"),
            format!("npm/local-tool (path)|has_version|1.0.0|{at}{local}"),
            format!("npm/private-lib (other registry)|part_of|checkout|{at}private-lib@npm:^2.0.0"),
            format!(
                "npm/private-lib (other registry)|has_version|2.0.0|{at}private-lib@npm:^2.0.0"
            ),
            format!("npm/remote-tool (other registry)|part_of|checkout|{at}{remote}"),
            format!("npm/remote-tool (other registry)|has_version|1.0.0|{at}{remote}"),
            format!("npm/string-width|part_of|checkout|{at}{cjs}"),
            format!("npm/string-width|has_version|4.2.3|{at}{cjs}"),
            format!("npm/string-width|has_version|5.1.2|{at}string-width@npm:^5.1.2"),
        ];
        assert_eq!(said, expected);
        assert_eq!((o.completeness, o.reason), ("full", None));
        // A tarball by `http://` is another registry's as one by `https://` is.
        let http = YARN.replace(
            "resolution: \"remote-tool@https://",
            "resolution: \"remote-tool@http://",
        );
        let (said, reason) = read_one("yarn-http", "yarn.lock", &http);
        assert_eq!((said, reason), (expected.to_vec(), None));
    }

    #[test]
    fn a_yarn_patch_of_the_projects_own_is_never_the_registrys_package_and_one_yarn_ships_is() {
        // A patch changes the package's files. One Yarn ships itself, as Yarn 4 and Yarn 3 write
        // it, is on nearly every project and leaves the registry's package; one from the
        // project's own files, alone or beside a builtin one, makes it a path's, so an advisory
        // on it is never answered "not affected".
        let builtin = "#optional!builtin<compat/fsevents>::version=2.3.3&hash=df0bf1\"";
        let key = "fsevents@patch:fsevents@npm%3A^2.3.2#optional!builtin<compat/fsevents>";
        for (paths, component) in [
            (
                "#~builtin<compat/fsevents>::version=2.3.3&hash=df0bf1\"",
                "fsevents",
            ),
            (
                "#~/.yarn/patches/fsevents-npm-2.3.3-0123456789.patch::version=2.3.3&hash=aaaa&locator=shop%40workspace%3A.\"",
                "fsevents (path)",
            ),
            (
                "#./patches/fsevents.patch::version=2.3.3&hash=aaaa\"",
                "fsevents (path)",
            ),
            (
                "#optional!builtin<compat/fsevents>&./patches/fsevents.patch::version=2.3.3\"",
                "fsevents (path)",
            ),
            ("#optional!builtin<compat/fsevents>x\"", "fsevents (path)"),
            (
                "#optional!builtin<compat/fsevents>&./p.patch&optional!builtin<compat/fsevents>\"",
                "fsevents (path)",
            ),
        ] {
            let (said, reason) = read_one("yarn-patch", "yarn.lock", &YARN.replace(builtin, paths));
            let fact = format!("npm/{component}|has_version|2.3.3|dev/shop/yarn.lock#{key}");
            assert!(said.contains(&fact), "{paths}: {said:?}");
            assert_eq!(reason, None, "{paths}");
        }
        // With no `#`, the patch names no patch: not told.
        let (said, reason) = read_one(
            "yarn-patch-bare",
            "yarn.lock",
            &YARN.replace(builtin, "::version=2.3.3&hash=df0bf1\""),
        );
        assert!(!said.iter().any(|s| s.contains("fsevents")), "{said:?}");
        assert_eq!(reason, one_not_told(&format!("yarn.lock#{key}")));
    }

    #[test]
    fn a_yarn_entry_whose_package_cannot_be_told_is_never_guessed_and_makes_the_reading_partial() {
        // No false calm. Each of these would answer for a package or a version Yarn may not
        // install: the entry is not told and the reading is partial.
        let width = "  version: 5.1.2\n  resolution: \"string-width@npm:5.1.2\"";
        let patch = "resolution: \"fsevents@patch:fsevents@npm%3A2.3.3#";
        let patch_key = "fsevents@patch:fsevents@npm%3A^2.3.2#optional!builtin<compat/fsevents>";
        for (from, to, key) in [
            // A `version` field of another version than the resolution's.
            (
                width,
                "  version: 5.1.3\n  resolution: \"string-width@npm:5.1.2\"",
            ),
            // A number where Yarn reads text: never converted, never taken as absent.
            (
                width,
                "  version: 5.1\n  resolution: \"string-width@npm:5.1.2\"",
            ),
            (
                width,
                "  version: 5.1.2\n  resolution: [string-width@npm:5.1.2]",
            ),
            (width, "  version: 5.1.2"),
            // A range where Yarn writes a version, with no `version` field to compare it with.
            (width, "  resolution: \"string-width@npm:^5.1.2\""),
            (
                width,
                "  version: 5.1.2\n  resolution: \"string-width@npm:5.1.2::x=1\"",
            ),
            (
                width,
                "  version: 5.1.2\n  resolution: \"string-width@jsr:5.1.2\"",
            ),
            (
                width,
                "  version: 5.1.2\n  resolution: \"string width@npm:5.1.2\"",
            ),
            (width, "  version: 5.1.2\n  resolution: \"@npm:5.1.2\""),
        ]
        .map(|(from, to)| (from, to, "string-width@npm:^5.1.2"))
        .into_iter()
        .chain([
            // A patch of another package, or of a package not from the registry.
            (
                patch,
                "resolution: \"fsevents@patch:chokidar@npm%3A2.3.3#",
                patch_key,
            ),
            (
                patch,
                "resolution: \"fsevents@patch:fsevents@https%3A//example.com/f.tgz#",
                patch_key,
            ),
        ]) {
            let (said, reason) = read_one("yarn-not-told", "yarn.lock", &YARN.replace(from, to));
            let at = format!("yarn.lock#{key}");
            assert!(!said.iter().any(|s| s.ends_with(&at)), "{to}: {said:?}");
            assert_eq!(reason, one_not_told(&at), "{to}");
        }
    }

    #[test]
    fn a_yarn_lockfile_yarn_would_not_read_as_written_is_a_failed_reading() {
        // serde_norway refuses a key given twice in a mapping, where Yarn keeps the later one:
        // the two readings would differ, so the file is not read. So is anything else that is
        // not one YAML mapping with Yarn's `__metadata`.
        let width = "\"string-width@npm:^5.1.2\":\n  version: 5.1.2\n  resolution: \"string-width@npm:5.1.2\"\n";
        for (tag, text) in [
            ("twice", format!("{YARN}\n{width}")),
            (
                "twice-field",
                YARN.replace(
                    "  resolution: \"string-width@npm:5.1.2\"",
                    "  resolution: \"string-width@npm:5.1.2\"\n  resolution: \"string-width@npm:5.0.0\"",
                ),
            ),
            ("no-metadata", YARN.replace("__metadata:", "metadata:")),
            ("number-key", format!("{YARN}\n1.5:\n  version: 1.5.0\n")),
            ("two-documents", format!("{YARN}---\n{width}")),
            ("not-yaml", format!("{YARN}\n\"x: [\n")),
            ("empty", String::new()),
            // Yarn 1's: a grammar error, a pointer to another key, a version too long to be one.
            ("v1-grammar", format!("{YARN1}x:\n   y \"1\"\n")),
            ("v1-pointer", format!("{YARN1}x@^1 \"string-width@^5.1.2\"\n")),
            ("v1-number", format!("{YARN1}x@^1 5\n")),
            ("v1-long", format!("# yarn lockfile v{}\n", "1".repeat(40))),
        ] {
            let (said, reason) = read_one(tag, "yarn.lock", &text);
            assert!(said.is_empty(), "{tag}: {said:?}");
            assert_eq!(reason.as_deref(), Some("could not be read: yarn.lock"), "{tag}");
        }
    }

    #[test]
    fn a_yarn_lockfile_of_a_version_not_read_here_is_named_as_a_kind_without_a_reader() {
        // A version of Yarn 1's header or a `__metadata.version` this reader was not written
        // against may mean something else. Each is named and leaves npm unknown.
        let v10 = "# yarn lockfile v10\n\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n";
        let metadata = "__metadata:\n  version: 8\n";
        for (tag, text, kind) in [
            ("yarn-v10", v10.to_string(), "yarn.lock version 10"),
            (
                "yarn-v2",
                v10.replace("v10", "v2") + "x: [\n",
                "yarn.lock version 2",
            ),
            (
                "yarn-7",
                YARN.replace(metadata, "__metadata:\n  version: 7\n"),
                "yarn.lock version 7",
            ),
            (
                "yarn-11",
                YARN.replace(metadata, "__metadata:\n  version: \"11\"\n"),
                "yarn.lock version 11",
            ),
        ] {
            let dir = Dir::new(tag, &[("yarn.lock", &text)]);
            let (o, said) = dir.read();
            assert!(said.is_empty(), "{tag}: {said:?}");
            assert_eq!(lacks(&o), [format!("{LOCKFILE_KIND} {kind}")], "{tag}");
            assert_eq!(unknown_for(&o), [true, false], "{tag}");
        }
        for version in ["4", "5", "6", "\"6\"", "9", "10"] {
            let text = YARN.replace(metadata, &format!("__metadata:\n  version: {version}\n"));
            let (said, reason) = read_one("yarn-read", "yarn.lock", &text);
            assert_eq!((said.len(), reason), (19, None), "{version}");
        }
        let (said, reason) = read_one(
            "yarn-odd",
            "yarn.lock",
            &YARN.replace(metadata, "__metadata:\n  version: \"8 or so\"\n"),
        );
        assert!(said.is_empty());
        assert_eq!(reason.as_deref(), Some("could not be read: yarn.lock"));
    }

    /// A `yarn.lock` of Yarn 1 with every kind of entry the reader tells apart, as Yarn 1 writes
    /// them. Names and addresses other than the public registry's are invented.
    const YARN1: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@jrichman/ink@^6.4.6":
  version "6.4.6"
  resolved "https://registry.yarnpkg.com/@jrichman/ink/-/ink-6.4.6.tgz#0123456789abcdef"
  integrity sha512-AAAA
  dependencies:
    string-width "^5.1.2"

dev-tool@^1.0.0:
  version "1.0.0"

"left-pad@git+ssh://git@github.com/example/left-pad.git#0123456":
  version "1.3.0"
  resolved "git+ssh://git@github.com/example/left-pad.git#0123456789abcdef0123456789abcdef01234567"

"linked-dir@link:./vendor/linked-dir":
  version "0.0.0"

"local-dir@file:./vendor/local-dir":
  version "1.0.0"

"local-tool@file:./vendor/local-tool-1.0.0.tgz":
  version "1.0.0"
  resolved "file:./vendor/local-tool-1.0.0.tgz#0123456789abcdef"

private-lib@^2.0.0:
  version "2.0.0"
  resolved "https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz#0123456789abcdef"

"remote-tool@github:example/remote-tool":
  version "1.0.0"
  resolved "https://codeload.github.com/example/remote-tool/tar.gz/0123456789abcdef"

"string-width-cjs@npm:string-width@^4.2.0":
  name string-width
  version "4.2.3"
  resolved "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz#0123456789abcdef"

string-width@^5.0.0, string-width@^5.1.2:
  version "5.1.2"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-5.1.2.tgz#0123456789abcdef"
"#;

    #[test]
    fn a_yarn_1_entry_is_the_package_its_resolved_address_names_and_says_where_it_comes_from() {
        // Yarn 1 fetches what `resolved` names: only the registry's own file of the entry's name
        // and version carries the bare name an advisory gives. Grouped keys are one package. An
        // entry with no `resolved` that is not a path is resolved again by Yarn: not told.
        let dir = Dir::new("yarn1", &[("yarn.lock", YARN1)]);
        let (o, said) = dir.read();
        let at = "dev/shop/yarn.lock#";
        let git = "left-pad@git+ssh://git@github.com/example/left-pad.git#0123456";
        let link = "linked-dir@link:./vendor/linked-dir";
        let dir_key = "local-dir@file:./vendor/local-dir";
        let local = "local-tool@file:./vendor/local-tool-1.0.0.tgz";
        let remote = "remote-tool@github:example/remote-tool";
        let cjs = "string-width-cjs@npm:string-width@^4.2.0";
        let width = "string-width@^5.0.0, string-width@^5.1.2";
        let expected = [
            format!("npm/@jrichman/ink|part_of|checkout|{at}@jrichman/ink@^6.4.6"),
            format!("npm/@jrichman/ink|has_version|6.4.6|{at}@jrichman/ink@^6.4.6"),
            format!("npm/left-pad (git)|part_of|checkout|{at}{git}"),
            format!("npm/left-pad (git)|has_version|1.3.0|{at}{git}"),
            format!("npm/linked-dir (path)|part_of|checkout|{at}{link}"),
            format!("npm/linked-dir (path)|has_version|0.0.0|{at}{link}"),
            format!("npm/local-dir (path)|part_of|checkout|{at}{dir_key}"),
            format!("npm/local-dir (path)|has_version|1.0.0|{at}{dir_key}"),
            format!("npm/local-tool (path)|part_of|checkout|{at}{local}"),
            format!("npm/local-tool (path)|has_version|1.0.0|{at}{local}"),
            format!("npm/private-lib (other registry)|part_of|checkout|{at}private-lib@^2.0.0"),
            format!("npm/private-lib (other registry)|has_version|2.0.0|{at}private-lib@^2.0.0"),
            format!("npm/remote-tool (git)|part_of|checkout|{at}{remote}"),
            format!("npm/remote-tool (git)|has_version|1.0.0|{at}{remote}"),
            format!("npm/string-width|part_of|checkout|{at}{cjs}"),
            format!("npm/string-width|has_version|4.2.3|{at}{cjs}"),
            format!("npm/string-width|has_version|5.1.2|{at}{width}"),
        ];
        assert_eq!(said, expected);
        assert_eq!(o.reason, one_not_told("yarn.lock#dev-tool@^1.0.0"));
        // A git address by `git://` is git as one by `git+` is.
        let (said, _) = read_one(
            "yarn1-git",
            "yarn.lock",
            &YARN1.replace("resolved \"git+ssh://git@", "resolved \"git://"),
        );
        assert_eq!(said, expected);
    }

    #[test]
    fn a_yarn_1_entry_whose_package_cannot_be_told_is_never_guessed_and_makes_the_reading_partial()
    {
        // No false calm. Yarn installs whatever `resolved` names: an honest key and `version`
        // beside an address of another package or version is not the registry's package.
        let width = "string-width@^5.0.0, string-width@^5.1.2";
        let file = "string-width/-/string-width-5.1.2.tgz";
        let (lib, lib_key) = ("private-lib@^2.0.0:\n", "private-lib@^2.0.0");
        let link = "\"linked-dir@link:./vendor/linked-dir\"";
        for (from, to, key) in [
            (file, "evil-width/-/evil-width-5.1.2.tgz", width),
            (file, "string-width/-/string-width-5.1.1.tgz", width),
            ("  version \"5.1.2\"\n", "", width),
            // A name a registry decodes to another one.
            (
                "string-width@^5.0.0, string-width@^5.1.2:\n  version \"5.1.2\"\n  resolved \"https://registry.yarnpkg.com/string-width/-/string-width-5.1.2.tgz",
                "x%2Dy@^5.0.0, x%2Dy@^5.1.2:\n  version \"5.1.2\"\n  resolved \"https://registry.yarnpkg.com/x%2Dy/-/x%2Dy-5.1.2.tgz",
                "x%2Dy@^5.0.0, x%2Dy@^5.1.2",
            ),
            // Dot segments in the version: the address names another package's file.
            (
                "version \"5.1.2\"\n  resolved \"https://registry.yarnpkg.com/string-width/-/string-width-5.1.2.tgz",
                "version \"5.1.2/../../../other/-/other-2.0.0\"\n  resolved \"https://registry.yarnpkg.com/string-width/-/string-width-5.1.2/../../../other/-/other-2.0.0.tgz",
                width,
            ),
            // Where the address alone would tell: a `version` or a `name` that is not text, or
            // not a package's, and keys of two packages.
            ("version \"2.0.0\"", "version 5", lib_key),
            ("version \"2.0.0\"", "version \"\"", lib_key),
            (lib, "private-lib@^2.0.0:\n  name true\n", lib_key),
            (lib, "private-lib@^2.0.0:\n  name \"a b\"\n", lib_key),
            (lib, "private-lib@^2.0.0:\n  name \".x\"\n", lib_key),
            (lib, "private-lib@^2.0.0:\n  name \"_x\"\n", lib_key),
            (lib, "private-lib@^2.0.0:\n  name \"@x%2Dy/z\"\n", lib_key),
            (
                lib,
                "other-lib@^2.0.0, private-lib@^2.0.0:\n",
                "other-lib@^2.0.0, private-lib@^2.0.0",
            ),
            // No `resolved`, and a key that is not a path.
            (
                link,
                "\"linked-dir@link:./vendor/linked-dir\", linked-dir@^1",
                "linked-dir@link:./vendor/linked-dir, linked-dir@^1",
            ),
        ] {
            let text = YARN1.replace(from, to);
            assert_ne!(text, YARN1, "{to}");
            let (said, reason) = read_one("yarn1-not-told", "yarn.lock", &text);
            let at = format!("yarn.lock#{key}");
            assert!(!said.iter().any(|s| s.ends_with(&at)), "{to}: {said:?}");
            let others = "the package of 2 entries cannot be told: dev/shop/yarn.lock#";
            assert!(
                reason.as_deref().unwrap_or_default().starts_with(others),
                "{to}: {reason:?}"
            );
            assert!(reason.unwrap_or_default().contains(&at), "{to}");
        }
        // On another host the package is another registry's, under either registry's path.
        let (said, reason) = read_one(
            "yarn1-host",
            "yarn.lock",
            &YARN1.replace(
                "https://registry.yarnpkg.com/string",
                "https://registry.example.com/string",
            ),
        );
        let fact = format!(
            "npm/string-width (other registry)|has_version|5.1.2|dev/shop/yarn.lock#{width}"
        );
        assert!(said.contains(&fact), "{said:?}");
        assert_eq!(reason, one_not_told("yarn.lock#dev-tool@^1.0.0"));
    }

    #[test]
    fn a_yarn_1_alias_is_the_package_its_range_or_name_field_names_when_resolved_is_its_file() {
        // Yarn 1 groups the keys that resolve to one package and writes `name` only for the
        // first when its name differs, so a group of a plain key and an alias has none. The
        // package is the one the alias names, and still only as `resolved` names its file.
        let file = "  version \"1.0.0\"\n  resolved \"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz#0123456789abcdef\"\n";
        let header = "# yarn lockfile v1\n\n\n";
        for (key, extra) in [
            ("widget@^1, \"zcopy@npm:widget@^1\"", ""),
            ("\"zcopy@npm:widget@^1\"", ""),
            ("\"zcopy@^1\"", "  name widget\n"),
        ] {
            let text = format!("{header}{key}:\n{extra}{file}");
            let (said, reason) = read_one("yarn1-alias", "yarn.lock", &text);
            let at = key.replace('"', "");
            let fact = format!("npm/widget|has_version|1.0.0|dev/shop/yarn.lock#{at}");
            assert_eq!(said.get(1), Some(&fact), "{key}: {said:?}");
            assert_eq!(reason, None, "{key}");
        }
        // An alias whose `resolved` is another package's file is not told.
        let text = format!(
            "{header}\"zcopy@npm:widget@^1\":\n{}",
            file.replace("widget/-/widget", "gadget/-/gadget")
        );
        let (said, reason) = read_one("yarn1-alias-other", "yarn.lock", &text);
        assert!(said.is_empty(), "{said:?}");
        assert_eq!(reason, one_not_told("yarn.lock#zcopy@npm:widget@^1"));
    }
}
