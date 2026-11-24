//! The reader of `bun.lock`, Bun's lockfile in text.

use super::{At, Dep, GIT, NPM_REGISTRY, Parsed, Source, WEB, npm_name, registry_tarball};

/// `bun.lock`, lockfile versions 0 to 3, whose rows of packages Bun writes in one shape: JSON
/// with comments and trailing commas, read by `jsonc`, which allows nothing else. A key given
/// twice with two values anywhere fails the reading, and so does a missing `packages` while a
/// workspace declares a dependency. `packages` maps an install path to a row whose first item is
/// `<name>@<resolution>`: the package is that, never the key. An npm row's second item is its
/// address, empty for the registry the project is set up with, which is taken for the public one
/// as for pnpm. `workspaces` is read only for whether it declares a dependency; `overrides`,
/// `catalog`, `catalogs`, `patchedDependencies` and `trustedDependencies` add no package and are
/// not read.
pub(super) fn bun(text: &str) -> Parsed {
    let Ok(crate::jsonc::Read {
        value: Some(lock),
        doubts,
        ..
    }) = crate::jsonc::read(text.as_bytes(), true)
    else {
        return Parsed::Failed;
    };
    match lock.get("lockfileVersion").and_then(|v| v.as_u64()) {
        _ if !doubts.is_empty() => return Parsed::Failed,
        Some(0..=3) => {}
        Some(n) => return Parsed::NoReader(format!("bun.lock version {n}")),
        None => return Parsed::Failed,
    }
    // Bun refuses a file without `workspaces`. It writes no `packages` when there is none, which
    // holds only while no workspace declares a dependency.
    let Some(workspaces) = lock.get("workspaces").and_then(|w| w.as_object()) else {
        return Parsed::Failed;
    };
    let declares = |w: &serde_json::Value| {
        [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ]
        .iter()
        .any(|f| {
            w.get(f)
                .is_some_and(|d| d.as_object().is_none_or(|d| !d.is_empty()))
        })
    };
    let empty = serde_json::Map::new();
    let packages = match lock.get("packages") {
        Some(serde_json::Value::Object(p)) => p,
        None if !workspaces.values().any(declares) => &empty,
        _ => return Parsed::Failed,
    };
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    for (key, row) in packages {
        match bun_row(key, row) {
            Some(Some(dep)) => out.push(dep),
            Some(None) => {}
            None => unknown.push(key.clone()),
        }
    }
    Parsed::Deps("npm", out, unknown)
}

/// One row of `bun.lock`'s `packages`: `Some(None)` for a workspace or the root, which are the
/// project itself, and `None` when the row does not tell what it is. The name ends at the first
/// `@` after its first character, since a package's name holds none there and an address may.
/// An npm row is the registry's when its address is empty or the registry's file of that name
/// and version (`registry_tarball`).
fn bun_row(key: &str, row: &serde_json::Value) -> Option<Option<Dep>> {
    let row = row.as_array()?;
    let first = row.first()?.as_str()?;
    let at = first.get(1..)?.find('@')? + 1;
    let (name, resolution) = (&first[..at], &first[at + 1..]);
    // The project itself, whatever it is named.
    if resolution.starts_with("workspace:") || resolution.starts_with("root:") {
        return Some(None);
    }
    if !npm_name(name) {
        return None;
    }
    let mut version = None;
    let source = match resolution {
        r if r.starts_with("file:") || r.starts_with("link:") => Source::Path,
        r if GIT.iter().any(|p| r.starts_with(p)) => Source::Git,
        r if WEB.iter().any(|p| r.starts_with(p)) => Source::OtherRegistry,
        r if semver::Version::parse(r).is_ok() => {
            version = Some(r.to_string());
            match row.get(1)?.as_str()? {
                "" => Source::Registry,
                address => match address.strip_prefix(NPM_REGISTRY) {
                    Some(path) if registry_tarball(path, name, r) => Source::Registry,
                    Some(_) => return None,
                    None => Source::OtherRegistry,
                },
            }
        }
        // A tarball on disk, by its path.
        r if r.ends_with(".tgz") => Source::Path,
        _ => return None,
    };
    Some(Some(Dep {
        at: At::Key(key.to_string()),
        name: name.to_string(),
        version,
        source,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::LOCKFILE_KIND;
    use super::super::tests::{BUN, Dir, lacks, one_not_told, read_one, unknown_for};

    #[test]
    fn a_bun_row_is_the_package_its_first_item_names_and_says_where_it_comes_from() {
        // The name ends at the first `@` after its first character, so a git address holding
        // `git@` stays the address. Only an npm row with no address or the registry's own file
        // carries the bare name an advisory gives. A workspace and the root are the project.
        let dir = Dir::new("bun", &[("bun.lock", BUN)]);
        let (o, said) = dir.read();
        let at = "dev/shop/bun.lock#";
        let expected = [
            format!("npm/@jrichman/ink|part_of|checkout|{at}ink"),
            format!("npm/@jrichman/ink|has_version|6.4.6|{at}ink"),
            format!("npm/dev-tool (path)|part_of|checkout|{at}dev-tool"),
            format!("npm/left-pad (git)|part_of|checkout|{at}left-pad"),
            format!("npm/local-dir (path)|part_of|checkout|{at}local-dir"),
            format!("npm/local-tool (path)|part_of|checkout|{at}local-tool"),
            format!("npm/private-lib (other registry)|part_of|checkout|{at}private-lib"),
            format!("npm/private-lib (other registry)|has_version|2.0.0|{at}private-lib"),
            format!("npm/remote-tool (other registry)|part_of|checkout|{at}remote-tool"),
            format!("npm/string-width|part_of|checkout|{at}string-width"),
            format!("npm/string-width|has_version|4.2.3|{at}string-width-cjs"),
            format!("npm/string-width|has_version|5.1.2|{at}string-width"),
            format!("npm/strip-ansi|part_of|checkout|{at}string-width-cjs/strip-ansi"),
            format!("npm/strip-ansi|has_version|6.0.1|{at}string-width-cjs/strip-ansi"),
            format!("npm/tool-git (git)|part_of|checkout|{at}tool-git"),
        ];
        assert_eq!(said, expected);
        assert_eq!((o.completeness, o.reason), ("full", None));
        // A tarball by `http://` is another registry's as one by `https://` is.
        let http = BUN.replace("[\"remote-tool@https://", "[\"remote-tool@http://");
        let (said, reason) = read_one("bun-http", "bun.lock", &http);
        assert_eq!((said, reason), (expected.to_vec(), None));
    }

    #[test]
    fn a_bun_row_whose_package_cannot_be_told_is_never_guessed_and_makes_the_reading_partial() {
        // No false calm: the registry's address of another version's or another package's file,
        // an address that is not text, and a row of a shape Bun does not write.
        let strip = "[\"strip-ansi@6.0.1\", \"https://registry.npmjs.org/strip-ansi/-/strip-ansi-6.0.1.tgz\"";
        let width = "[\"string-width@5.1.2\", \"\"";
        for (from, to, key) in [
            (
                strip,
                "[\"strip-ansi@6.0.1\", \"https://registry.npmjs.org/strip-ansi/-/strip-ansi-6.0.0.tgz\"",
                "string-width-cjs/strip-ansi",
            ),
            (
                strip,
                "[\"strip-ansi@6.0.1\", \"https://registry.npmjs.org/strip-ansi/-/ansi-regex-6.0.1.tgz\"",
                "string-width-cjs/strip-ansi",
            ),
            (width, "[\"string-width@5.1.2\", null", "string-width"),
            (width, "[\"string-width@^5.1.2\", \"\"", "string-width"),
            (width, "[\"string-width\", \"\"", "string-width"),
            (width, "[\"string width@5.1.2\", \"\"", "string-width"),
            (width, "[5, \"\"", "string-width"),
            (
                "\"string-width\": [\"string-width@5.1.2\", \"\", {}, \"sha512-CCCC\"]",
                "\"string-width\": {}",
                "string-width",
            ),
            (
                "[\"string-width@5.1.2\", \"\", {}, \"sha512-CCCC\"]",
                "[\"string-width@5.1.2\"]",
                "string-width",
            ),
        ] {
            let (said, reason) = read_one("bun-not-told", "bun.lock", &BUN.replace(from, to));
            let at = format!("bun.lock#{key}");
            assert!(!said.iter().any(|s| s.ends_with(&at)), "{to}: {said:?}");
            assert_eq!(reason, one_not_told(&at), "{to}");
        }
    }

    #[test]
    fn a_bun_lockfile_bun_would_not_read_as_written_is_a_failed_reading() {
        // A key given twice anywhere is read one way by a reader that keeps the first and another
        // by one that keeps the last. Bun allows comments and trailing commas and nothing else.
        let ink = "\"ink\": [\"@jrichman/ink@6.4.6\"";
        for (tag, text) in [
            (
                "bun-twice",
                BUN.replace(ink, &format!("\"ink\": [\"ink@1.0.0\", \"\"],\n    {ink}")),
            ),
            (
                "bun-twice-top",
                BUN.replace(
                    "\"lockfileVersion\": 1,",
                    "\"lockfileVersion\": 1, \"lockfileVersion\": 9,",
                ),
            ),
            (
                "bun-twice-info",
                BUN.replace(
                    "{ \"string-width\": \"^5.1.2\" }",
                    "{ \"string-width\": \"^5.1.2\", \"string-width\": \"^4.0.0\" }",
                ),
            ),
            (
                "bun-quotes",
                BUN.replace("\"sha512-AAAA\"", "'sha512-AAAA'"),
            ),
            ("bun-no-version", BUN.replace("\"lockfileVersion\": 1,", "")),
            (
                "bun-version-text",
                BUN.replace("\"lockfileVersion\": 1,", "\"lockfileVersion\": \"1\","),
            ),
            (
                "bun-no-workspaces",
                BUN.replace("\"workspaces\"", "\"members\""),
            ),
            (
                "bun-packages-list",
                "{\"lockfileVersion\": 1, \"workspaces\": {}, \"packages\": []}".to_string(),
            ),
            ("bun-empty", String::new()),
        ] {
            let (said, reason) = read_one(tag, "bun.lock", &text);
            assert!(said.is_empty(), "{tag}: {said:?}");
            assert_eq!(
                reason.as_deref(),
                Some("could not be read: bun.lock"),
                "{tag}"
            );
        }
        // With no package, Bun writes no `packages`, and that is read as none. While a workspace
        // declares a dependency, a missing `packages` would leave it in no fact: not read.
        let workspace = |more: &str| {
            format!(
                "{{\"lockfileVersion\": 1, \"workspaces\": {{\"\": {{\"name\": \"shop\"}}, \"packages/ui\": {{\"name\": \"ui\"{more}}}}}}}"
            )
        };
        for more in ["", ", \"dependencies\": {}"] {
            let (said, reason) = read_one("bun-no-packages", "bun.lock", &workspace(more));
            assert_eq!((said.len(), reason), (0, None), "{more}");
        }
        for field in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            for map in ["{\"left-pad\": \"^1.3.0\"}", "\"left-pad\""] {
                let (said, reason) = read_one(
                    "bun-no-packages-declared",
                    "bun.lock",
                    &workspace(&format!(", \"{field}\": {map}")),
                );
                assert!(said.is_empty(), "{field}");
                assert_eq!(
                    reason.as_deref(),
                    Some("could not be read: bun.lock"),
                    "{field} {map}"
                );
            }
        }
    }

    #[test]
    fn a_bun_lockfile_of_a_version_not_read_here_is_named_as_a_kind_without_a_reader() {
        // Versions 0 to 3 write rows of one shape; a later one is named and leaves npm unknown.
        for version in [0, 2, 3] {
            let text = BUN.replace(
                "\"lockfileVersion\": 1,",
                &format!("\"lockfileVersion\": {version},"),
            );
            let (said, reason) = read_one("bun-read", "bun.lock", &text);
            assert_eq!((said.len(), reason), (15, None), "{version}");
        }
        let text = BUN.replace("\"lockfileVersion\": 1,", "\"lockfileVersion\": 4,");
        let dir = Dir::new("bun-4", &[("bun.lock", &text)]);
        let (o, said) = dir.read();
        assert!(said.is_empty());
        assert_eq!(lacks(&o), [format!("{LOCKFILE_KIND} bun.lock version 4")]);
        assert_eq!(unknown_for(&o), [true, false]);
    }
}
