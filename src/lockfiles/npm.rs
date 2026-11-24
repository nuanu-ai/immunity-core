//! The reader of `package-lock.json` and `npm-shrinkwrap.json`.

use super::{At, Dep, GIT, NPM_REGISTRY, Parsed, Source, npm_name, registry_tarball};

/// `package-lock.json` or `npm-shrinkwrap.json`, the `kind`, lockfile versions 2 and 3: the
/// `packages` map. The root entry and workspace folders are the project itself and are skipped.
/// Version 1 has no such map and no reader here; it is named as a kind of lockfile without one.
pub(super) fn npm(text: &str, kind: &str) -> Parsed {
    let Ok(lock) = serde_json::from_str::<serde_json::Value>(text) else {
        return Parsed::Failed;
    };
    match lock.get("lockfileVersion").and_then(|v| v.as_u64()) {
        Some(2 | 3) => {}
        Some(n) => return Parsed::NoReader(format!("{kind} version {n}")),
        None => return Parsed::Failed,
    }
    let Some(packages) = lock.get("packages").and_then(|p| p.as_object()) else {
        return Parsed::Failed;
    };
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    for (key, entry) in packages {
        let Some(i) = key.rfind("node_modules/") else {
            continue;
        };
        match npm_entry(key, &key[i + "node_modules/".len()..], entry, packages) {
            Some(dep) => out.push(dep),
            None => unknown.push(key.clone()),
        }
    }
    Parsed::Deps("npm", out, unknown)
}

/// One entry under `node_modules`, or `None` when the lockfile does not tell what it is: a
/// name that is not a package's, no version, or a registry address that is not the file of the
/// entry's name and `version` (`registry_tarball`).
fn npm_entry(
    key: &str,
    installed_as: &str,
    entry: &serde_json::Value,
    packages: &serde_json::Map<String, serde_json::Value>,
) -> Option<Dep> {
    let text = |field: &str| match entry.get(field) {
        None => Some(None),
        Some(v) => v.as_str().map(Some),
    };
    // An alias is installed under its own name and records the package in `name`.
    let name = text("name")?.unwrap_or(installed_as);
    let resolved = text("resolved")?;
    if !npm_name(name) {
        return None;
    }
    let link = entry.get("link").and_then(|l| l.as_bool()) == Some(true);
    let source = match resolved {
        _ if link => Source::Path,
        None => Source::Registry,
        Some(r) if r.starts_with(NPM_REGISTRY) => Source::Registry,
        Some(r) if GIT.iter().any(|p| r.starts_with(p)) => Source::Git,
        Some(r) if r.starts_with("file:") => Source::Path,
        // Another registry, a tarball's address, or an address of a kind not known here:
        // whatever it is, it is not the public registry.
        Some(_) => Source::OtherRegistry,
    };
    let version = match text("version")? {
        Some("") => return None,
        Some(v) => Some(v.to_string()),
        // A link points at a folder of the project, whose entry carries the version if any.
        None if link => resolved
            .and_then(|target| packages.get(target))
            .and_then(|t| t.get("version"))
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        None => return None,
    };
    // A registry address that is not the file of this name and version means the entry is not
    // what it says.
    if let Some(path) = resolved
        .filter(|_| source == Source::Registry)
        .and_then(|r| r.strip_prefix(NPM_REGISTRY))
        && !version
            .as_deref()
            .is_some_and(|v| registry_tarball(path, name, v))
    {
        return None;
    }
    Some(Dep {
        at: At::Key(key.to_string()),
        name: name.to_string(),
        version,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::super::LOCKFILE_KIND;
    use super::super::tests::{Dir, NPM, lacks, one_not_told, read_one, unknown_for};
    use crate::store::Cause;

    #[test]
    fn an_npm_entry_is_named_by_the_package_it_is_and_says_where_it_comes_from() {
        // An alias installed as `string-width-cjs` is string-width, and only an entry from the
        // public registry carries the bare name an advisory gives: a package from git, a file,
        // a link or another registry is a component of its own, never the registry's one.
        let dir = Dir::new("npm", &[("package-lock.json", NPM)]);
        let (o, said) = dir.read();
        let at = "dev/shop/package-lock.json#node_modules";
        let expected = [
            format!("npm/@jrichman/ink|part_of|checkout|{at}/ink"),
            format!("npm/@jrichman/ink|has_version|6.4.6|{at}/ink"),
            format!("npm/@shop/ui (path)|part_of|checkout|{at}/@shop/ui"),
            format!("npm/@shop/ui (path)|has_version|0.1.0|{at}/@shop/ui"),
            format!("npm/abbrev|part_of|checkout|{at}/npm-bundler/node_modules/abbrev"),
            format!("npm/abbrev|has_version|1.1.1|{at}/npm-bundler/node_modules/abbrev"),
            format!("npm/left-pad (git)|part_of|checkout|{at}/left-pad"),
            format!("npm/left-pad (git)|has_version|1.3.0|{at}/left-pad"),
            format!("npm/local-tool (path)|part_of|checkout|{at}/local-tool"),
            format!("npm/local-tool (path)|has_version|1.0.0|{at}/local-tool"),
            format!("npm/npm-bundler|part_of|checkout|{at}/npm-bundler"),
            format!("npm/npm-bundler|has_version|2.0.0|{at}/npm-bundler"),
            format!("npm/private-lib (other registry)|part_of|checkout|{at}/private-lib"),
            format!("npm/private-lib (other registry)|has_version|2.0.0|{at}/private-lib"),
            format!("npm/string-width|part_of|checkout|{at}/string-width"),
            format!("npm/string-width|has_version|4.2.3|{at}/string-width-cjs"),
            format!("npm/string-width|has_version|5.1.2|{at}/string-width"),
        ];
        assert_eq!(said, expected);
        assert_eq!((o.completeness, o.reason), ("full", None));
    }

    #[test]
    fn an_npm_entry_whose_package_cannot_be_told_is_never_guessed_and_makes_the_reading_partial() {
        // An alias written without the package's name would be taken for a package of the
        // alias's name, which anyone may register. Left out, it must not let the reading
        // say the package is absent.
        let unknown = NPM
            .replace(
                "\"node_modules/string-width-cjs\": {\n      \"name\": \"string-width\",",
                "\"node_modules/string-width-cjs\": {",
            )
            .replace(
                "\"node_modules/left-pad\": {\n      \"version\": \"1.3.0\",",
                "\"node_modules/left-pad\": {",
            )
            .replace(
                "\"name\": \"@jrichman/ink\"",
                "\"name\": \"@jrichman/ink 2\"",
            );
        let dir = Dir::new("npm-unknown", &[("package-lock.json", &unknown)]);
        let (o, said) = dir.read();
        for gone in ["string-width-cjs", "left-pad", "ink"] {
            assert!(!said.iter().any(|s| s.contains(gone)), "{gone}: {said:?}");
        }
        assert!(said.contains(
            &"npm/string-width|has_version|5.1.2|dev/shop/package-lock.json#node_modules/string-width"
                .to_string()
        ));
        assert_eq!(o.completeness, "partial");
        assert_eq!(o.gap.cause, Some(Cause::NotGiven));
        assert_eq!(
            o.reason.as_deref(),
            Some(
                "the package of 3 entries cannot be told: \
                 dev/shop/package-lock.json#node_modules/ink, \
                 dev/shop/package-lock.json#node_modules/left-pad, \
                 dev/shop/package-lock.json#node_modules/string-width-cjs"
            )
        );
    }

    #[test]
    fn an_npm_lockfile_of_version_1_is_named_as_a_kind_without_a_reader() {
        // Version 1 records aliases and git sources as versions; it is not read, and says so
        // by name, like any lockfile kind without a reader, so nothing is taken as absent.
        let v1 = r#"{"name": "old", "lockfileVersion": 1, "requires": true,
                     "dependencies": {"left-pad": {"version": "1.3.0"}}}"#;
        let dir = Dir::new("npm-v1", &[("package-lock.json", v1)]);
        let (o, said) = dir.read();
        assert!(said.is_empty());
        assert_eq!(o.completeness, "partial");
        assert_eq!(o.gap.cause, Some(Cause::NoReader));
        assert_eq!(
            o.gap.lacks[0].name.as_deref(),
            Some("package-lock.json version 1")
        );
        assert_eq!(
            o.reason.as_deref(),
            Some("not supported yet: package-lock.json version 1")
        );
    }

    #[test]
    fn an_npm_entry_is_the_registrys_only_when_its_address_names_its_package_and_version() {
        // No false calm. npm fetches what `resolved` names: an honest `version` beside the
        // address of another version's file, of another package's file in the right folder, or
        // with more after `.tgz` would answer for a version that may not be installed. Such an
        // entry is not told and the reading is partial. A scoped package's file carries its name
        // without the scope, as `ink-6.4.6.tgz` in `NPM`.
        let width = "string-width/-/string-width-5.1.2.tgz";
        let ink = "@jrichman/ink/-/ink-6.4.6.tgz";
        for (from, to, key) in [
            (
                width,
                "string-width/-/string-width-5.0.0.tgz",
                "string-width",
            ),
            (width, "string-width/-/strip-ansi-5.1.2.tgz", "string-width"),
            (
                width,
                "string-width/-/string-width-5.1.2.tgz?v=5",
                "string-width",
            ),
            (ink, "@jrichman/ink/-/ink-6.4.5.tgz", "ink"),
        ] {
            let dir = Dir::new(
                "npm-address",
                &[("package-lock.json", &NPM.replace(from, to))],
            );
            let (o, said) = dir.read();
            let at = format!("package-lock.json#node_modules/{key}");
            assert!(!said.iter().any(|s| s.ends_with(&at)), "{to}: {said:?}");
            assert_eq!(o.reason, one_not_told(&at), "{to}");
        }
        // A `version` with dot segments makes an address that names the package as text and
        // another package's file once a client resolves it.
        let dots = "5.1.2/../../../other/-/other-2.0.0";
        let text = NPM.replace(
            "\"version\": \"5.1.2\",\n      \"resolved\": \"https://registry.npmjs.org/string-width/-/string-width-5.1.2.tgz\"",
            &format!("\"version\": \"{dots}\",\n      \"resolved\": \"https://registry.npmjs.org/string-width/-/string-width-{dots}.tgz\""),
        );
        assert_ne!(text, NPM);
        let (said, reason) = read_one("npm-dots", "package-lock.json", &text);
        let at = "package-lock.json#node_modules/string-width";
        assert!(!said.iter().any(|s| s.ends_with(at)), "{said:?}");
        assert_eq!(reason, one_not_told(at));
        // A name a registry decodes to another one: `x%2Dy` is served as `x-y`.
        let text = NPM.replace(
            "    \"node_modules/string-width\": {",
            "    \"node_modules/x%2Dy\": {\n      \"version\": \"1.0.0\",\n      \"resolved\": \"https://registry.npmjs.org/x%2Dy/-/x%2Dy-1.0.0.tgz\"\n    },\n    \"node_modules/string-width\": {",
        );
        assert_ne!(text, NPM);
        let (said, reason) = read_one("npm-encoded", "package-lock.json", &text);
        let at = "package-lock.json#node_modules/x%2Dy";
        assert!(!said.iter().any(|s| s.ends_with(at)), "{said:?}");
        assert_eq!(reason, one_not_told(at));
    }

    #[test]
    fn an_npm_shrinkwrap_of_version_1_is_named_by_its_own_name_and_leaves_only_npm_unknown() {
        let v1 = r#"{"name": "old", "lockfileVersion": 1, "requires": true,
                     "dependencies": {"left-pad": {"version": "1.3.0"}}}"#;
        let dir = Dir::new("shrinkwrap-v1", &[("npm-shrinkwrap.json", v1)]);
        let (o, said) = dir.read();
        assert!(said.is_empty());
        assert_eq!(
            lacks(&o),
            [format!("{LOCKFILE_KIND} npm-shrinkwrap.json version 1")]
        );
        assert_eq!(
            o.reason.as_deref(),
            Some("not supported yet: npm-shrinkwrap.json version 1")
        );
        assert_eq!(unknown_for(&o), [true, false]);
    }
}
