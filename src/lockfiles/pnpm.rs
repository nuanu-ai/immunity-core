//! The reader of `pnpm-lock.yaml`, in the formats 5.x, 6.0 and 9.0.

use super::{At, Dep, NPM_REGISTRY, Parsed, Source, npm_name, registry_tarball, version_shape};

/// The shapes of `pnpm-lock.yaml` read here, as pnpm's own specification describes them: the
/// documents `lockfile/5.md`, `5.2.md`, `6.0.md`, `9.0.md` and `dependency-path.md` of
/// github.com/pnpm/spec at commit 834f2815, with what the specification leaves out taken from
/// pnpm's code: `@pnpm/dependency-path` and `nameVerFromPkgSnapshot` of pnpm 8.15.9 for 5.x and
/// 6.0, and of pnpm 11 (`deps/path`, `lockfile/utils`, `lockfile/types`) for 9.0.
#[derive(Clone, Copy, PartialEq)]
enum PnpmFormat {
    /// 5.0 to 5.4 (pnpm 3 to 7). A key is `/<name>/<version>`, a peer suffix after `_`; a key
    /// without the leading slash names a host or a source other than the registry.
    V5,
    /// 6.0 (pnpm 8). A key is `/<name>@<version>`, a peer suffix in parentheses.
    V6,
    /// 9.0 (pnpm 9 to 11). A key of `packages` is `<name>@<version or source>`; `snapshots`
    /// holds each package as installed, its key with a peer suffix in parentheses.
    V9,
}

/// `pnpm-lock.yaml`: every entry of `packages`, by the package it is, and every `link:` among
/// the dependencies of the projects. Every document of the file is read, since pnpm 11 may put
/// the packages of its own configuration in a first one. A version of the format not listed in
/// `PnpmFormat` has no reader here and is named as a kind of lockfile without one. A `link:`
/// among a package's own dependencies (5.2 and later) is not recorded: it names a folder on
/// disk, never a package from a registry.
///
/// pnpm does not write which registry a package came from: an entry the registry served carries
/// only its `integrity`, and pnpm fetches it from the registry the project is set up with. Such
/// an entry is taken as the public registry's, as npm's own lockfile is read for an entry with no
/// address; one whose key names a host, in 5.x and 6.0, is another registry's.
pub(super) fn pnpm(text: &str) -> Parsed {
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    // An empty file is one empty document, which has no version.
    for document in serde_norway::Deserializer::from_str(text) {
        // serde_norway's own pass-through helper turns a document into a value, so that serde
        // itself need not be named here.
        let Ok(lock) =
            serde_norway::with::singleton_map::deserialize::<serde_norway::Value, _>(document)
        else {
            return Parsed::Failed;
        };
        let version = match lock.get("lockfileVersion") {
            Some(serde_norway::Value::String(v)) => v.clone(),
            Some(serde_norway::Value::Number(n)) => n.to_string(),
            _ => return Parsed::Failed,
        };
        let format = match version.as_str() {
            "5" | "5.1" | "5.2" | "5.3" | "5.4" => PnpmFormat::V5,
            "6.0" => PnpmFormat::V6,
            "9.0" => PnpmFormat::V9,
            v if version_shape(v) => {
                return Parsed::NoReader(format!("pnpm-lock.yaml version {v}"));
            }
            _ => return Parsed::Failed,
        };
        if pnpm_document(&lock, format, &mut out, &mut unknown).is_none() {
            return Parsed::Failed;
        }
    }
    Parsed::Deps("npm", out, unknown)
}

/// One document of `pnpm-lock.yaml`; `None` when it is not in the shape of its version.
fn pnpm_document(
    lock: &serde_norway::Value,
    format: PnpmFormat,
    out: &mut Vec<Dep>,
    unknown: &mut Vec<String>,
) -> Option<()> {
    // A map that may be left out, and when there must be a map.
    let map = |field: &str| match lock.get(field) {
        None => Some(None),
        Some(v) => v.as_mapping().map(Some),
    };
    let packages = map("packages")?;
    let snapshots = map("snapshots")?;
    let importers = map("importers")?;
    // pnpm 9 and later write `importers` even for a project with no dependencies.
    if format == PnpmFormat::V9 && importers.is_none() {
        return None;
    }
    for (key, entry) in packages.into_iter().flatten() {
        let key = key.as_str().unwrap_or_default();
        match pnpm_package(format, key, entry) {
            Some(dep) => out.push(dep),
            None => unknown.push(key.to_string()),
        }
        // pnpm writes the names of the packages bundled inside one, never their versions.
        match entry.get("bundledDependencies") {
            None => {}
            Some(serde_norway::Value::Sequence(names)) => unknown.extend(names.iter().map(|n| {
                format!(
                    "{key}/bundledDependencies/{}",
                    n.as_str().unwrap_or_default()
                )
            })),
            Some(_) => unknown.push(format!("{key}/bundledDependencies")),
        }
    }
    // In 9.0 a package as installed is an entry of `snapshots`, its key the key of its entry
    // in `packages` and its peers in parentheses. One with no entry there is not described.
    for key in snapshots.into_iter().flat_map(|s| s.keys()) {
        let key = key.as_str().unwrap_or_default();
        let described = |id: &str| packages.is_some_and(|p| p.contains_key(id));
        if !described(key) && !key.match_indices('(').any(|(i, _)| described(&key[..i])) {
            unknown.push(key.to_string());
        }
    }
    match importers {
        Some(importers) => {
            for (id, importer) in importers {
                let id = id.as_str().unwrap_or_default();
                pnpm_links(&format!("importers/{id}/"), importer, out, unknown);
            }
        }
        // A lockfile of 5.x or 6.0 for a single project lists its dependencies at the top.
        None => pnpm_links("", lock, out, unknown),
    }
    Some(())
}

/// One entry of `packages`, or `None` when the lockfile does not tell what it is: a name that is
/// not a package's, no version, a name or a version its key and its field disagree on, no resolution,
/// or a registry address that is not the file of the entry's name and version
/// (`registry_tarball`).
fn pnpm_package(format: PnpmFormat, key: &str, entry: &serde_norway::Value) -> Option<Dep> {
    fn text<'a>(v: &'a serde_norway::Value, field: &str) -> Option<Option<&'a str>> {
        match v.get(field) {
            None => Some(None),
            Some(v) => v.as_str().map(Some),
        }
    }
    let (key_name, key_version) = pnpm_key(format, key);
    let name = match (text(entry, "name")?, key_name) {
        (Some(field), Some(key)) if field != key => return None,
        (Some(name), _) | (None, Some(name)) => name,
        (None, None) => return None,
    };
    if !npm_name(name) {
        return None;
    }
    let version = match (text(entry, "version")?, key_version) {
        (Some(""), _) => return None,
        (Some(field), Some(key)) if field != key => return None,
        (Some(version), _) | (None, Some(version)) => version,
        (None, None) => return None,
    };
    let resolution = entry.get("resolution")?;
    // A key that does not start with a slash, in 5.x and 6.0, names a host or a source.
    let configured = if format != PnpmFormat::V9 && !key.starts_with('/') {
        Source::OtherRegistry
    } else {
        Source::Registry
    };
    let source = match (text(resolution, "type")?, text(resolution, "tarball")?) {
        (Some("git"), _) => Source::Git,
        (Some("directory"), _) => Source::Path,
        // A binary, a runtime or a custom resolver's: not the public registry.
        (Some(_), _) => Source::OtherRegistry,
        (None, Some(t)) if t.starts_with("file:") => Source::Path,
        // An archive of a commit from the git hosts pnpm knows.
        (None, Some(t))
            if [
                "https://codeload.github.com/",
                "https://gitlab.com/",
                "https://bitbucket.org/",
            ]
            .iter()
            .any(|p| t.starts_with(p)) =>
        {
            Source::Git
        }
        (None, Some(t)) if t.starts_with(NPM_REGISTRY) => {
            if !registry_tarball(&t[NPM_REGISTRY.len()..], name, version) {
                return None;
            }
            Source::Registry
        }
        (None, Some(t)) if t.contains("://") => Source::OtherRegistry,
        // `integrity` alone: the registry the project is set up with.
        (None, None) if resolution.get("integrity").is_some() => configured,
        // An address of a kind not known here, or nothing to fetch the package by.
        _ => return None,
    };
    Some(Dep {
        at: At::Key(key.to_string()),
        name: name.to_string(),
        version: Some(version.to_string()),
        source,
    })
}

/// The name and version a key of `packages` carries, as pnpm's `dependency-path` parses it for
/// the format: the version without its peer suffix, and only when it is SemVer. A key of 9.0
/// always names the package; one of 5.x or 6.0 only with a SemVer version, after the host or
/// source it starts with when it does not start with a slash, as `github.com/<owner>/<repo>/<commit>`
/// names none.
fn pnpm_key(format: PnpmFormat, key: &str) -> (Option<&str>, Option<&str>) {
    let path = match (format, key.strip_prefix('/')) {
        (PnpmFormat::V9, _) => key,
        (_, Some(path)) => path,
        (_, None) => key.split_once('/').map_or("", |(_, path)| path),
    };
    let at = match format {
        PnpmFormat::V5 => {
            // `<name>/<version>`, a scoped name holding one slash itself.
            let skip = if path.starts_with('@') {
                path.find('/').map_or(0, |i| i + 1)
            } else {
                0
            };
            path[skip..].find('/').map(|i| i + skip)
        }
        _ => path.get(1..).and_then(|p| p.find('@')).map(|i| i + 1),
    };
    let Some(at) = at else {
        return (None, None);
    };
    // A peer suffix is in parentheses, or after `_` in 5.x; neither can be part of SemVer.
    let version = path[at + 1..].split(['(', '_']).next().unwrap_or_default();
    match semver::Version::parse(version) {
        Ok(_) => (Some(&path[..at]), Some(version)),
        Err(_) if format == PnpmFormat::V9 => (Some(&path[..at]), None),
        Err(_) => (None, None),
    }
}

/// The `link:` dependencies of a project: a folder on disk, which no entry of `packages`
/// describes. Every other reference is to an entry of `packages`. A workspace package taken
/// under another name, `workspace:<name>@<range>`, is that package. A reference that is not
/// text cannot be told.
fn pnpm_links(
    at: &str,
    holder: &serde_norway::Value,
    out: &mut Vec<Dep>,
    unknown: &mut Vec<String>,
) {
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(deps) = holder.get(field).and_then(|d| d.as_mapping()) else {
            continue;
        };
        for (installed_as, reference) in deps {
            let installed_as = installed_as.as_str().unwrap_or_default();
            let at = format!("{at}{field}/{installed_as}");
            // 5.x and a package's own: the reference as text, with the project's specifiers
            // beside; 6.0 and 9.0 projects: `{specifier, version}`.
            let (version, specifier) = match reference.as_mapping() {
                Some(r) => (r.get("version"), r.get("specifier")),
                None => (
                    Some(reference),
                    holder.get("specifiers").and_then(|s| s.get(installed_as)),
                ),
            };
            let Some(version) = version.and_then(|v| v.as_str()) else {
                unknown.push(at);
                continue;
            };
            if !version.starts_with("link:") {
                continue;
            }
            let name = specifier
                .and_then(|s| s.as_str())
                .and_then(|s| s.strip_prefix("workspace:"))
                .and_then(|s| s.get(1..)?.find('@').map(|i| &s[..=i]))
                .unwrap_or(installed_as);
            if !npm_name(name) {
                unknown.push(at);
                continue;
            }
            out.push(Dep {
                at: At::Key(at),
                name: name.to_string(),
                version: None,
                source: Source::Path,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Dir, PNPM_9, one_not_told};
    use crate::store::Cause;

    /// A `pnpm-lock.yaml` of version 5.4 as pnpm 7 writes it for a workspace: keys
    /// `/<name>/<version>`, a peer suffix after `_`, specifiers apart from the references, a
    /// workspace package taken under another name, and every source an entry can come from.
    /// Names and addresses other than the public registry's are invented.
    const PNPM_5: &str = r#"lockfileVersion: 5.4

importers:

  .:
    specifiers:
      '@types/node': ^20.14.10
      fsevents: ^2.3.3
      left-pad: github:example/left-pad
      local-dir: file:vendor/local-dir
      local-tool: file:vendor/local-tool-1.0.0.tgz
      ms: ^2.1.3
      ms-legacy: npm:ms@2.0.0
      private-lib: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz
      react: ^18.3.1
      react-dom: ^18.3.1
    dependencies:
      left-pad: github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567
      local-dir: file:vendor/local-dir
      local-tool: file:vendor/local-tool-1.0.0.tgz
      ms: 2.1.3
      ms-legacy: /ms/2.0.0
      private-lib: '@npm.example.com/private-lib/-/private-lib-2.0.0.tgz'
      react: 18.3.1
      react-dom: 18.3.1_react@18.3.1
    devDependencies:
      '@types/node': 20.14.10
    optionalDependencies:
      fsevents: 2.3.3

  packages/ui:
    specifiers:
      react: ^18.3.1
    dependencies:
      react: 18.3.1

  packages/web:
    specifiers:
      ui-kit: workspace:@shop/ui@*
    devDependencies:
      ui-kit: link:../ui

packages:

  /@types/node/20.14.10:
    resolution: {integrity: sha512-AAAA}
    dependencies:
      undici-types: 5.26.5
    dev: true

  /fsevents/2.3.3:
    resolution: {integrity: sha512-BBBB}
    engines: {node: ^8.16.0 || ^10.6.0 || >=11.0.0}
    os: [darwin]
    requiresBuild: true
    dev: false
    optional: true

  /js-tokens/4.0.0:
    resolution: {integrity: sha512-CCCC}
    dev: false

  /loose-envify/1.4.0:
    resolution: {integrity: sha512-DDDD}
    hasBin: true
    dependencies:
      js-tokens: 4.0.0
    dev: false

  /ms/2.0.0:
    resolution: {integrity: sha512-EEEE}
    dev: false

  /ms/2.1.3:
    resolution: {integrity: sha512-FFFF}
    dev: false

  /react-dom/18.3.1_react@18.3.1:
    resolution: {integrity: sha512-GGGG}
    peerDependencies:
      react: ^18.3.1
    dependencies:
      loose-envify: 1.4.0
      react: 18.3.1
      scheduler: 0.23.2
    dev: false

  /react/18.3.1:
    resolution: {integrity: sha512-HHHH}
    engines: {node: '>=0.10.0'}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /scheduler/0.23.2:
    resolution: {integrity: sha512-IIII}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /undici-types/5.26.5:
    resolution: {integrity: sha512-JJJJ}
    dev: true

  '@npm.example.com/private-lib/-/private-lib-2.0.0.tgz':
    resolution: {tarball: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz}
    name: private-lib
    version: 2.0.0
    dev: false

  file:vendor/local-dir:
    resolution: {directory: vendor/local-dir, type: directory}
    name: local-dir
    version: 0.1.0
    dev: false

  file:vendor/local-tool-1.0.0.tgz:
    resolution: {integrity: sha512-KKKK, tarball: file:vendor/local-tool-1.0.0.tgz}
    name: local-tool
    version: 1.0.0
    dev: false

  github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567:
    resolution: {tarball: https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567}
    name: left-pad
    version: 1.3.0
    dev: false
"#;

    /// A `pnpm-lock.yaml` of version 6.0 as pnpm 8 writes it for a single project: keys
    /// `/<name>@<version>`, a peer suffix in parentheses, and the dependencies at the top with
    /// their specifiers inline. Names and addresses other than the public registry's are
    /// invented.
    const PNPM_6: &str = r#"lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  left-pad:
    specifier: github:example/left-pad
    version: github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567
  local-dir:
    specifier: file:vendor/local-dir
    version: file:vendor/local-dir
  local-tool:
    specifier: file:vendor/local-tool-1.0.0.tgz
    version: file:vendor/local-tool-1.0.0.tgz
  ms:
    specifier: ^2.1.3
    version: 2.1.3
  ms-legacy:
    specifier: npm:ms@2.0.0
    version: /ms@2.0.0
  private-lib:
    specifier: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz
    version: '@npm.example.com/private-lib/-/private-lib-2.0.0.tgz'
  react:
    specifier: ^18.3.1
    version: 18.3.1
  react-dom:
    specifier: ^18.3.1
    version: 18.3.1(react@18.3.1)

optionalDependencies:
  '@shop/ui':
    specifier: link:../ui
    version: link:../ui
  fsevents:
    specifier: ^2.3.3
    version: 2.3.3

devDependencies:
  '@types/node':
    specifier: ^20.14.10
    version: 20.14.10

packages:

  /@types/node@20.14.10:
    resolution: {integrity: sha512-AAAA}
    dependencies:
      undici-types: 5.26.5
    dev: true

  /fsevents@2.3.3:
    resolution: {integrity: sha512-BBBB}
    engines: {node: ^8.16.0 || ^10.6.0 || >=11.0.0}
    os: [darwin]
    requiresBuild: true
    dev: false
    optional: true

  /js-tokens@4.0.0:
    resolution: {integrity: sha512-CCCC}
    dev: false

  /loose-envify@1.4.0:
    resolution: {integrity: sha512-DDDD}
    hasBin: true
    dependencies:
      js-tokens: 4.0.0
    dev: false

  /ms@2.0.0:
    resolution: {integrity: sha512-EEEE}
    dev: false

  /ms@2.1.3:
    resolution: {integrity: sha512-FFFF}
    dev: false

  /react-dom@18.3.1(react@18.3.1):
    resolution: {integrity: sha512-GGGG}
    peerDependencies:
      react: ^18.3.1
    dependencies:
      loose-envify: 1.4.0
      react: 18.3.1
      scheduler: 0.23.2
    dev: false

  /react@18.3.1:
    resolution: {integrity: sha512-HHHH}
    engines: {node: '>=0.10.0'}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /scheduler@0.23.2:
    resolution: {integrity: sha512-IIII}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /undici-types@5.26.5:
    resolution: {integrity: sha512-JJJJ}
    dev: true

  '@npm.example.com/private-lib/-/private-lib-2.0.0.tgz':
    resolution: {tarball: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz}
    name: private-lib
    version: 2.0.0
    dev: false

  file:vendor/local-dir:
    resolution: {directory: vendor/local-dir, type: directory}
    name: local-dir
    version: 0.1.0
    dev: false

  file:vendor/local-tool-1.0.0.tgz:
    resolution: {integrity: sha512-KKKK, tarball: file:vendor/local-tool-1.0.0.tgz}
    name: local-tool
    version: 1.0.0
    dev: false

  github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567:
    resolution: {tarball: https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567}
    name: left-pad
    version: 1.3.0
    dev: false
"#;

    /// What each pnpm sample says, given the keys its version writes for the scoped package,
    /// the git one, the local file, the other registry's, `ms` at both versions, `react-dom`
    /// and where the workspace package is first linked: the same packages from every version.
    fn pnpm_expected(key: impl Fn(&str, &str) -> String, git: &str, link: &str) -> Vec<String> {
        let at = "dev/shop/pnpm-lock.yaml#";
        let mut said = vec![
            format!("npm/@shop/ui (path)|part_of|checkout|{at}{link}"),
            format!(
                "npm/@types/node|part_of|checkout|{at}{}",
                key("@types/node", "20.14.10")
            ),
            format!(
                "npm/@types/node|has_version|20.14.10|{at}{}",
                key("@types/node", "20.14.10")
            ),
            format!(
                "npm/fsevents|part_of|checkout|{at}{}",
                key("fsevents", "2.3.3")
            ),
            format!(
                "npm/fsevents|has_version|2.3.3|{at}{}",
                key("fsevents", "2.3.3")
            ),
        ];
        if !git.is_empty() {
            said.push(format!("npm/is-even (git)|part_of|checkout|{at}{git}"));
            said.push(format!("npm/is-even (git)|has_version|1.0.0|{at}{git}"));
        }
        let left_pad = key("left-pad", "");
        let dir = key("local-dir", "");
        let local = key("local-tool", "");
        let private = key("private-lib", "");
        said.extend([
            format!(
                "npm/js-tokens|part_of|checkout|{at}{}",
                key("js-tokens", "4.0.0")
            ),
            format!(
                "npm/js-tokens|has_version|4.0.0|{at}{}",
                key("js-tokens", "4.0.0")
            ),
            format!("npm/left-pad (git)|part_of|checkout|{at}{left_pad}"),
            format!("npm/left-pad (git)|has_version|1.3.0|{at}{left_pad}"),
            format!("npm/local-dir (path)|part_of|checkout|{at}{dir}"),
            format!("npm/local-dir (path)|has_version|0.1.0|{at}{dir}"),
            format!("npm/local-tool (path)|part_of|checkout|{at}{local}"),
            format!("npm/local-tool (path)|has_version|1.0.0|{at}{local}"),
            format!(
                "npm/loose-envify|part_of|checkout|{at}{}",
                key("loose-envify", "1.4.0")
            ),
            format!(
                "npm/loose-envify|has_version|1.4.0|{at}{}",
                key("loose-envify", "1.4.0")
            ),
            format!("npm/ms|part_of|checkout|{at}{}", key("ms", "2.0.0")),
            format!("npm/ms|has_version|2.0.0|{at}{}", key("ms", "2.0.0")),
            format!("npm/ms|has_version|2.1.3|{at}{}", key("ms", "2.1.3")),
            format!("npm/private-lib (other registry)|part_of|checkout|{at}{private}"),
            format!("npm/private-lib (other registry)|has_version|2.0.0|{at}{private}"),
            format!("npm/react|part_of|checkout|{at}{}", key("react", "18.3.1")),
            format!(
                "npm/react|has_version|18.3.1|{at}{}",
                key("react", "18.3.1")
            ),
            format!(
                "npm/react-dom|part_of|checkout|{at}{}",
                key("react-dom", "18.3.1")
            ),
            format!(
                "npm/react-dom|has_version|18.3.1|{at}{}",
                key("react-dom", "18.3.1")
            ),
            format!(
                "npm/scheduler|part_of|checkout|{at}{}",
                key("scheduler", "0.23.2")
            ),
            format!(
                "npm/scheduler|has_version|0.23.2|{at}{}",
                key("scheduler", "0.23.2")
            ),
            format!(
                "npm/undici-types|part_of|checkout|{at}{}",
                key("undici-types", "5.26.5")
            ),
            format!(
                "npm/undici-types|has_version|5.26.5|{at}{}",
                key("undici-types", "5.26.5")
            ),
        ]);
        said
    }

    /// The keys pnpm 5.x and 6.0 write for the entries that come from elsewhere than the
    /// registry; `None` for one from the registry.
    fn pnpm_elsewhere(name: &str) -> Option<String> {
        match name {
            "left-pad" => Some(
                "github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567".to_string(),
            ),
            "local-dir" => Some("file:vendor/local-dir".to_string()),
            "local-tool" => Some("file:vendor/local-tool-1.0.0.tgz".to_string()),
            "private-lib" => {
                Some("@npm.example.com/private-lib/-/private-lib-2.0.0.tgz".to_string())
            }
            _ => None,
        }
    }

    #[test]
    fn a_pnpm_entry_is_the_registrys_only_when_its_tarball_names_its_package_and_version() {
        // As for npm: the registry's address of another version, of another package's file or
        // with more after `.tgz` leaves the entry not told. The registry's own address of a
        // scoped package, and of a package whose key carries a peer suffix, is read.
        let ms = "  ms@2.1.3:\n    resolution: {integrity: sha512-FFFF}";
        let tarball = |file: &str| {
            format!(
                "  ms@2.1.3:\n    resolution: {{integrity: sha512-FFFF, tarball: https://registry.npmjs.org/{file}}}"
            )
        };
        for file in [
            "ms/-/ms-2.0.0.tgz",
            "ms/-/left-pad-2.1.3.tgz",
            "ms/-/ms-2.1.3.tgz#ms-2.0.0",
        ] {
            let dir = Dir::new(
                "pnpm-address",
                &[("pnpm-lock.yaml", &PNPM_9.replace(ms, &tarball(file)))],
            );
            let (o, said) = dir.read();
            assert!(
                !said.iter().any(|s| s.contains("ms@2.1.3")),
                "{file}: {said:?}"
            );
            assert_eq!(o.reason, one_not_told("pnpm-lock.yaml#ms@2.1.3"), "{file}");
        }
        for (text, from, to, read) in [
            (
                PNPM_9,
                "  '@types/node@20.14.10':\n    resolution: {integrity: sha512-AAAA}",
                "  '@types/node@20.14.10':\n    resolution: {integrity: sha512-AAAA, tarball: https://registry.npmjs.org/@types/node/-/node-20.14.10.tgz}",
                "npm/@types/node|has_version|20.14.10|dev/shop/pnpm-lock.yaml#@types/node@20.14.10",
            ),
            (
                PNPM_6,
                "resolution: {integrity: sha512-GGGG}",
                "resolution: {integrity: sha512-GGGG, tarball: https://registry.npmjs.org/react-dom/-/react-dom-18.3.1.tgz}",
                "npm/react-dom|has_version|18.3.1|dev/shop/pnpm-lock.yaml#/react-dom@18.3.1(react@18.3.1)",
            ),
        ] {
            let dir = Dir::new(
                "pnpm-address-read",
                &[("pnpm-lock.yaml", &text.replace(from, to))],
            );
            let (o, said) = dir.read();
            assert!(said.contains(&read.to_string()), "{read}: {said:?}");
            assert_eq!((o.completeness, o.reason), ("full", None), "{read}");
        }
    }

    #[test]
    fn a_pnpm_entry_whose_version_field_disagrees_with_its_key_is_never_read_as_either() {
        // pnpm fetches by the key: a `version` field of another version would answer for a
        // version that is not installed. The same version in both is read.
        let ms = "  ms@2.1.3:\n    resolution: {integrity: sha512-FFFF}\n";
        for (version, read) in [("9.9.9", false), ("2.1.3", true)] {
            let text = PNPM_9.replace(ms, &format!("{ms}    version: {version}\n"));
            let dir = Dir::new("pnpm-version-field", &[("pnpm-lock.yaml", &text)]);
            let (o, said) = dir.read();
            let fact = "npm/ms|has_version|2.1.3|dev/shop/pnpm-lock.yaml#ms@2.1.3".to_string();
            assert_eq!(said.contains(&fact), read, "{version}: {said:?}");
            assert!(!said.iter().any(|s| s.contains("9.9.9")), "{said:?}");
            let reason = (!read)
                .then(|| one_not_told("pnpm-lock.yaml#ms@2.1.3"))
                .flatten();
            assert_eq!(o.reason, reason, "{version}");
        }
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn every_pnpm_lockfile_version_names_each_package_by_what_it_is_and_says_where_it_comes_from() {
        // pnpm 7, 8 and 9 write the same project in three shapes; each is read to the same
        // packages. An alias is the package it stands for, a peer suffix is not part of the
        // version, a dev and an optional dependency are there, and only an entry from the
        // registry carries the bare name an advisory gives.
        let v5 = |name: &str, version: &str| match (pnpm_elsewhere(name), name) {
            (Some(key), _) => key,
            (None, "react-dom") => "/react-dom/18.3.1_react@18.3.1".to_string(),
            (None, _) => format!("/{name}/{version}"),
        };
        let v6 = |name: &str, version: &str| match (pnpm_elsewhere(name), name) {
            (Some(key), _) => key,
            (None, "react-dom") => "/react-dom@18.3.1(react@18.3.1)".to_string(),
            (None, _) => format!("/{name}@{version}"),
        };
        let v9 = |name: &str, version: &str| match name {
            "left-pad" => {
                format!("left-pad@https://codeload.github.com/example/left-pad/tar.gz/{SHA}")
            }
            "local-dir" => "local-dir@file:vendor/local-dir".to_string(),
            "local-tool" => "local-tool@file:vendor/local-tool-1.0.0.tgz".to_string(),
            "private-lib" => {
                "private-lib@https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz"
                    .to_string()
            }
            _ => format!("{name}@{version}"),
        };
        let git = format!("is-even@git+https://git.example.com/tools/is-even.git#{SHA}");
        let link5 = "importers/packages/web/devDependencies/ui-kit";
        // pnpm 3 to 6 wrote 5.0 to 5.3 in the same shape as pnpm 7's 5.4.
        let older: Vec<(String, Vec<String>)> = ["5", "5.1", "5.2", "5.3"]
            .iter()
            .map(|v| {
                let text = PNPM_5.replace("lockfileVersion: 5.4", &format!("lockfileVersion: {v}"));
                (text, pnpm_expected(v5, "", link5))
            })
            .collect();
        for (sample, expected) in [
            (PNPM_5.to_string(), pnpm_expected(v5, "", link5)),
            (
                PNPM_6.to_string(),
                pnpm_expected(v6, "", "optionalDependencies/@shop/ui"),
            ),
            (
                PNPM_9.to_string(),
                pnpm_expected(v9, &git, "importers/./dependencies/@shop/ui"),
            ),
        ]
        .into_iter()
        .chain(older)
        {
            let dir = Dir::new("pnpm", &[("pnpm-lock.yaml", &sample)]);
            let (o, said) = dir.read();
            assert_eq!(said, expected, "{}", &sample[..20]);
            assert_eq!((o.completeness, o.reason), ("full", None));
        }
    }

    #[test]
    fn a_pnpm_entry_from_another_registry_or_a_runtime_is_never_named_as_the_registrys() {
        // A key of 5.x that names a host is another registry's package even with `integrity`
        // alone; the public registry's own address is the registry's package; an archive from
        // each git host pnpm knows is from git; a runtime pnpm installs, such as Node.js
        // itself, is not an npm package from the registry.
        let gitlab =
            format!("is-odd@https://gitlab.com/example/is-odd/-/archive/{SHA}/is-odd-{SHA}.tar.gz");
        let bitbucket =
            format!("is-number@https://bitbucket.org/example/is-number/get/{SHA}.tar.gz");
        let v5 = "lockfileVersion: 5.4\n\nspecifiers:\n  is-positive: ^3.1.0\n\n\
                  dependencies:\n  is-positive: registry.example.com/is-positive/3.1.0\n\n\
                  packages:\n\n  registry.example.com/is-positive/3.1.0:\n    \
                  resolution: {integrity: sha512-AAAA}\n    engines: {node: '>=0.10.0'}\n    dev: false\n";
        let v9 = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      ms:\n        \
                  specifier: ^2.1.3\n        version: 2.1.3\n    devDependencies:\n      node:\n        \
                  specifier: runtime:22.11.0\n        version: runtime:22.11.0\n\npackages:\n\n  \
                  ms@2.1.3:\n    resolution: {integrity: sha512-BBBB, tarball: https://registry.npmjs.org/ms/-/ms-2.1.3.tgz}\n\n  \
                  node@runtime:22.11.0:\n    hasBin: true\n    resolution:\n      type: variations\n      \
                  variants:\n        - resolution: {archive: tarball, bin: bin/node, integrity: sha256-CCCC, type: binary, \
                  url: https://nodejs.org/download/release/v22.11.0/node-v22.11.0-darwin-arm64.tar.gz}\n          \
                  targets:\n            - cpu: arm64\n              os: darwin\n    version: 22.11.0\n\n\
                  snapshots:\n\n  ms@2.1.3: {}\n\n  node@runtime:22.11.0: {}\n";
        let git_hosts = |text: &str| {
            let packages = [&gitlab, &bitbucket]
                .iter()
                .map(|k| {
                    let url = k.split_once('@').unwrap().1;
                    format!("  {k}:\n    resolution: {{tarball: {url}}}\n    version: 1.0.0\n\n")
                })
                .collect::<String>();
            let snapshots: String = [&gitlab, &bitbucket]
                .iter()
                .map(|k| format!("  {k}: {{}}\n\n"))
                .collect();
            text.replace("packages:\n\n", &format!("packages:\n\n{packages}"))
                .replace("snapshots:\n\n", &format!("snapshots:\n\n{snapshots}"))
        };
        let v9 = git_hosts(v9);
        let at = "dev/shop/pnpm-lock.yaml#";
        for (text, expected) in [
            (
                v5,
                vec![
                    format!(
                        "npm/is-positive (other registry)|part_of|checkout|{at}registry.example.com/is-positive/3.1.0"
                    ),
                    format!(
                        "npm/is-positive (other registry)|has_version|3.1.0|{at}registry.example.com/is-positive/3.1.0"
                    ),
                ],
            ),
            (
                &v9,
                vec![
                    format!("npm/is-number (git)|part_of|checkout|{at}{bitbucket}"),
                    format!("npm/is-number (git)|has_version|1.0.0|{at}{bitbucket}"),
                    format!("npm/is-odd (git)|part_of|checkout|{at}{gitlab}"),
                    format!("npm/is-odd (git)|has_version|1.0.0|{at}{gitlab}"),
                    format!("npm/ms|part_of|checkout|{at}ms@2.1.3"),
                    format!("npm/ms|has_version|2.1.3|{at}ms@2.1.3"),
                    format!("npm/node (other registry)|part_of|checkout|{at}node@runtime:22.11.0"),
                    format!(
                        "npm/node (other registry)|has_version|22.11.0|{at}node@runtime:22.11.0"
                    ),
                ],
            ),
        ] {
            let dir = Dir::new("pnpm-registries", &[("pnpm-lock.yaml", text)]);
            let (o, said) = dir.read();
            assert_eq!(said, expected);
            assert_eq!(o.completeness, "full");
        }
    }

    #[test]
    fn a_pnpm_entry_whose_package_cannot_be_told_is_never_guessed_and_makes_the_reading_partial() {
        // No false calm: an entry whose version is not written or empty, whose name its key and
        // its field disagree on, whose registry address names another package, or whose
        // resolution says nothing to fetch it by is left out; so are the packages bundled inside
        // another, whose versions pnpm never writes, an installed package with no entry, a
        // dependency whose reference is not text and a link whose name is not a package's. Each
        // makes the reading partial, so it never says that a package is not there.
        let unknown = PNPM_9
            .replace(
                "  '@types/node@20.14.10':\n    resolution: {integrity: sha512-AAAA}\n",
                "  '@types/node@20.14.10':\n    resolution: {tarball: vendor/node-types.tgz}\n",
            )
            .replace(
                "    os: [darwin]\n",
                "    os: [darwin]\n    bundledDependencies: true\n",
            )
            .replace(
                "type: git}\n    version: 1.0.0\n",
                "type: git}\n    version: ''\n",
            )
            .replace(
                "      ms-legacy:\n        specifier: npm:ms@2.0.0\n",
                "      broken:\n        specifier: ^1.0.0\n      ms-legacy:\n        specifier: npm:ms@2.0.0\n",
            )
            .replace(
                "      ui-kit:\n        specifier: workspace:@shop/ui@*\n",
                "      bad name:\n        specifier: link:../x\n        version: link:../x\n      \
                 ui-kit:\n        specifier: workspace:@shop/ui@*\n",
            )
            .replace(
                &format!("tar.gz/{SHA}}}\n    version: 1.3.0\n"),
                &format!("tar.gz/{SHA}}}\n"),
            )
            .replace(
                "  ms@2.0.0:\n    resolution: {integrity: sha512-EEEE}\n",
                "  ms@2.0.0:\n    resolution: {integrity: sha512-EEEE}\n    name: lodash\n",
            )
            .replace(
                "resolution: {integrity: sha512-HHHH}",
                "resolution: {integrity: sha512-HHHH, tarball: https://registry.npmjs.org/preact/-/preact-10.0.0.tgz}",
            )
            .replace(
                "  loose-envify@1.4.0:\n    resolution: {integrity: sha512-DDDD}\n",
                "  loose-envify@1.4.0:\n    resolution: {integrity: sha512-DDDD}\n    bundledDependencies: [js-tokens]\n",
            )
            .replace(
                "  scheduler@0.23.2:\n    resolution: {integrity: sha512-IIII}\n\n",
                "",
            )
            .replace(
                "  undici-types@5.26.5:\n    resolution: {integrity: sha512-JJJJ}\n",
                "  undici-types@5.26.5: {}\n",
            );
        let dir = Dir::new("pnpm-unknown", &[("pnpm-lock.yaml", &unknown)]);
        let (o, said) = dir.read();
        for gone in [
            "npm/@types/node",
            "npm/is-even",
            "npm/left-pad",
            "lodash",
            "ms|has_version|2.0.0",
            "npm/react|",
            "npm/scheduler",
            "npm/undici-types",
            "bad name",
        ] {
            assert!(!said.iter().any(|s| s.contains(gone)), "{gone}: {said:?}");
        }
        assert!(
            said.contains(&"npm/ms|has_version|2.1.3|dev/shop/pnpm-lock.yaml#ms@2.1.3".to_string())
        );
        assert_eq!(o.completeness, "partial");
        assert_eq!(o.gap.cause, Some(Cause::NotGiven));
        // In the order of the file: packages, then snapshots, then projects.
        assert_eq!(
            o.reason.as_deref(),
            Some(
                format!(
                    "the package of 11 entries cannot be told: \
                     dev/shop/pnpm-lock.yaml#@types/node@20.14.10, \
                     dev/shop/pnpm-lock.yaml#fsevents@2.3.3/bundledDependencies, \
                     dev/shop/pnpm-lock.yaml#is-even@git+https://git.example.com/tools/is-even.git#{SHA}, …"
                )
                .as_str()
            )
        );
        // The ones after the first three, each left out by its own rule.
        let only = |from: &str, to: &str| {
            let text = PNPM_9.replace(from, to);
            let dir = Dir::new("pnpm-unknown-one", &[("pnpm-lock.yaml", &text)]);
            dir.read().0.reason.unwrap_or_default()
        };
        let one = |key: &str| {
            format!("the package of 1 entry cannot be told: dev/shop/pnpm-lock.yaml#{key}")
        };
        for (from, to, key) in [
            (
                format!("tar.gz/{SHA}}}\n    version: 1.3.0\n"),
                format!("tar.gz/{SHA}}}\n"),
                format!("left-pad@https://codeload.github.com/example/left-pad/tar.gz/{SHA}"),
            ),
            (
                "    hasBin: true\n".to_string(),
                "    hasBin: true\n    bundledDependencies: [js-tokens]\n".to_string(),
                "loose-envify@1.4.0/bundledDependencies/js-tokens".to_string(),
            ),
            (
                "  ms@2.0.0:\n    resolution: {integrity: sha512-EEEE}\n".to_string(),
                "  ms@2.0.0:\n    resolution: {integrity: sha512-EEEE}\n    name: lodash\n".to_string(),
                "ms@2.0.0".to_string(),
            ),
            (
                "resolution: {integrity: sha512-HHHH}".to_string(),
                "resolution: {integrity: sha512-HHHH, tarball: https://registry.npmjs.org/preact/-/preact-10.0.0.tgz}".to_string(),
                "react@18.3.1".to_string(),
            ),
            (
                "  undici-types@5.26.5:\n    resolution: {integrity: sha512-JJJJ}\n".to_string(),
                "  undici-types@5.26.5: {}\n".to_string(),
                "undici-types@5.26.5".to_string(),
            ),
            (
                "  undici-types@5.26.5:\n    resolution: {integrity: sha512-JJJJ}\n".to_string(),
                "  undici-types@5.26.5:\n    resolution: {}\n".to_string(),
                "undici-types@5.26.5".to_string(),
            ),
            (
                "  scheduler@0.23.2:\n    resolution: {integrity: sha512-IIII}\n\n".to_string(),
                String::new(),
                "scheduler@0.23.2".to_string(),
            ),
            (
                "      ms-legacy:\n        specifier: npm:ms@2.0.0\n".to_string(),
                "      broken:\n        specifier: ^1.0.0\n      ms-legacy:\n        specifier: npm:ms@2.0.0\n".to_string(),
                "importers/./dependencies/broken".to_string(),
            ),
            (
                "      ui-kit:\n        specifier: workspace:@shop/ui@*\n".to_string(),
                "      bad name:\n        specifier: link:../x\n        version: link:../x\n      \
                 ui-kit:\n        specifier: workspace:@shop/ui@*\n"
                    .to_string(),
                "importers/packages/web/dependencies/bad name".to_string(),
            ),
        ] {
            assert_eq!(only(&from, &to), one(&key), "{to}");
        }
        // A name that is not a package's, where only the entry's field gives one.
        let text = PNPM_5.replace("    name: left-pad\n", "    name: left pad\n");
        let dir = Dir::new("pnpm-unknown-name", &[("pnpm-lock.yaml", &text)]);
        assert_eq!(
            dir.read().0.reason.unwrap_or_default(),
            one(&format!("github.com/example/left-pad/{SHA}"))
        );
    }

    #[test]
    fn a_pnpm_lockfile_of_a_version_not_read_here_is_named_as_a_kind_without_a_reader() {
        // A version of the format this build was not written for is never guessed at: it is
        // named, and it leaves npm's packages of the project unknown and no other ecosystem's.
        // pnpm 7's experiment with inline specifiers is such a version.
        for version in ["6.1", "5.4-inlineSpecifiers"] {
            let dir = Dir::new(
                "pnpm-other",
                &[(
                    "pnpm-lock.yaml",
                    &PNPM_9.replace(
                        "lockfileVersion: '9.0'",
                        &format!("lockfileVersion: '{version}'"),
                    ),
                )],
            );
            let (o, said) = dir.read();
            assert!(said.is_empty());
            assert_eq!(o.completeness, "partial");
            assert_eq!(o.gap.cause, Some(Cause::NoReader));
            let name = format!("pnpm-lock.yaml version {version}");
            assert_eq!(o.gap.lacks[0].name.as_deref(), Some(name.as_str()));
            let reason = o.reason.clone().unwrap();
            assert_eq!(reason, format!("not supported yet: {name}"));
            let (rows, lacks) = (
                super::super::tests::rows(&o),
                super::super::tests::names(&o),
            );
            assert!(super::super::partial_for(&rows, &lacks, "npm"));
            assert!(!super::super::partial_for(&rows, &lacks, "crates.io"));
        }
    }

    #[test]
    fn a_pnpm_lockfile_out_of_its_shape_is_not_read_and_never_taken_for_one_with_no_packages() {
        // A file pnpm would not write is a reading that failed, never a project with nothing
        // in it: no version, a version that is not one (and so is never repeated as a name),
        // YAML that does not parse, an empty file, a map that is not one, and a 9.0 lockfile
        // without its projects.
        let long = format!("lockfileVersion: '{}'\nimporters: {{}}\n", "9".repeat(33));
        for text in [
            "packages: {}\n",
            "lockfileVersion: 'nine point oh'\nimporters: {}\n",
            "lockfileVersion: ''\nimporters: {}\n",
            &long,
            "lockfileVersion: '9.0'\nimporters: {.: {}\n",
            "",
            "lockfileVersion: '9.0'\nimporters: {}\npackages: [ms@2.1.3]\n",
            "lockfileVersion: '9.0'\n",
        ] {
            let dir = Dir::new("pnpm-broken", &[("pnpm-lock.yaml", text)]);
            let (o, said) = dir.read();
            assert!(said.is_empty(), "{text}");
            assert_eq!(o.gap.cause, Some(Cause::Failed), "{text}");
            assert_eq!(
                o.reason.as_deref(),
                Some("could not be read: pnpm-lock.yaml"),
                "{text}"
            );
        }
    }

    #[test]
    fn every_document_of_a_pnpm_lockfile_is_read() {
        // pnpm 11 may put the packages of its own configuration in a first document; they are
        // installed packages like the project's.
        let env = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies:\n      \
                   is-positive:\n        specifier: 3.1.0\n        version: 3.1.0\n\npackages:\n\n  \
                   is-positive@3.1.0:\n    resolution: {integrity: sha512-LLLL}\n\nsnapshots:\n\n  \
                   is-positive@3.1.0: {}\n\n---\n";
        let dir = Dir::new("pnpm-env", &[("pnpm-lock.yaml", &format!("{env}{PNPM_9}"))]);
        let (o, said) = dir.read();
        assert!(
            said.contains(
                &"npm/is-positive|has_version|3.1.0|dev/shop/pnpm-lock.yaml#is-positive@3.1.0"
                    .to_string()
            )
        );
        assert!(
            said.contains(&"npm/ms|has_version|2.1.3|dev/shop/pnpm-lock.yaml#ms@2.1.3".to_string())
        );
        assert_eq!(o.completeness, "full");
    }
}
