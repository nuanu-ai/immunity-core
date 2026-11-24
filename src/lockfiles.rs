//! The `lockfiles` reader: dependencies that lockfiles declare in local checkouts.
//! It only reads: it never runs git or a package manager and writes nothing where it reads.
//!
//! The checkouts come from the `checkouts` and `agent-folders` readers. Lockfiles are kept under version
//! control, so the raw input is a manifest of their paths, sizes and the checkout's commit
//! instead of a copy.
//!
//! A component is named by the package an entry really is, not by the name it was installed
//! under, and carries where the entry comes from (`Source`). Only an entry from its ecosystem's
//! public registry is named bare, `component:<checkout>/npm/<name>`; any other source is part of
//! the name, `component:<checkout>/npm/<name> (git)`, so a package from git and the registry's
//! package of the same name are two components and never one. No registry name holds a space,
//! so such a name can never equal one an advisory gives.

use crate::baseline::Unit;
use crate::checkouts::Checkout;
use crate::store::Statement;
use crate::store::{Cause, Gap, Lack};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

mod bun;
mod cargo;
mod commit;
mod npm;
mod pdm;
mod pipfile;
mod pnpm;
mod poetry;
mod pylock;
mod pypi;
mod requirements;
mod uv;
mod yarn;

use bun::bun;
use cargo::cargo;
pub use commit::commit;
use npm::npm;
use pnpm::pnpm;
pub use pypi::pypi_normalized;
use yarn::yarn;

pub const READER: &str = "lockfiles";
pub const KIND: &str = "lockfile dependencies";
pub const BASIS: &str = "declared";
/// The note of a full reading of a checkout in which no lockfile this version knows was found:
/// it was opened, and there was nothing to read. A checkout with no reading was never opened.
pub const NONE_FOUND_NOTE: &str = "no lockfile this version knows of was found in it";
/// What this build has no reader for among lockfiles, in its own words: a kind, by name.
pub const LOCKFILE_KIND: &str = "lockfile kind";

/// What this build reads of a lockfile below the folders it opens: its kind, by name. The
/// lockfile is there and was not opened.
pub const DEEPER: &str = "lockfile below the folders read";
/// What this build reads of a lockfile in a folder it sets aside, `vendor` or a hidden one: its
/// kind, by name. The lockfile is there and was not opened.
pub const SET_ASIDE: &str = "lockfile in a folder set aside";
/// What this build reads of a lockfile with entries whose package cannot be told: its kind, by
/// name. The lockfile was read, and those entries were left out.
pub const NOT_TOLD: &str = "lockfile entries whose package cannot be told";
/// Folders past `LOOK_LIMIT` that the walk did not look through: what they hold is not known.
pub const NOT_LOOKED: &str = "folders not looked through for lockfiles";
/// What this build reads of a lockfile that is a symbolic link: its kind, by name. Links are not
/// followed, so it was not opened.
pub const LINKED: &str = "lockfile that is a link";
/// How a partial reading's reason begins a clause for what its lacks name (`Gap::lacks`): the
/// kinds with no reader and the lockfiles not opened. The lacks decide what such a clause
/// leaves unknown; the words are for a person.
const NOT_SUPPORTED_SAID: &str = "not supported yet: ";
const NOT_OPENED_SAID: &str = "not opened: ";

/// Lockfiles are opened in the project's folder and in folders at most this deep below it.
/// Below, the walk only looks for them by name, so that one it does not open is said and never
/// taken as absent.
const MAX_DEPTH: usize = 4;
/// How many folders the walk lists, besides those whose lockfiles it opens, only to look for
/// lockfiles it does not open: below `MAX_DEPTH` and in folders set aside. Listing a folder is
/// one call to the system, about 0.1 s for 9,000 folders on a debug build, and ordinary build
/// trees (`android/app/build/intermediates`, a large Java package tree) hold several thousand.
/// Past this the reading is partial for every ecosystem, since what lies there is not known.
const LOOK_LIMIT: usize = 50_000;
/// Folders never entered, at any depth, since none holds what the project itself declares:
/// `.git` is git's own database, never a working file; `node_modules` holds installed copies of
/// packages, which the project's lockfile beside it declares, and a lockfile inside one is a
/// published package's own, about how that package was built; `target` is build output, made
/// from the project's own files. Every other hidden folder, and `vendor`, can hold code of the
/// project's own with its own lockfile, a CI action or a vendored app: they are set aside,
/// looked through for lockfiles that are then not opened (`SET_ASIDE`).
const NEVER_ENTERED: [&str; 3] = [".git", "node_modules", "target"];
const SET_ASIDE_FOLDER: &str = "vendor";
/// What marks a folder, or part of one, as holding nothing of the project's own. Marks only
/// bound the look for names below `MAX_DEPTH` and in folders set aside: where lockfiles are
/// opened, every one is opened whatever marks are there. What a marked folder holds is not the
/// project's and is not looked at.
/// - `pyvenv.cfg` marks a Python virtual environment (PEP 405). People make one in place in a
///   project's folder, so only the subfolders of an environment's own layout, as `venv` makes
///   them on POSIX and on Windows, are not looked into; the folder's own files and its other
///   subfolders are looked at as any other.
/// - `conda-meta` marks a conda environment, a folder of its own by construction.
/// - `CACHEDIR.TAG` beginning with its signature marks a cache (the Cache Directory Tagging
///   Specification, bford.info/cachedir).
/// - `.git`, a folder or a file (a worktree, a submodule, a nested repository), below the
///   project's own folder marks another project.
const ENVIRONMENT_MARK: &str = "pyvenv.cfg";
const ENVIRONMENT_LAYOUT: [&str; 8] = [
    "lib", "lib64", "bin", "include", "share", "Scripts", "Lib", "Include",
];
const CONDA_MARK: &str = "conda-meta";
const CACHE_MARK: &str = "CACHEDIR.TAG";
const CACHE_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";
const CHECKOUT_MARK: &str = ".git";

/// How a lockfile is read: from its text and its kind's name, which `npm` needs to tell
/// `package-lock.json` from `npm-shrinkwrap.json` and the other readers leave unused.
type Reader = fn(&str, &str) -> Parsed;

/// The kinds of lockfile this build knows a reader's place for: a kind's name, the ecosystem
/// whose packages it declares, as OSV names it, and its reader, `None` until one is written. A
/// kind whose reader is `None` is named as having no reader and never opened, as a kind of
/// `NOT_SUPPORTED` is. A kind is read only by the reader of its own row.
/// `npm-shrinkwrap.json` is in the format of `package-lock.json`, as npm documents it.
/// `yarn.lock` is read in the formats of Yarn 1 and of Yarn 2 and later. A row gets a reader
/// only with a feed for its ecosystem in `osv::FEEDS` (a test below holds it).
const FORMATS: [(&str, &str, Option<Reader>); 12] = [
    ("package-lock.json", "npm", Some(npm)),
    ("npm-shrinkwrap.json", "npm", Some(npm)),
    ("pnpm-lock.yaml", "npm", Some(|text, _| pnpm(text))),
    ("yarn.lock", "npm", Some(|text, _| yarn(text))),
    ("bun.lock", "npm", Some(|text, _| bun(text))),
    ("Cargo.lock", "crates.io", Some(|text, _| cargo(text))),
    ("uv.lock", "PyPI", uv::READ),
    ("poetry.lock", "PyPI", poetry::READ),
    ("pdm.lock", "PyPI", pdm::READ),
    ("pylock.toml", "PyPI", pylock::READ),
    ("Pipfile.lock", "PyPI", pipfile::READ),
    ("requirements.txt", "PyPI", requirements::READ),
];
/// Kinds a file is also named by in a pattern: the prefix, one or more characters none of
/// which is `.`, and the suffix, ignoring case. PEP 751 names a named lock `pylock.<name>.toml`,
/// `^pylock\.([^.]+)\.toml$` (packaging.python.org, "pylock.toml specification").
const PATTERNS: [(&str, &str, &str); 1] = [("pylock.", ".toml", "pylock.toml")];

/// The reader of a kind of lockfile, by the kind's name; `None` for a kind with none.
fn reader_of(kind: &str) -> Option<Reader> {
    FORMATS.iter().find(|(k, ..)| *k == kind).and_then(|f| f.2)
}

/// Whether this build reads some kind of lockfile of an ecosystem, as OSV names it, so that a
/// feed of it has packages to be matched against.
pub fn has_reader(ecosystem: &str) -> bool {
    (FORMATS.iter()).any(|(_, of, read)| *of == ecosystem && read.is_some())
}

/// Lockfiles this build has no reader for, by name, with the ecosystem whose packages each
/// declares, as OSV names it. Data, from OSV-Scanner's list of supported lockfiles
/// (google.github.io/osv-scanner, "Supported languages and lockfiles", read on 16 November
/// 2026), with `go.sum` for Go, Swift's `Package.resolved`, CocoaPods' `Podfile.lock` and Nix's
/// `flake.lock`, whose ecosystems OSV does not name, and Bun's binary `bun.lockb`, which Bun's
/// documentation of its lockfile (bun.com/docs/install/lockfile) gives as the earlier form of
/// `bun.lock`. The
/// manifests that page lists beside the lockfiles (`go.mod`, `pom.xml`, `deps.json` and the
/// like) are not lockfiles and are not here. A lockfile of a name on no list is not known to be
/// one and cannot be said (docs/reference.md).
const NOT_SUPPORTED: [(&str, Option<&str>); 17] = [
    ("bun.lockb", Some("npm")),
    ("composer.lock", Some("Packagist")),
    ("go.sum", Some("Go")),
    ("Package.resolved", Some("SwiftURL")),
    ("Gemfile.lock", Some("RubyGems")),
    ("gems.locked", Some("RubyGems")),
    ("mix.lock", Some("Hex")),
    ("pubspec.lock", Some("Pub")),
    ("renv.lock", Some("CRAN")),
    ("gradle.lockfile", Some("Maven")),
    ("buildscript-gradle.lockfile", Some("Maven")),
    ("packages.lock.json", Some("NuGet")),
    ("conan.lock", Some("ConanCenter")),
    ("cabal.project.freeze", Some("Hackage")),
    ("stack.yaml.lock", Some("Hackage")),
    ("Podfile.lock", None),
    ("flake.lock", None),
];

/// Where a lockfile entry comes from. A closed set: only `Registry`, the ecosystem's public
/// registry, is what the ecosystem's open vulnerability data speaks of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// npm's public registry; for Cargo, crates.io.
    Registry,
    Git,
    /// A file, a link or a folder on disk: npm's `file:` and linked entries, Cargo's path and
    /// workspace crates.
    Path,
    /// Any other registry, or an address that is not the public registry's.
    OtherRegistry,
}

/// The name part of a component's id: the real name, and for any source but the public registry
/// the source in brackets.
fn component_name(name: &str, source: Source) -> String {
    let source = match source {
        Source::Registry => return name.to_string(),
        Source::Git => "git",
        Source::Path => "path",
        Source::OtherRegistry => "other registry",
    };
    format!("{name} ({source})")
}

/// The name part of a component's id told apart: the package's name, and where it comes from
/// when that is not the public registry. The inverse of `component_name`.
pub fn split_name(name: &str) -> (&str, Option<&'static str>) {
    for (suffix, from) in [
        (" (git)", "git"),
        (" (path)", "a path"),
        (" (other registry)", "another registry"),
    ] {
        if let Some(package) = name.strip_suffix(suffix) {
            return (package, Some(from));
        }
    }
    (name, None)
}

/// The ecosystem whose dependencies a kind of lockfile declares, by its name as `read` names
/// it, a version of its format with no reader as `<kind> version <n>`; `None` for one not known
/// here.
pub fn ecosystem_of(kind: &str) -> Option<&'static str> {
    let kind = kind.split_once(" version ").map_or(kind, |(kind, _)| kind);
    (FORMATS.iter().map(|(name, of, _)| (*name, Some(*of))))
        .chain(NOT_SUPPORTED)
        .find(|(name, _)| *name == kind)
        .and_then(|(_, ecosystem)| ecosystem)
}

/// The predicate of a lockfile found in a checkout: the checkout `has_lockfile` the file at
/// this path relative to it.
pub const HAS_LOCKFILE: &str = "has_lockfile";

/// The ecosystem whose dependencies the lockfile at a path declares, by its file name as
/// `lockfile_kind` tells it; `None` for a kind of no ecosystem a record can be about.
pub fn ecosystem_of_file(path: &str) -> Option<&'static str> {
    lockfile_kind(path.rsplit('/').next()?).and_then(ecosystem_of)
}

/// Whether a partial reading leaves the dependencies of one ecosystem in part unknown. What the
/// reading names it did not read, `lacks` by their names (a kind with no reader, a lockfile not
/// opened, a kind with entries not told), leaves the ecosystem of each name unknown and no
/// other: a name of no ecosystem a record can be about, such as `flake.lock`, leaves none. A
/// lack with no name, folders not looked through, counts for every ecosystem. The reason's
/// clauses for the lacks are only words for a person. The reason decides the rest: a lockfile
/// of that ecosystem not parsed, a folder not listed. A clause this does not recognise counts for every ecosystem,
/// so that nothing reads as fully known that is not.
pub fn partial_for(reason: &str, lacks: &[Option<String>], ecosystem: &str) -> bool {
    let of_it = |name: &str| ecosystem_of(name) == Some(ecosystem);
    lacks.iter().any(|name| name.as_deref().is_none_or(of_it))
        || reason.split("; ").any(|clause| {
            if clause.starts_with(NOT_SUPPORTED_SAID) || clause.starts_with(NOT_OPENED_SAID) {
                false
            } else if let Some(names) = clause.strip_prefix("could not be read: ") {
                names.split(", ").any(of_it)
            } else if clause.starts_with("the package of ") {
                // Entries not told are decided by their lack (`NOT_TOLD`). The clause counts for
                // npm only for a reading written before that lack was recorded.
                ecosystem == "npm"
            } else {
                true
            }
        })
}

/// What reading one checkout found.
pub struct Outcome {
    pub completeness: &'static str,
    pub reason: Option<String>,
    /// Why the reading is incomplete, and the lockfile kinds this build has no reader for.
    pub gap: Gap,
    pub statements: Vec<Statement>,
    /// Every lockfile found: path relative to the home folder, and size in bytes.
    pub lockfiles: Vec<(String, u64)>,
}

/// The kind of lockfile a file's name says, as this build names the kind; `None` for a name of
/// no lockfile. Names are matched ignoring case: macOS volumes ignore case by default, so
/// `Package-Lock.json` is the same file to its tool. A name of no kind is matched against
/// `PATTERNS`, ignoring case too.
fn lockfile_kind(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    let in_pattern = |(prefix, suffix, _): &&(&str, &str, &str)| {
        let middle = lower
            .strip_prefix(prefix)
            .and_then(|r| r.strip_suffix(suffix));
        middle.is_some_and(|middle| !middle.is_empty() && !middle.contains('.'))
    };
    (FORMATS.iter().map(|(kind, ..)| *kind))
        .chain(NOT_SUPPORTED.iter().map(|(kind, _)| *kind))
        .find(|kind| kind.eq_ignore_ascii_case(name))
        .or_else(|| PATTERNS.iter().find(in_pattern).map(|(.., kind)| *kind))
}

/// Where the walk found a lockfile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Where {
    /// Where lockfiles are opened.
    Opened,
    /// Below `MAX_DEPTH`.
    Deeper,
    /// In a folder set aside, at any depth.
    SetAside,
    /// A symbolic link, anywhere: not followed, so not opened.
    Linked,
}

/// What the walk of a checkout found: lockfiles relative to it, each with its kind and where,
/// and the folders it did not look through, relative to it with `/` after each.
struct Walk {
    lockfiles: Vec<(String, &'static str, Where)>,
    /// Folders that could not be listed in full, each with the system's error.
    unlisted: Vec<(String, String)>,
    /// What the walk passes over by design: every entry of a folder it listed that it neither
    /// goes into nor opens, and a folder a mark sets aside.
    aside: Vec<String>,
    /// Whether folders were left that the look limit kept it from looking through.
    stopped: bool,
}

/// Whether a file is a cache's tag: `CACHE_MARK` beginning with its signature.
fn cache_tag(name: &str, path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; CACHE_SIGNATURE.len()];
    name == CACHE_MARK
        && std::fs::File::open(path)
            .and_then(|mut f| f.read_exact(&mut head))
            .is_ok()
        && head == CACHE_SIGNATURE
}

/// Walks a checkout for lockfiles: opened down to `MAX_DEPTH`, as they always were, and below
/// it and in folders set aside looked for by name only, at most `limit` folders. Links are not
/// followed. A folder a mark says is not the project's is not looked at by that look; where
/// lockfiles are opened, marks change nothing.
fn walk(checkout: &Path, limit: usize) -> Walk {
    let mut out = Walk {
        lockfiles: Vec::new(),
        unlisted: Vec::new(),
        aside: Vec::new(),
        stopped: false,
    };
    let mut looked = 0;
    // Each folder with where it is and whether a mark above it says it is not the project's.
    let mut stack = vec![(
        String::new(),
        checkout.to_path_buf(),
        0,
        Where::Opened,
        false,
    )];
    while let Some((rel, dir, depth, at, not_own)) = stack.pop() {
        if at != Where::Opened {
            if looked == limit {
                out.stopped = true;
                continue;
            }
            looked += 1;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                out.unlisted.push((rel, e.to_string()));
                continue;
            }
        };
        let (mut files, mut folders, mut missed) = (Vec::new(), Vec::new(), None);
        let (mut environment, mut whole) = (false, not_own);
        for entry in entries {
            let (entry, file_type) = match entry.and_then(|e| e.file_type().map(|t| (e, t))) {
                Ok(found) => found,
                Err(e) => {
                    missed.get_or_insert(e.to_string());
                    continue;
                }
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            environment |= file_type.is_file() && name == ENVIRONMENT_MARK;
            whole |= depth > 0
                && (name == CHECKOUT_MARK
                    || (file_type.is_dir() && name == CONDA_MARK)
                    || (file_type.is_file() && cache_tag(&name, &entry.path())));
            if file_type.is_dir() && !NEVER_ENTERED.contains(&name.as_str()) {
                folders.push((name, entry.path()));
                continue;
            }
            // A file is known by its name: nothing lies under it.
            if file_type.is_file() {
                files.extend(lockfile_kind(&name).map(|kind| (name, kind, at)));
                continue;
            }
            // Neither gone into nor opened, whatever the reason: a folder never entered, a link
            // of any kind, which is not followed, or an entry of another kind. What was known
            // under it is kept (`Walk::aside`); a lockfile that is a link is also said.
            out.aside.push(format!("{rel}{name}"));
            if file_type.is_symlink() {
                files.extend(lockfile_kind(&name).map(|kind| (name, kind, Where::Linked)));
            }
        }
        out.unlisted.extend(missed.map(|e| (rel.clone(), e)));
        // The look for names does not look at what a mark says is not the project's.
        if at != Where::Opened && whole {
            out.aside.push(rel);
            continue;
        }
        out.lockfiles.extend(
            files
                .into_iter()
                .map(|(name, kind, at)| (format!("{rel}{name}"), kind, at)),
        );
        for (name, path) in folders {
            let next = match at {
                Where::Opened if name.starts_with('.') || name == SET_ASIDE_FOLDER => {
                    Where::SetAside
                }
                Where::Opened if depth == MAX_DEPTH => Where::Deeper,
                other => other,
            };
            let not_own = whole || (environment && ENVIRONMENT_LAYOUT.contains(&name.as_str()));
            stack.push((format!("{rel}{name}/"), path, depth + 1, next, not_own));
        }
    }
    out.lockfiles.sort();
    out
}

/// What one walk of a checkout gives the indicators reader to look for strings in, relative
/// to the checkout: the lockfiles of the kinds read here that are opened as text, those found
/// and not opened, the folders it did not look through (`Walk`), and whether it went to its end.
pub struct Texts {
    pub opened: Vec<String>,
    pub not_opened: Vec<String>,
    pub unlisted: Vec<(String, String)>,
    pub aside: Vec<String>,
    pub stopped: bool,
}

/// Whether the file at `rel` in a checkout is one the walk of `read_as_text` looks for: a
/// lockfile, by its name in any case. Where it lies decides only whether it is opened.
pub fn looked_for_as_text(rel: &str) -> bool {
    lockfile_kind(rel.rsplit('/').next().unwrap_or(rel)).is_some()
}

pub fn read_as_text(checkout: &Path) -> Texts {
    let walked = walk(checkout, LOOK_LIMIT);
    let (opened, not_opened) = (walked.lockfiles.into_iter())
        .filter(|(_, kind, _)| reader_of(kind).is_some())
        .partition::<Vec<_>, _>(|(_, _, at)| *at == Where::Opened);
    let paths = |found: Vec<(String, &str, Where)>| found.into_iter().map(|(p, ..)| p).collect();
    Texts {
        opened: paths(opened),
        not_opened: paths(not_opened),
        unlisted: walked.unlisted,
        aside: walked.aside,
        stopped: walked.stopped,
    }
}

/// Reads one checkout. `None` when it holds no lockfile at all: then there is nothing
/// to cover. Where the checkout is, is said by the `checkouts` reader.
pub fn read(checkout: &Checkout, id: &str) -> Option<Outcome> {
    read_within(checkout, id, LOOK_LIMIT)
}

/// `read`, with the look for names below the folders opened stopping after `limit` folders.
fn read_within(checkout: &Checkout, id: &str, limit: usize) -> Option<Outcome> {
    let walked = walk(&checkout.path, limit);
    if walked.lockfiles.is_empty() && walked.unlisted.is_empty() && !walked.stopped {
        return None;
    }
    let prefix = if checkout.rel == "." {
        String::new()
    } else {
        format!("{}/", checkout.rel)
    };
    let mut not_supported: BTreeSet<String> = BTreeSet::new();
    let mut not_parsed: BTreeSet<&str> = BTreeSet::new();
    // Entries whose package cannot be told, as `<lockfile>#<key>`, and the kinds they are of.
    let mut not_told: Vec<String> = Vec::new();
    let mut not_told_kinds: BTreeSet<&str> = BTreeSet::new();
    // Lockfiles of a kind read here that were not opened, by where, and their kinds.
    let mut not_opened: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut lacks: BTreeSet<(&'static str, &str)> = BTreeSet::new();
    let mut lockfiles = Vec::new();
    // (ecosystem, name with its source) -> where it was first read, and version -> where
    // that version was first read.
    let mut deps: BTreeMap<(&str, String), Found> = BTreeMap::new();

    for (rel, kind, at) in &walked.lockfiles {
        let source = format!("{prefix}{rel}");
        let name: &str = kind;
        // A kind with no reader is that wherever it is; one read here is not opened where the
        // walk does not open lockfiles, or when it is a link, and is named as such.
        let unopened = match at {
            Where::Opened => None,
            Where::Deeper => Some(DEEPER),
            Where::SetAside => Some(SET_ASIDE),
            Where::Linked => Some(LINKED),
        };
        if let Some(what) = unopened {
            if reader_of(name).is_some() {
                not_opened.entry(what).or_default().push(source);
                lacks.insert((what, name));
            } else {
                not_supported.insert(name.to_string());
            }
            continue;
        }
        let path = checkout.path.join(rel);
        // A kind with no reader is never opened: its size is the file's own, 0 when that cannot
        // be had, as for a lockfile that could not be read.
        let Some(reader) = reader_of(name) else {
            let size = std::fs::symlink_metadata(&path).map_or(0, |m| m.len());
            lockfiles.push((source, size));
            not_supported.insert(name.to_string());
            continue;
        };
        let text = std::fs::read(&path).ok();
        lockfiles.push((source.clone(), text.as_ref().map_or(0, |t| t.len() as u64)));
        let parsed = match text.and_then(|t| String::from_utf8(t).ok()) {
            None => Parsed::Failed,
            Some(t) => reader(&t, name),
        };
        let (ecosystem, found) = match parsed {
            Parsed::Deps(ecosystem, found, unknown) => {
                if !unknown.is_empty() {
                    not_told_kinds.insert(name);
                }
                not_told.extend(unknown.iter().map(|key| format!("{source}#{key}")));
                (ecosystem, found)
            }
            Parsed::NoReader(kind) => {
                not_supported.insert(kind);
                continue;
            }
            Parsed::Failed => {
                not_parsed.insert(name);
                continue;
            }
        };
        for dep in found {
            let at = match &dep.at {
                At::Line(n) => format!("{source}:{n}"),
                At::Key(key) => format!("{source}#{key}"),
            };
            let (_, versions) = deps
                .entry((ecosystem, component_name(&dep.name, dep.source)))
                .or_insert_with(|| (at.clone(), BTreeMap::new()));
            if let Some(version) = dep.version {
                versions.entry(version).or_insert(at);
            }
        }
    }

    // Every lockfile found, of any kind, read or not: the ecosystems matching has something to
    // say of in this checkout (`vulnerabilities::match_all`).
    let mut statements: Vec<Statement> = (walked.lockfiles.iter())
        .map(|(rel, ..)| Statement {
            subject: id.to_string(),
            predicate: HAS_LOCKFILE,
            object: rel.clone(),
            source_ref: rel.clone(),
        })
        .collect();
    for ((ecosystem, name), (first, versions)) in deps {
        let component = format!("component:{id}/{ecosystem}/{name}");
        statements.push(Statement {
            subject: component.clone(),
            predicate: "part_of",
            object: id.to_string(),
            source_ref: first,
        });
        for (version, at) in versions {
            statements.push(Statement {
                subject: component.clone(),
                predicate: "has_version",
                object: version,
                source_ref: at,
            });
        }
    }

    let mut reasons = Vec::new();
    if !not_supported.is_empty() {
        let names: Vec<&str> = not_supported.iter().map(String::as_str).collect();
        reasons.push(format!("{NOT_SUPPORTED_SAID}{}", names.join(", ")));
    }
    for (what, paths) in &not_opened {
        let place = match *what {
            DEEPER => format!("deeper than {MAX_DEPTH} folders"),
            LINKED if paths.len() == 1 => "that is a link".to_string(),
            LINKED => "that are links".to_string(),
            _ => "in vendor or hidden folders".to_string(),
        };
        let n = counted(paths.len(), "lockfile", "lockfiles");
        reasons.push(format!("{NOT_OPENED_SAID}{n} {place}: {}", some_of(paths)));
    }
    if walked.stopped {
        reasons.push(format!(
            "{NOT_OPENED_SAID}what lies past the first {limit} folders looked through \
             for lockfiles below {MAX_DEPTH} folders or in vendor and hidden folders"
        ));
    }
    if !not_parsed.is_empty() {
        let names: Vec<&str> = not_parsed.iter().copied().collect();
        reasons.push(format!("could not be read: {}", names.join(", ")));
    }
    if !not_told.is_empty() {
        // Never a guess: an entry that is not known to be the package it names is left out,
        // and the reading is partial, so it never says that a package is not there.
        let n = counted(not_told.len(), "entry", "entries");
        reasons.push(format!(
            "the package of {n} cannot be told: {}",
            some_of(&not_told)
        ));
    }
    if !walked.unlisted.is_empty() {
        // Each folder with what the system said, so that a permission is told from another
        // failure. `partial_for` takes this clause for every ecosystem.
        let named: Vec<String> = (walked.unlisted.iter())
            .map(|(rel, why)| format!("{} ({why})", Unit::whole(format!("{prefix}{rel}"))))
            .collect();
        let n = counted(named.len(), "folder", "folders");
        reasons.push(format!("{n} could not be listed: {}", some_of(&named)));
    }
    // A lockfile that could not be read or a folder that could not be listed failed; a kind
    // of lockfile without a reader, a lockfile not opened where it is and folders not looked
    // through are no reader; an entry the lockfile does not say enough about is not given.
    // The reading takes the worst. Folders not looked through by design (`Walk::aside`) are
    // limits of the reader, said in docs/reference.md.
    let mut causes = Vec::new();
    if !not_parsed.is_empty() || !walked.unlisted.is_empty() {
        causes.push(Cause::Failed);
    }
    if !not_supported.is_empty() || !lacks.is_empty() || walked.stopped {
        causes.push(Cause::NoReader);
    }
    if !not_told.is_empty() {
        causes.push(Cause::NotGiven);
    }
    // What was not read, each by name where it has one, so that what it leaves unknown is
    // decided from these and never from the reason's words (`partial_for`).
    let gap = Gap {
        cause: Cause::worst(causes),
        lacks: not_supported
            .iter()
            .map(|name| Lack::new(LOCKFILE_KIND, Some(name)))
            .chain(lacks.iter().map(|(what, name)| Lack::new(what, Some(name))))
            .chain((not_told_kinds.iter()).map(|name| Lack::new(NOT_TOLD, Some(name))))
            .chain(walked.stopped.then(|| Lack::new(NOT_LOOKED, None)))
            .collect(),
    };
    Some(Outcome {
        gap,
        completeness: if reasons.is_empty() {
            "full"
        } else {
            "partial"
        },
        reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
        statements,
        lockfiles,
    })
}

/// `n` things, as a reason counts them.
fn counted(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The first three of `items`, and "…" when there are more: a reason names some and counts all.
fn some_of(items: &[String]) -> String {
    let more = if items.len() > 3 { ", …" } else { "" };
    format!("{}{more}", items[..items.len().min(3)].join(", "))
}

/// Where a component was first read, and each of its versions with where it was first read.
type Found = (String, BTreeMap<String, String>);

/// Where in its lockfile an entry was read.
enum At {
    Line(usize),
    /// The key of `package-lock.json`'s `packages` map. It names an alias as it was
    /// installed, so a person finds the entry. For `pnpm-lock.yaml`, the key of its `packages`
    /// map, or the path to a dependency as `<where>/<field>/<name>`. For `yarn.lock`, an entry's
    /// key as written; for `bun.lock`, the install path that keys `packages`.
    Key(String),
}

/// One entry of a lockfile: the package it really is, its version, and where it comes from.
struct Dep {
    at: At,
    name: String,
    /// `None` only for an entry not from a registry that its lockfile gives no version, as a
    /// linked entry whose target has none.
    version: Option<String>,
    source: Source,
}

enum Parsed {
    /// The ecosystem, the entries, and the keys of entries whose package cannot be told.
    Deps(&'static str, Vec<Dep>, Vec<String>),
    /// A lockfile of a kind this build has no reader for, by name.
    NoReader(String),
    Failed,
}

/// npm's public registry. An entry is from it when it names no `resolved` address, as a
/// bundled entry does, or names one here. An address here is the package's own only as
/// `registry_tarball` says; any other is not its package. A mirror counts as another registry.
const NPM_REGISTRY: &str = "https://registry.npmjs.org/";

/// How an address of a git repository begins, in the lockfiles of npm and Bun.
const GIT: [&str; 5] = ["git+", "git://", "github:", "gitlab:", "bitbucket:"];
/// How the address of a tarball on the web begins, in the lockfiles of Yarn and Bun: another
/// registry's, or no registry's.
const WEB: [&str; 2] = ["https://", "http://"];

/// Whether `path`, the part of an address after `NPM_REGISTRY`, is the registry's file of the
/// package `name` at `version`: exactly `<name>/-/<unscoped name>-<version>.tgz`, the unscoped
/// name being `name` without its `@scope/`, with nothing after `.tgz`. Any other address names
/// another package, another version or a file not known here. `version` must parse as a full
/// SemVer version: a version holding `/..` would make an address whose dot segments a client
/// resolves to another package's file, while the text still names this one.
fn registry_tarball(path: &str, name: &str, version: &str) -> bool {
    let unscoped = name.rsplit_once('/').map_or(name, |(_, n)| n);
    semver::Version::parse(version).is_ok() && path == format!("{name}/-/{unscoped}-{version}.tgz")
}

/// A package name as npm allows it: what `encodeURIComponent` leaves unchanged, so that a
/// registry that decodes an address serves the package the text names. ASCII letters, digits
/// and `-_.!~*'()`, with one slash only in `@scope/name`. A name with no scope does not start
/// with `.` or `_`; a scope and the name after it may (`@_sh/widget` is a package), and neither
/// is `.` or `..`, which an address would take for a folder. The rule is npm's
/// `validate-npm-package-name` as remembered, not read again for this.
fn npm_name(name: &str) -> bool {
    let part = |s: &str| {
        !matches!(s, "" | "." | "..")
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&c))
    };
    match name.split_once('/') {
        None => part(name) && !name.starts_with(['.', '_']),
        Some((scope, rest)) => scope.strip_prefix('@').is_some_and(part) && part(rest),
    }
}

/// A version of a lockfile's format in the shape pnpm and Yarn write one: digits, letters, dots
/// and dashes, as `5.4` or `5.4-inlineSpecifiers`. Anything else is not a version.
fn version_shape(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::{
        CACHE_SIGNATURE, Checkout, DEEPER, FORMATS, HAS_LOCKFILE, LINKED, LOCKFILE_KIND,
        NOT_LOOKED, NOT_TOLD, SET_ASIDE, ecosystem_of, has_reader, lockfile_kind, partial_for,
        read, read_as_text, read_within,
    };

    fn file_name(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }
    use crate::store::Cause;
    use std::path::PathBuf;

    /// A `package-lock.json` of version 3 as npm 10 writes it, with every source an entry can
    /// come from. Names and addresses other than the public registry's are invented.
    pub(super) const NPM: &str = r#"{
  "name": "shop",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "shop",
      "version": "1.0.0",
      "workspaces": ["packages/ui"],
      "dependencies": {
        "ink": "npm:@jrichman/ink@6.4.6",
        "left-pad": "github:example/left-pad",
        "local-tool": "file:vendor/local-tool-1.0.0.tgz",
        "private-lib": "^2.0.0",
        "string-width": "^5.1.2",
        "string-width-cjs": "npm:string-width@^4.2.0"
      }
    },
    "node_modules/@shop/ui": {
      "resolved": "packages/ui",
      "link": true
    },
    "node_modules/ink": {
      "name": "@jrichman/ink",
      "version": "6.4.6",
      "resolved": "https://registry.npmjs.org/@jrichman/ink/-/ink-6.4.6.tgz",
      "integrity": "sha512-AAAA",
      "license": "MIT"
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "git+ssh://git@github.com/example/left-pad.git#0123456789abcdef0123456789abcdef01234567",
      "license": "WTFPL"
    },
    "node_modules/local-tool": {
      "version": "1.0.0",
      "resolved": "file:vendor/local-tool-1.0.0.tgz",
      "integrity": "sha512-BBBB"
    },
    "node_modules/npm-bundler": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/npm-bundler/-/npm-bundler-2.0.0.tgz",
      "integrity": "sha512-CCCC",
      "bundleDependencies": ["abbrev"]
    },
    "node_modules/npm-bundler/node_modules/abbrev": {
      "version": "1.1.1",
      "inBundle": true,
      "license": "ISC"
    },
    "node_modules/private-lib": {
      "version": "2.0.0",
      "resolved": "https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz",
      "integrity": "sha512-DDDD"
    },
    "node_modules/string-width": {
      "version": "5.1.2",
      "resolved": "https://registry.npmjs.org/string-width/-/string-width-5.1.2.tgz",
      "integrity": "sha512-EEEE",
      "dev": true
    },
    "node_modules/string-width-cjs": {
      "name": "string-width",
      "version": "4.2.3",
      "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz",
      "integrity": "sha512-FFFF",
      "dev": true
    },
    "packages/ui": {
      "name": "@shop/ui",
      "version": "0.1.0"
    }
  }
}
"#;

    /// A `Cargo.lock` of version 4 with every source a crate can come from: the workspace,
    /// both forms of crates.io's index, git, another registry, and a crate patched to a path.
    pub(super) const CARGO: &str = r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "libc",
 "rand 0.8.5",
 "rand 0.9.0-dev",
 "serde",
 "internal-crate",
]

[[package]]
name = "internal-crate"
version = "1.2.0"
source = "sparse+https://cargo.example.com/index/"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"

[[package]]
name = "libc"
version = "0.2.191"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222"

[[package]]
name = "rand"
version = "0.9.0-dev"
source = "git+https://github.com/rust-random/rand?branch=master#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "serde"
version = "1.0.210"
source = "sparse+https://index.crates.io/"
checksum = "3333333333333333333333333333333333333333333333333333333333333333"

[[patch.unused]]
name = "log"
version = "0.4.22"
source = "git+https://github.com/rust-lang/log#89abcdef0123456789abcdef0123456789abcdef"
"#;

    /// A `pnpm-lock.yaml` of version 9.0 as pnpm 9 writes it for a workspace: `packages` keyed
    /// `<name>@<version or source>`, `snapshots` with peer suffixes in parentheses, and a
    /// dependency from a git server that is not a known host. Names and addresses other than
    /// the public registry's are invented.
    pub(super) const PNPM_9: &str = r#"lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      '@shop/ui':
        specifier: workspace:*
        version: link:packages/ui
      is-even:
        specifier: git+https://git.example.com/tools/is-even.git#0123456789abcdef0123456789abcdef01234567
        version: git+https://git.example.com/tools/is-even.git#0123456789abcdef0123456789abcdef01234567
      left-pad:
        specifier: github:example/left-pad
        version: https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567
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
        version: ms@2.0.0
      private-lib:
        specifier: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz
        version: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz
      react:
        specifier: ^18.3.1
        version: 18.3.1
      react-dom:
        specifier: ^18.3.1
        version: 18.3.1(react@18.3.1)
    devDependencies:
      '@types/node':
        specifier: ^20.14.10
        version: 20.14.10
    optionalDependencies:
      fsevents:
        specifier: ^2.3.3
        version: 2.3.3

  packages/ui:
    dependencies:
      react:
        specifier: ^18.3.1
        version: 18.3.1

  packages/web:
    dependencies:
      ui-kit:
        specifier: workspace:@shop/ui@*
        version: link:../ui

packages:

  '@types/node@20.14.10':
    resolution: {integrity: sha512-AAAA}

  fsevents@2.3.3:
    resolution: {integrity: sha512-BBBB}
    engines: {node: ^8.16.0 || ^10.6.0 || >=11.0.0}
    os: [darwin]

  is-even@git+https://git.example.com/tools/is-even.git#0123456789abcdef0123456789abcdef01234567:
    resolution: {commit: 0123456789abcdef0123456789abcdef01234567, repo: https://git.example.com/tools/is-even.git, type: git}
    version: 1.0.0

  js-tokens@4.0.0:
    resolution: {integrity: sha512-CCCC}

  left-pad@https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567:
    resolution: {tarball: https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567}
    version: 1.3.0

  local-dir@file:vendor/local-dir:
    resolution: {directory: vendor/local-dir, type: directory}
    version: 0.1.0

  local-tool@file:vendor/local-tool-1.0.0.tgz:
    resolution: {integrity: sha512-KKKK, tarball: file:vendor/local-tool-1.0.0.tgz}
    version: 1.0.0

  loose-envify@1.4.0:
    resolution: {integrity: sha512-DDDD}
    hasBin: true

  ms@2.0.0:
    resolution: {integrity: sha512-EEEE}

  ms@2.1.3:
    resolution: {integrity: sha512-FFFF}

  private-lib@https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz:
    resolution: {tarball: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz}
    version: 2.0.0

  react-dom@18.3.1:
    resolution: {integrity: sha512-GGGG}
    peerDependencies:
      react: ^18.3.1

  react@18.3.1:
    resolution: {integrity: sha512-HHHH}
    engines: {node: '>=0.10.0'}

  scheduler@0.23.2:
    resolution: {integrity: sha512-IIII}

  undici-types@5.26.5:
    resolution: {integrity: sha512-JJJJ}

snapshots:

  '@types/node@20.14.10':
    dependencies:
      undici-types: 5.26.5

  fsevents@2.3.3:
    optional: true

  is-even@git+https://git.example.com/tools/is-even.git#0123456789abcdef0123456789abcdef01234567: {}

  js-tokens@4.0.0: {}

  left-pad@https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567: {}

  local-dir@file:vendor/local-dir: {}

  local-tool@file:vendor/local-tool-1.0.0.tgz: {}

  loose-envify@1.4.0:
    dependencies:
      js-tokens: 4.0.0

  ms@2.0.0: {}

  ms@2.1.3: {}

  private-lib@https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz: {}

  react-dom@18.3.1(react@18.3.1):
    dependencies:
      loose-envify: 1.4.0
      react: 18.3.1
      scheduler: 0.23.2

  react@18.3.1:
    dependencies:
      loose-envify: 1.4.0

  scheduler@0.23.2:
    dependencies:
      loose-envify: 1.4.0

  undici-types@5.26.5: {}
"#;

    /// A checkout of its own for one test, removed after it.
    pub(super) struct Dir(PathBuf);

    impl Dir {
        pub(super) fn new(tag: &str, files: &[(&str, &str)]) -> Dir {
            let dir =
                std::env::temp_dir().join(format!("immunity-lock-{tag}-{}", std::process::id()));
            crate::common::remove(&dir);
            for (name, text) in files {
                let path = dir.join(name);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text).unwrap();
            }
            Dir(dir)
        }

        /// What the reader says of its dependencies: each statement as
        /// `subject|predicate|object|where`, with the checkout's id left out. The lockfiles
        /// found (`HAS_LOCKFILE`) are left to `found`.
        pub(super) fn read(&self) -> (super::Outcome, Vec<String>) {
            let checkout = Checkout {
                rel: "dev/shop".to_string(),
                path: self.0.clone(),
            };
            let o = read(&checkout, "checkout:machine:mac/dev/shop").unwrap();
            let said = o
                .statements
                .iter()
                .filter(|s| s.predicate != HAS_LOCKFILE)
                .map(|s| {
                    let subject = s
                        .subject
                        .replace("component:checkout:machine:mac/dev/shop/", "");
                    let object = s
                        .object
                        .replace("checkout:machine:mac/dev/shop", "checkout");
                    format!("{subject}|{}|{object}|{}", s.predicate, s.source_ref)
                })
                .collect();
            (o, said)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            crate::common::remove(&self.0);
        }
    }

    /// The reason of a reading that could not tell one entry, `<lockfile>#<key>`.
    pub(super) fn one_not_told(at: &str) -> Option<String> {
        Some(format!(
            "the package of 1 entry cannot be told: dev/shop/{at}"
        ))
    }

    #[test]
    fn an_npm_shrinkwrap_is_read_under_its_own_name_and_beside_a_package_lock_neither_hides_the_other()
     {
        // npm 11 and earlier install from `npm-shrinkwrap.json` when both are there, npm 12 from
        // `package-lock.json`, and the folder does not say which npm runs: both are read, and a
        // package of two versions in the two comes out at both.
        let dir = Dir::new(
            "shrinkwrap",
            &[
                ("npm-shrinkwrap.json", &NPM.replace("5.1.2", "5.1.3")),
                ("package-lock.json", NPM),
            ],
        );
        let (o, said) = dir.read();
        for (version, file) in [
            ("5.1.3", "npm-shrinkwrap.json"),
            ("5.1.2", "package-lock.json"),
        ] {
            let fact = format!(
                "npm/string-width|has_version|{version}|dev/shop/{file}#node_modules/string-width"
            );
            assert!(said.contains(&fact), "{fact}: {said:?}");
        }
        assert_eq!((o.completeness, o.reason), ("full", None));
        assert_eq!(
            read_as_text(&dir.0).opened,
            ["npm-shrinkwrap.json", "package-lock.json"]
        );
    }

    #[test]
    fn a_project_with_only_bun_s_binary_lockfile_is_never_one_with_no_lockfile() {
        // Bun's binary `bun.lockb` has no reader: it is named, never opened as text, and leaves
        // npm's packages of the project unknown and no other ecosystem's.
        let dir = Dir::new("bun-lockb", &[("bun.lockb", "bun-lockfile-format-v0\n")]);
        let (o, said) = dir.read();
        assert!(said.is_empty());
        assert_eq!(o.completeness, "partial");
        assert_eq!(lacks(&o), [format!("{LOCKFILE_KIND} bun.lockb")]);
        assert_eq!(unknown_for(&o), [true, false]);
        let texts = read_as_text(&dir.0);
        assert!(texts.opened.is_empty() && texts.not_opened.is_empty());
    }

    #[test]
    fn a_lockfile_of_a_kind_with_no_reader_is_never_opened_and_is_listed_with_its_size() {
        // Its size comes from the folder, so one this user may not open is still named as a
        // kind with no reader, never as a failed reading, and listed with its size. The six
        // Python kinds have a row with no reader yet, and a named `pylock.<name>.toml` is a
        // `pylock.toml`: each leaves PyPI unknown, and npm and crates.io as they were.
        use std::os::unix::fs::PermissionsExt;
        let text = "bun-lockfile-format-v0\n";
        for (file, kind) in [
            ("bun.lockb", "bun.lockb"),
            ("uv.lock", "uv.lock"),
            ("poetry.lock", "poetry.lock"),
            ("pdm.lock", "pdm.lock"),
            ("pylock.toml", "pylock.toml"),
            ("pylock.dev.toml", "pylock.toml"),
            ("Pipfile.lock", "Pipfile.lock"),
            ("requirements.txt", "requirements.txt"),
        ] {
            let dir = Dir::new("kind-closed", &[("Cargo.lock", CARGO), (file, text)]);
            let path = dir.0.join(file);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            let (o, _) = dir.read();
            let texts = read_as_text(&dir.0);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(lacks(&o), [format!("{LOCKFILE_KIND} {kind}")], "{file}");
            assert_eq!(o.gap.cause, Some(Cause::NoReader), "{file}");
            let reason = format!("not supported yet: {kind}");
            assert_eq!(o.reason.as_deref(), Some(reason.as_str()), "{file}");
            let size = text.len() as u64;
            assert!(o.lockfiles.contains(&(format!("dev/shop/{file}"), size)));
            assert_eq!(unknown_for(&o), [kind == "bun.lockb", false], "{file}");
            let names: Vec<Option<String>> = o.gap.lacks.iter().map(|l| l.name.clone()).collect();
            let python = partial_for(&reason, &names, "PyPI");
            assert_eq!(python, kind != "bun.lockb", "{file}");
            assert_eq!(texts.opened, ["Cargo.lock"], "{file}");
            assert!(texts.not_opened.is_empty(), "{file}");
        }
    }

    #[test]
    fn an_entry_not_told_leaves_the_ecosystem_of_its_kind_unknown_and_no_other() {
        // No false calm. The reading names the kind with entries not told in a lack of its own:
        // npm is left in part unknown and crates.io beside it is not, and a kind of any other
        // ecosystem leaves that ecosystem unknown by its lack alone, with no clause counted.
        let text = NPM.replace(
            "registry.npmjs.org/string-width/-/string-width-5.1.2.tgz",
            "registry.npmjs.org/widget/-/widget-5.1.2.tgz",
        );
        let dir = Dir::new(
            "not-told",
            &[("Cargo.lock", CARGO), ("package-lock.json", &text)],
        );
        let (o, _) = dir.read();
        let at = "package-lock.json#node_modules/string-width";
        assert_eq!(o.reason, one_not_told(at));
        assert_eq!(o.gap.cause, Some(Cause::NotGiven));
        assert_eq!(lacks(&o), [format!("{NOT_TOLD} package-lock.json")]);
        assert_eq!(unknown_for(&o), [true, false]);
        // The lack beside a reason whose only clause decides nothing.
        let (uv, words) = (
            [Some("uv.lock".to_string())],
            "not supported yet: flake.lock",
        );
        assert!(partial_for(words, &uv, "PyPI"));
        assert!(!partial_for(words, &uv, "npm") && !partial_for(words, &uv, "crates.io"));
        // A reading written before the lack was recorded still leaves npm unknown by its words.
        let said = one_not_told(at).unwrap();
        assert!(partial_for(&said, &[], "npm") && !partial_for(&said, &[], "crates.io"));
    }

    #[test]
    fn every_kind_with_a_reader_is_read_by_its_own_reader() {
        // A kind is read only by the reader of its row: a sample of each format named as its
        // kind is read in full, and an ecosystem has a reader only where a row of it has one.
        for (kind, sample, ecosystem) in [
            ("package-lock.json", NPM, "npm"),
            ("npm-shrinkwrap.json", NPM, "npm"),
            ("pnpm-lock.yaml", PNPM_9, "npm"),
            ("yarn.lock", YARN, "npm"),
            ("bun.lock", BUN, "npm"),
            ("Cargo.lock", CARGO, "crates.io"),
        ] {
            let (said, reason) = read_one("own-reader", kind, sample);
            assert_eq!(reason, None, "{kind}");
            let of_it = format!("{ecosystem}/");
            assert!(said.iter().any(|s| s.starts_with(&of_it)), "{kind}");
        }
        assert!(has_reader("npm") && has_reader("crates.io"));
        assert!(!has_reader("PyPI") && !has_reader("RubyGems"));
    }

    #[test]
    fn every_ecosystem_a_lockfile_is_read_for_has_a_feed() {
        // Packages read and never compared would read as compared: no place, no lack and no
        // answer would say otherwise. So a reader comes only with data for its ecosystem.
        for (kind, ecosystem, reader) in FORMATS {
            let fed = crate::osv::FEEDS.iter().any(|f| f.ecosystem == ecosystem);
            assert!(reader.is_none() || fed, "{kind}: {ecosystem}");
        }
    }

    #[test]
    fn a_named_pylock_is_a_pylock_toml_and_no_other_name_is() {
        // PEP 751: `pylock.toml`, or `pylock.<name>.toml` with a name holding no dot.
        for name in [
            "pylock.toml",
            "pylock.dev.toml",
            "PyLock.Dev.TOML",
            "pylock.a-b_c.toml",
        ] {
            assert_eq!(lockfile_kind(name), Some("pylock.toml"), "{name}");
        }
        for name in [
            "pylock..toml",
            "pylock.a.b.toml",
            "xpylock.dev.toml",
            "pylock.dev.toml.bak",
            "pylock.dev.tom",
            "pylock-dev.toml",
        ] {
            assert_eq!(lockfile_kind(name), None, "{name}");
        }
    }

    /// A `yarn.lock` of Yarn 4 (`__metadata.version` 8) with every kind of resolution the
    /// reader tells apart, keys sorted as Yarn sorts them. Names and addresses are invented.
    pub(super) const YARN: &str = r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"@jrichman/ink@npm:^6.4.6":
  version: 6.4.6
  resolution: "@jrichman/ink@npm:6.4.6"
  checksum: 10c0/aaaa
  languageName: node
  linkType: hard

"@shop/ui@workspace:packages/ui":
  version: 0.0.0-use.local
  resolution: "@shop/ui@workspace:packages/ui"
  languageName: unknown
  linkType: soft

"dev-tool@portal:../dev-tool::locator=shop%40workspace%3A.":
  version: 0.0.0-use.local
  resolution: "dev-tool@portal:../dev-tool::locator=shop%40workspace%3A."
  languageName: node
  linkType: soft

"fsevents@patch:fsevents@npm%3A^2.3.2#optional!builtin<compat/fsevents>":
  version: 2.3.3
  resolution: "fsevents@patch:fsevents@npm%3A2.3.3#optional!builtin<compat/fsevents>::version=2.3.3&hash=df0bf1"
  conditions: os=darwin
  languageName: node
  linkType: hard

"gen-tool@exec:./scripts/gen-tool.js::locator=shop%40workspace%3A.":
  version: 1.0.0
  resolution: "gen-tool@exec:./scripts/gen-tool.js#./scripts/gen-tool.js::hash=cccc&locator=shop%40workspace%3A."
  languageName: node
  linkType: hard

"left-pad@https://github.com/example/left-pad.git#commit=0123456789abcdef0123456789abcdef01234567":
  version: 1.3.0
  resolution: "left-pad@https://github.com/example/left-pad.git#commit=0123456789abcdef0123456789abcdef01234567"
  languageName: node
  linkType: hard

"linked-dir@link:./vendor/linked-dir::locator=shop%40workspace%3A.":
  version: 0.0.0-use.local
  resolution: "linked-dir@link:./vendor/linked-dir::locator=shop%40workspace%3A."
  languageName: node
  linkType: soft

"local-tool@file:./vendor/local-tool-1.0.0.tgz::locator=shop%40workspace%3A.":
  version: 1.0.0
  resolution: "local-tool@file:./vendor/local-tool-1.0.0.tgz#./vendor/local-tool-1.0.0.tgz::hash=dddd&locator=shop%40workspace%3A."
  languageName: node
  linkType: hard

"private-lib@npm:^2.0.0":
  version: 2.0.0
  resolution: "private-lib@npm:2.0.0::__archiveUrl=https%3A%2F%2Fnpm.example.com%2Fprivate-lib%2F-%2Fprivate-lib-2.0.0.tgz"
  languageName: node
  linkType: hard

"remote-tool@https://example.com/remote-tool-1.0.0.tgz":
  version: 1.0.0
  resolution: "remote-tool@https://example.com/remote-tool-1.0.0.tgz"
  languageName: node
  linkType: hard

"shop@workspace:.":
  version: 0.0.0-use.local
  resolution: "shop@workspace:."
  languageName: unknown
  linkType: soft

"string-width-cjs@npm:string-width@^4.2.0":
  version: 4.2.3
  resolution: "string-width@npm:4.2.3"
  languageName: node
  linkType: hard

"string-width@npm:^5.1.2":
  version: 5.1.2
  resolution: "string-width@npm:5.1.2"
  languageName: node
  linkType: hard
"#;

    /// A `bun.lock` of lockfile version 1 with every kind of row the reader tells apart, and a
    /// comment, which Bun reads. Names and addresses other than the public registry's are
    /// invented.
    pub(super) const BUN: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "shop",
      "dependencies": {
        "ink": "npm:@jrichman/ink@6.4.6",
        "string-width": "^5.1.2",
      },
    },
    "packages/ui": {
      "name": "@shop/ui",
    },
  },
  // Bun writes no comment, and reads one.
  "packages": {
    "@shop/ui": ["@shop/ui@workspace:packages/ui"],

    "dev-tool": ["dev-tool@link:dev-tool", {}],

    "ink": ["@jrichman/ink@6.4.6", "", { "dependencies": { "string-width": "^5.1.2" } }, "sha512-AAAA"],

    "left-pad": ["left-pad@github:example/left-pad#0123456", {}, "example-left-pad-0123456"],

    "local-dir": ["local-dir@file:vendor/local-dir", {}],

    "local-tool": ["local-tool@vendor/local-tool-1.0.0.tgz", {}],

    "private-lib": ["private-lib@2.0.0", "https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz", {}, "sha512-BBBB"],

    "remote-tool": ["remote-tool@https://example.com/remote-tool-1.0.0.tgz", {}],

    "shop": ["shop@root:", {}],

    "string-width": ["string-width@5.1.2", "", {}, "sha512-CCCC"],

    "string-width-cjs": ["string-width@4.2.3", "", {}, "sha512-DDDD"],

    "string-width-cjs/strip-ansi": ["strip-ansi@6.0.1", "https://registry.npmjs.org/strip-ansi/-/strip-ansi-6.0.1.tgz", {}, "sha512-EEEE"],

    "tool-git": ["tool-git@git+ssh://git@github.com/example/tool-git.git#0123456789abcdef0123456789abcdef01234567", {}, "0123456789abcdef0123456789abcdef01234567"],
  }
}
"#;

    /// What a reading of `file` holding `text` says, and its reason.
    pub(super) fn read_one(tag: &str, file: &str, text: &str) -> (Vec<String>, Option<String>) {
        let dir = Dir::new(tag, &[(file, text)]);
        let (o, said) = dir.read();
        (said, o.reason)
    }

    #[test]
    fn the_package_is_what_a_yarn_resolution_or_a_bun_row_names_never_its_key() {
        // Yarn fetches by the resolution and Bun installs the row's first item into the key's
        // folder: a key that names another package is not what is installed.
        let (said, reason) = read_one(
            "yarn-key",
            "yarn.lock",
            &YARN.replace(
                "5.1.2\n  resolution: \"string-width@npm:5.1.2\"",
                "9.0.0\n  resolution: \"evil-width@npm:9.0.0\"",
            ),
        );
        let fact = "npm/evil-width|has_version|9.0.0|dev/shop/yarn.lock#string-width@npm:^5.1.2";
        assert!(said.contains(&fact.to_string()), "{said:?}");
        assert!(!said.iter().any(|s| s.contains("|5.1.2|")), "{said:?}");
        assert_eq!(reason, None);
        let (said, reason) = read_one(
            "bun-key",
            "bun.lock",
            &BUN.replace("[\"string-width@5.1.2\"", "[\"evil-width@9.0.0\""),
        );
        let fact = "npm/evil-width|has_version|9.0.0|dev/shop/bun.lock#string-width";
        assert!(said.contains(&fact.to_string()), "{said:?}");
        assert!(!said.iter().any(|s| s.contains("|5.1.2|")), "{said:?}");
        assert_eq!(reason, None);
    }

    #[test]
    fn a_package_name_is_what_npm_allows_and_never_one_an_address_would_read_another_way() {
        // A name goes into a registry address as text. One a registry would decode, or take for
        // a folder, names another file; an honest name is never refused for its first character
        // inside a scope.
        for name in [
            "widget",
            "@scope/widget",
            "@_sh/widget",
            "@scope/_widget",
            "a.b-c_d~e",
        ] {
            assert!(super::npm_name(name), "{name}");
        }
        for name in [
            "",
            ".",
            "..",
            ".x",
            "_x",
            "x%2Dy",
            "x y",
            "x/y",
            "@/x",
            "@scope/",
            "@scope/..",
            "@../x",
            "@scope/a/b",
            "x?y",
            "x#y",
            "x@y",
        ] {
            assert!(!super::npm_name(name), "{name}");
        }
    }

    #[test]
    fn the_project_itself_is_skipped_whatever_it_is_named() {
        // A workspace or root is no package to judge: a name npm would not publish leaves
        // nothing not told.
        for (tag, file, text) in [
            (
                "yarn-ws",
                "yarn.lock",
                YARN.replace("@shop/ui@workspace", "_widget@workspace"),
            ),
            (
                "bun-ws",
                "bun.lock",
                BUN.replace("\"@shop/ui@workspace", "\"_widget@workspace"),
            ),
            (
                "bun-root",
                "bun.lock",
                BUN.replace("\"shop@root:", "\"_shop@root:"),
            ),
        ] {
            assert_ne!(text, if file == "bun.lock" { BUN } else { YARN }, "{tag}");
            let (_, reason) = read_one(tag, file, &text);
            assert_eq!(reason, None, "{tag}");
        }
    }

    #[test]
    fn yarn_and_bun_lockfiles_beside_a_package_lock_are_each_read_and_none_hides_another() {
        // No lockfile says which manager runs: a package of another version in each comes out
        // at every version, and every one is read as text for the indicators.
        let dir = Dir::new(
            "node-beside",
            &[
                ("package-lock.json", NPM),
                ("yarn.lock", &YARN.replace("5.1.2", "5.1.4")),
                ("bun.lock", &BUN.replace("5.1.2", "5.1.5")),
            ],
        );
        let (o, said) = dir.read();
        for fact in [
            "npm/string-width|has_version|5.1.2|dev/shop/package-lock.json#node_modules/string-width",
            "npm/string-width|has_version|5.1.4|dev/shop/yarn.lock#string-width@npm:^5.1.4",
            "npm/string-width|has_version|5.1.5|dev/shop/bun.lock#string-width",
        ] {
            assert!(said.contains(&fact.to_string()), "{fact}: {said:?}");
        }
        assert_eq!((o.completeness, o.reason), ("full", None));
        assert_eq!(
            read_as_text(&dir.0).opened,
            ["bun.lock", "package-lock.json", "yarn.lock"]
        );
    }

    #[test]
    fn a_project_with_both_an_npm_and_a_pnpm_lockfile_is_read_from_both() {
        // Two lockfiles are two declarations of what the project uses; neither hides the other.
        let dir = Dir::new(
            "npm-and-pnpm",
            &[("package-lock.json", NPM), ("web/pnpm-lock.yaml", PNPM_9)],
        );
        let (o, said) = dir.read();
        assert!(said.contains(
            &"npm/string-width|has_version|5.1.2|dev/shop/package-lock.json#node_modules/string-width"
                .to_string()
        ));
        assert!(said.contains(
            &"npm/ms|has_version|2.1.3|dev/shop/web/pnpm-lock.yaml#ms@2.1.3".to_string()
        ));
        assert_eq!(
            o.lockfiles
                .iter()
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>(),
            ["dev/shop/package-lock.json", "dev/shop/web/pnpm-lock.yaml"]
        );
        assert_eq!(o.completeness, "full");
    }

    /// The lacks of a reading by what and name, as `what name`.
    pub(super) fn lacks(o: &super::Outcome) -> Vec<String> {
        o.gap
            .lacks
            .iter()
            .map(|l| format!("{} {}", l.what, l.name.as_deref().unwrap_or("-")))
            .collect()
    }

    /// Whether the reading leaves each of npm and crates.io in part unknown.
    pub(super) fn unknown_for(o: &super::Outcome) -> [bool; 2] {
        let names: Vec<Option<String>> = o.gap.lacks.iter().map(|l| l.name.clone()).collect();
        let reason = o.reason.as_deref().unwrap_or_default();
        ["npm", "crates.io"].map(|e| o.completeness == "partial" && partial_for(reason, &names, e))
    }

    #[test]
    fn a_lockfile_the_walk_does_not_open_makes_the_reading_partial_for_its_ecosystem_by_its_kind() {
        // No false calm. A lockfile below the folders the reader opens, or in `vendor` or a
        // hidden folder, is named by its kind in a lack of its own, and leaves its ecosystem
        // unknown: never a reading in full beside a `Cargo.lock` at the root.
        for (tag, path, what, eco) in [
            (
                "deep",
                "apps/web/client/ui/desk/package-lock.json",
                DEEPER,
                [true, false],
            ),
            (
                "vendor",
                "vendor/app/package-lock.json",
                SET_ASIDE,
                [true, false],
            ),
            (
                "hidden",
                ".github/actions/deploy/package-lock.json",
                SET_ASIDE,
                [true, false],
            ),
            (
                "deep-cargo",
                "a/b/c/d/tool/Cargo.lock",
                DEEPER,
                [false, true],
            ),
            (
                "vendor-deep",
                "vendor/a/b/c/d/e/pnpm-lock.yaml",
                SET_ASIDE,
                [true, false],
            ),
        ] {
            let dir = Dir::new(tag, &[("Cargo.lock", CARGO), (path, NPM)]);
            let (o, said) = dir.read();
            assert!(!said.iter().any(|s| s.contains("npm/")), "{tag}: {said:?}");
            assert_eq!(o.completeness, "partial", "{tag}");
            assert_eq!(o.gap.cause, Some(Cause::NoReader), "{tag}");
            let kind = file_name(path);
            assert_eq!(lacks(&o), [format!("{what} {kind}")], "{tag}");
            assert!(
                o.reason
                    .as_deref()
                    .unwrap()
                    .contains(&format!("dev/shop/{path}")),
                "{tag}"
            );
            assert_eq!(unknown_for(&o), eco, "{tag}");
            // Not opened, so neither in the copy of what was read nor read as text.
            assert_eq!(o.lockfiles.len(), 1, "{tag}");
            assert_eq!(read_as_text(&dir.0).opened, ["Cargo.lock"], "{tag}");
        }
    }

    #[test]
    fn a_lockfile_of_an_ecosystem_with_no_reader_is_named_as_a_kind_wherever_it_is() {
        // `Pipfile.lock`, `Gemfile.lock` and the rest of the published list are lockfiles: one
        // beside a `Cargo.lock` is a kind with no reader, by name, whether at the root, deep or
        // set aside. It leaves its own ecosystem unknown and no other: a deep `uv.lock` makes
        // PyPI partial and not npm, and a name of no ecosystem a record can be about leaves none.
        for (tag, path, eco) in [
            ("uv-deep", "a/b/c/d/e/uv.lock", Some("PyPI")),
            ("pipfile", "Pipfile.lock", Some("PyPI")),
            ("gemfile", "api/Gemfile.lock", Some("RubyGems")),
            (
                "composer-deep",
                "a/b/c/d/e/composer.lock",
                Some("Packagist"),
            ),
            ("mix-vendor", "vendor/x/mix.lock", Some("Hex")),
            ("pubspec", "app/pubspec.lock", Some("Pub")),
            ("swift", "Package.resolved", Some("SwiftURL")),
            ("flake", "flake.lock", None),
        ] {
            let dir = Dir::new(tag, &[("Cargo.lock", CARGO), (path, "{}\n")]);
            let (o, _) = dir.read();
            let kind = file_name(path);
            assert_eq!(lacks(&o), [format!("{LOCKFILE_KIND} {kind}")], "{tag}");
            assert_eq!(ecosystem_of(kind), eco, "{tag}");
            assert_eq!(o.completeness, "partial", "{tag}");
            assert_eq!(unknown_for(&o), [false, false], "{tag}");
            let names: Vec<Option<String>> = o.gap.lacks.iter().map(|l| l.name.clone()).collect();
            if let Some(eco) = eco {
                assert!(
                    partial_for(o.reason.as_deref().unwrap(), &names, eco),
                    "{tag}"
                );
            }
        }
    }

    #[test]
    fn a_folder_of_installed_copies_build_output_an_environment_or_a_cache_holds_no_lockfile_of_the_project()
     {
        // A project read in full stays full. What `node_modules`, `target`, `.git`, a Python
        // environment's own folders, a conda environment, a tagged cache and another checkout
        // hold is not what the project declares, so a lockfile the look for names finds inside
        // one leaves nothing unknown. A `CACHEDIR.TAG` without its signature marks nothing.
        let tag = std::str::from_utf8(CACHE_SIGNATURE).unwrap();
        let dir = Dir::new(
            "set-aside-not",
            &[
                ("Cargo.lock", CARGO),
                ("node_modules/left-pad/package-lock.json", NPM),
                ("web/node_modules/x/yarn.lock", ""),
                ("target/package/app-0.1.0/Cargo.lock", CARGO),
                (".git/modules/x/package-lock.json", NPM),
                (".venv/pyvenv.cfg", "home = /usr/bin\n"),
                (
                    ".venv/lib/python3.12/site-packages/lab/staging/yarn.lock",
                    "",
                ),
                ("env/pyvenv.cfg", "home = /usr/bin\n"),
                ("env/lib/python3.12/site-packages/lab/staging/yarn.lock", ""),
                (".conda/conda-meta/history", ""),
                (".conda/pkgs/x/package-lock.json", NPM),
                ("envs/py/conda-meta/history", ""),
                ("envs/py/share/a/b/package-lock.json", NPM),
                (".cache/CACHEDIR.TAG", &format!("{tag}\n# a cache\n")),
                (".cache/x/package-lock.json", NPM),
                ("src/a/b/c/d/e/f/main.rs", ""),
            ],
        );
        let (o, _) = dir.read();
        assert_eq!((o.completeness, o.reason.as_deref()), ("full", None));
        assert!(o.gap.lacks.is_empty());
        let read: Vec<&str> = o.lockfiles.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(read, ["dev/shop/Cargo.lock"]);
        // Each is told to the indicators reader as a folder left aside, so that what was known
        // in it is kept.
        let aside = read_as_text(&dir.0).aside;
        for folder in ["node_modules", "target", ".git", ".cache", ".conda"] {
            let at = |a: &String| a.trim_end_matches('/') == folder;
            assert!(aside.iter().any(at), "{folder} {aside:?}");
        }
        let dir = Dir::new(
            "unsigned-tag",
            &[
                ("Cargo.lock", CARGO),
                (
                    ".cache/CACHEDIR.TAG",
                    "Signature: 0000000000000000000000000000000\n",
                ),
                (".cache/x/package-lock.json", NPM),
            ],
        );
        assert_eq!(
            lacks(&dir.read().0),
            [format!("{SET_ASIDE} package-lock.json")]
        );
        // A project's own folder holding such a file is still the project's.
        let dir = Dir::new(
            "marked-root",
            &[("Cargo.lock", CARGO), ("pyvenv.cfg", "home = /usr/bin\n")],
        );
        assert!(!dir.read().1.is_empty());
    }

    #[test]
    fn a_mark_never_changes_which_lockfiles_are_opened() {
        // No false calm. A folder within the four the reader opens is opened as it always was,
        // whatever marks it holds: a `package-lock.json` beside a `pyvenv.cfg`, a signed
        // `CACHEDIR.TAG`, a `conda-meta` or a `.git` is read, and read as text.
        let tag = format!("{}\n", std::str::from_utf8(CACHE_SIGNATURE).unwrap());
        for (mark, text) in [
            ("pyvenv.cfg", "home = /usr/bin\n"),
            ("CACHEDIR.TAG", tag.as_str()),
            ("conda-meta/history", ""),
            (".git", "gitdir: ../.git/worktrees/web\n"),
            (".git/HEAD", "ref: refs/heads/main\n"),
        ] {
            let dir = Dir::new(
                "marked-opened",
                &[
                    (&format!("web/{mark}") as &str, text),
                    ("web/package-lock.json", NPM),
                    ("web/a/b/package-lock.json", NPM),
                ],
            );
            let (o, said) = dir.read();
            assert!(
                said.iter().any(|s| s.contains("npm/string-width")),
                "{mark}"
            );
            assert_eq!(
                (o.completeness, o.reason.as_deref()),
                ("full", None),
                "{mark}"
            );
            assert_eq!(
                read_as_text(&dir.0).opened,
                ["web/a/b/package-lock.json", "web/package-lock.json"],
                "{mark}"
            );
        }
    }

    #[test]
    fn a_lockfile_beside_an_environment_made_in_place_is_still_looked_for() {
        // People make a Python environment in a project's own folder: only the environment's
        // own folders are not looked into, so a lockfile deep beside them is told.
        let dir = Dir::new(
            "venv-in-place",
            &[
                ("Cargo.lock", CARGO),
                ("svc/pyvenv.cfg", "home = /usr/bin\n"),
                (
                    "svc/lib/python3.12/site-packages/x/a/package-lock.json",
                    NPM,
                ),
                ("svc/bin/a/b/c/package-lock.json", NPM),
                ("svc/web/client/ui/desk/package-lock.json", NPM),
            ],
        );
        let (o, _) = dir.read();
        assert_eq!(lacks(&o), [format!("{DEEPER} package-lock.json")]);
        assert!(
            o.reason
                .as_deref()
                .unwrap()
                .ends_with(": dev/shop/svc/web/client/ui/desk/package-lock.json")
        );
    }

    #[test]
    fn another_checkout_inside_a_project_is_not_looked_into() {
        // A worktree an agent made, a submodule or a nested repository is a project of its own:
        // the look for names stops at its `.git`, a file or a folder, and the project stays full.
        let dir = Dir::new(
            "nested-checkout",
            &[
                ("Cargo.lock", CARGO),
                (
                    ".claude/worktrees/x/.git",
                    "gitdir: ../../../.git/worktrees/x\n",
                ),
                (".claude/worktrees/x/package-lock.json", NPM),
                ("vendor/dep/.git/HEAD", "ref: refs/heads/main\n"),
                ("vendor/dep/yarn.lock", ""),
                ("libs/sub/.git", "gitdir: ../../.git/modules/sub\n"),
                ("libs/sub/a/b/c/package-lock.json", NPM),
            ],
        );
        let (o, _) = dir.read();
        assert_eq!((o.completeness, o.reason.as_deref()), ("full", None));
    }

    #[test]
    fn a_lockfile_that_is_a_link_leaves_its_ecosystem_unknown() {
        // A link is not followed, so the lockfile it names is not opened: it is named by its
        // kind and leaves npm unknown, and not crates.io.
        let dir = Dir::new("linked", &[("Cargo.lock", CARGO), ("web/real.json", NPM)]);
        std::os::unix::fs::symlink("real.json", dir.0.join("web/package-lock.json")).unwrap();
        let (o, said) = dir.read();
        assert!(!said.iter().any(|s| s.contains("npm/")));
        assert_eq!(lacks(&o), [format!("{LINKED} package-lock.json")]);
        assert_eq!(unknown_for(&o), [true, false]);
    }

    #[test]
    fn a_lockfile_named_in_another_case_is_read_as_its_kind() {
        // macOS volumes ignore case by default, so npm reads `Package-Lock.json` as its lockfile.
        let dir = Dir::new(
            "case",
            &[("Package-Lock.json", NPM), ("api/CARGO.LOCK", CARGO)],
        );
        let (o, said) = dir.read();
        assert!(said.iter().any(|s| s.contains("npm/string-width")));
        assert!(said.iter().any(|s| s.contains("crates.io/serde")));
        assert_eq!(o.completeness, "full");
    }

    #[test]
    fn ordinary_projects_whose_lockfiles_are_all_opened_stay_read_in_full() {
        // No new partial reading for an ordinary project: lockfiles within four folders,
        // deep source trees, CI configuration and a vendored folder without a lockfile.
        let shapes: [&[(&str, &str)]; 5] = [
            &[("Cargo.lock", CARGO), ("src/a/b/c/d/e/f/g/lib.rs", "")],
            &[("package-lock.json", NPM), (".github/workflows/ci.yml", "")],
            &[
                ("pnpm-lock.yaml", PNPM_9),
                ("apps/web/client/ui/package-lock.json", NPM),
                ("packages/ui/src/a/b/c/d/index.ts", ""),
            ],
            &[("Cargo.lock", CARGO), ("vendor/lib/src/a.c", "")],
            &[
                ("app/package-lock.json", NPM),
                (".vscode/settings.json", "{}"),
            ],
        ];
        for (i, files) in shapes.iter().enumerate() {
            let dir = Dir::new(&format!("ordinary-{i}"), files);
            let (o, said) = dir.read();
            assert_eq!((o.completeness, o.reason.as_deref()), ("full", None), "{i}");
            assert!(!said.is_empty(), "{i}");
        }
    }

    #[test]
    fn folders_past_the_look_through_limit_leave_every_ecosystem_unknown() {
        // The walk below the folders it opens is bounded; what it did not look through is not
        // known to hold no lockfile, so it is a lack with no name, for every ecosystem.
        // `vendor` and the folders in it, as many as the walk looks through.
        let dir = Dir::new(
            "look-limit",
            &[
                ("Cargo.lock", CARGO),
                ("vendor/1/a", ""),
                ("vendor/2/a", ""),
            ],
        );
        let checkout = Checkout {
            rel: "dev/shop".to_string(),
            path: dir.0.clone(),
        };
        let within = |limit| read_within(&checkout, "checkout:machine:mac/dev/shop", limit);
        let o = within(3).unwrap();
        assert_eq!((o.completeness, o.reason), ("full", None));
        let o = within(2).unwrap();
        assert_eq!(lacks(&o), [format!("{NOT_LOOKED} -")]);
        assert_eq!(o.gap.cause, Some(Cause::NoReader));
        assert_eq!(unknown_for(&o), [true, true]);
        // Without a lockfile where it opens them, such a project is still not one with none.
        std::fs::remove_file(dir.0.join("Cargo.lock")).unwrap();
        assert_eq!(within(2).unwrap().completeness, "partial");
    }

    #[test]
    fn a_folder_that_could_not_be_listed_is_named_with_what_the_system_said_and_leaves_every_ecosystem_unknown()
     {
        // The status tells a folder this user may not open from another failure by the
        // system's words, and the clause naming it is taken for every ecosystem.
        use std::os::unix::fs::PermissionsExt;
        let dir = Dir::new("unlisted", &[("web/package-lock.json", NPM)]);
        let web = dir.0.join("web");
        std::fs::set_permissions(&web, std::fs::Permissions::from_mode(0o000)).unwrap();
        let (o, _) = dir.read();
        let texts = read_as_text(&dir.0);
        std::fs::set_permissions(&web, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            o.reason.as_deref(),
            Some("1 folder could not be listed: dev/shop/web (Permission denied (os error 13))")
        );
        assert_eq!(o.gap.cause, Some(Cause::Failed));
        assert_eq!(unknown_for(&o), [true, true]);
        assert_eq!(
            texts.unlisted,
            [(
                "web/".to_string(),
                "Permission denied (os error 13)".to_string()
            )]
        );
    }

    #[test]
    fn what_a_reading_did_not_open_is_decided_from_its_lacks_and_never_from_its_words() {
        // The words of a reason are for a person: a clause about a lockfile not opened or a
        // kind with no reader decides nothing, its lack does.
        let said = "not opened: 1 lockfile deeper than 4 folders: a/b/c/d/e/Cargo.lock; \
                    not supported yet: yarn.lock";
        for eco in ["npm", "crates.io"] {
            assert!(!partial_for(said, &[], eco), "{eco}");
        }
        let npm = [Some("package-lock.json".to_string())];
        assert!(partial_for(said, &npm, "npm"));
        assert!(!partial_for(said, &npm, "crates.io"));
        for eco in ["npm", "crates.io"] {
            assert!(partial_for(said, &[None], eco), "{eco}");
            assert!(
                !partial_for(said, &[Some("flake.lock".to_string())], eco),
                "{eco}"
            );
        }
    }
}
