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
use crate::look::{Look, Said, Unread};
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
mod source;
mod uv;
mod yarn;

use bun::bun;
use cargo::cargo;
pub use commit::commit;
use npm::npm;
use pnpm::pnpm;
pub use pypi::pypi_normalized;
pub use source::{Source, component_name, split_name};
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
/// A lockfile, or git's `packed-refs`, larger than this is not read: the cap this build has
/// for a file read whole. A real one is far under it.
const CAP: u64 = crate::targets::CAP;
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
/// reading names it has no reader for, `lacks` by their names (a kind with no reader, a lockfile
/// not opened, a kind with entries not told), leaves the ecosystem of each name unknown and no
/// other: a name of no ecosystem a record can be about, such as `flake.lock`, leaves none. A
/// lack with no name, folders not looked through, counts for every ecosystem. The rows of what
/// it did not read (`store::unread_of`) decide the rest, those with no reader aside, which their
/// lacks say: a lockfile that could not be read or has entries not told counts for the
/// ecosystem its file's name gives; anything else, a folder not listed or what is no unit,
/// counts for every ecosystem, so that nothing reads as fully known that is not. The reason is
/// words for a person and decides nothing.
pub fn partial_for(
    rows: &[crate::store::Unread],
    lacks: &[Option<String>],
    ecosystem: &str,
) -> bool {
    let of_it = |name: &str| ecosystem_of(name) == Some(ecosystem);
    let lockfile = [Said::Lockfile("").word(), Said::Untold.word()];
    lacks.iter().any(|name| name.as_deref().is_none_or(of_it))
        || (rows.iter())
            .filter(|u| u.cause != Cause::NoReader.literal())
            .any(|u| match &u.path {
                Some(path) if lockfile.contains(&u.how.as_str()) => {
                    ecosystem_of_file(path).is_none_or(|e| e == ecosystem)
                }
                _ => true,
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
/// and what it looked at (`Look`), each unit by its path as the reading names it. A folder
/// listed is read; a folder that could not be listed in full and an entry named as a lockfile
/// that is neither a regular file nor a link are units not read, with why; what it passes over
/// by design, every entry of a folder listed that it neither goes into nor opens and a folder
/// a mark sets aside, is aside; and folders the look limit kept it from looking through are
/// said together, with a lack of no name.
struct Walk {
    lockfiles: Vec<(String, &'static str, Where)>,
    look: Look,
}

/// How a walk says what it did not read, in the words of the reading it is for: a folder it
/// could not list, a lockfile of a kind with a reader that is not a regular file, and what lies
/// past its limit.
struct Say {
    folder: Said,
    file: fn(&'static str) -> Said,
    stopped: String,
}

/// Whether a file is a cache's tag: `CACHE_MARK` beginning with its signature.
fn cache_tag(name: &str, path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; CACHE_SIGNATURE.len()];
    name == CACHE_MARK
        && crate::open::open(path, crate::open::Reach::Place, crate::open::UNCAPPED)
            .is_ok_and(|(mut f, _)| f.read_exact(&mut head).is_ok())
        && head == CACHE_SIGNATURE
}

/// Walks a checkout for lockfiles: opened down to `MAX_DEPTH`, as they always were, and below
/// it and in folders set aside looked for by name only, at most `limit` folders. Links are not
/// followed. A folder a mark says is not the project's is not looked at by that look; where
/// lockfiles are opened, marks change nothing. Units are named `prefix` and the path relative
/// to the checkout.
fn walk(checkout: &Path, prefix: &str, limit: usize, say: Say) -> Walk {
    let mut out = Walk {
        lockfiles: Vec::new(),
        look: Look::default(),
    };
    let unit = |rel: &str| Unit::whole(format!("{prefix}{rel}"));
    let (mut looked, mut stopped) = (0, false);
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
                stopped = true;
                continue;
            }
            looked += 1;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                out.look
                    .unread_as(unit(&rel), say.folder, e.raw_os_error(), e.to_string());
                continue;
            }
        };
        out.look.present += 1;
        let (mut files, mut special, mut folders, mut missed) =
            (Vec::new(), Vec::new(), Vec::new(), None);
        let (mut environment, mut whole) = (false, not_own);
        for entry in entries {
            let (entry, file_type) = match entry.and_then(|e| e.file_type().map(|t| (e, t))) {
                Ok(found) => found,
                Err(e) => {
                    missed.get_or_insert(e);
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
            // A file is known by its name: nothing lies under it. A kind with no reader is never
            // opened, so it is that kind whatever the entry is.
            let (kind, link) = (lockfile_kind(&name), file_type.is_symlink());
            let no_reader = kind.is_some_and(|kind| reader_of(kind).is_none());
            if file_type.is_file() || no_reader {
                files.extend(kind.map(|kind| (name, kind, at)));
                continue;
            }
            // A lockfile of a kind with a reader that is neither a regular file nor a link, such
            // as a named pipe, is met and cannot be read: it is never opened, and said with what
            // it is.
            if let (false, Some(kind)) = (link, kind) {
                let what = crate::open::kind_of(file_type);
                special.push((name, (say.file)(kind), what));
                continue;
            }
            // Neither gone into nor opened, whatever the reason: a folder never entered, a link
            // of any kind, which is not followed, or an entry of another kind. Indicator matches
            // under it are kept; the packages read there before are let go, and the reading stays
            // full. A lockfile that is a link is also said.
            out.look.aside(unit(&format!("{rel}{name}")));
            if link {
                files.extend(kind.map(|kind| (name, kind, Where::Linked)));
            }
        }
        match missed {
            Some(e) => {
                let errno = e.raw_os_error();
                out.look
                    .unread_as(unit(&rel), say.folder, errno, e.to_string());
            }
            None => out.look.listed(unit(&rel)),
        }
        // The look for names does not look at what a mark says is not the project's.
        if at != Where::Opened && whole {
            out.look.aside(unit(&rel));
            continue;
        }
        for (name, said, what) in special {
            let why = format!("{}{what}", crate::watched::NOT_A_FILE);
            out.look
                .unread_as(unit(&format!("{rel}{name}")), said, None, why);
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
    if stopped {
        out.look.short_of([unit("")], Cause::NoReader, say.stopped);
        out.look.lack(Lack::new(NOT_LOOKED, None));
    }
    out.lockfiles.sort();
    out
}

/// What one walk of a checkout gives the indicators reader to look for strings in: the
/// lockfiles of the kinds read here that are opened as text and those found and not opened,
/// relative to the checkout, and what the walk did not read (`Walk`) in the words of that
/// reader, each unit by its path relative to the home folder.
pub struct Texts {
    pub opened: Vec<String>,
    pub not_opened: Vec<String>,
    pub look: Look,
}

/// Whether the file at `rel` in a checkout is one the walk of `read_as_text` looks for: a
/// lockfile, by its name in any case. Where it lies decides only whether it is opened.
pub fn looked_for_as_text(rel: &str) -> bool {
    lockfile_kind(rel.rsplit('/').next().unwrap_or(rel)).is_some()
}

pub fn read_as_text(checkout: &Checkout) -> Texts {
    let say = Say {
        folder: Said::Failed,
        file: |_| Said::Failed,
        stopped: format!(
            "lockfiles were not looked for past the walk's limit in {}",
            checkout.rel
        ),
    };
    let prefix = format!("{}/", checkout.rel);
    let walked = walk(&checkout.path, &prefix, LOOK_LIMIT, say);
    let (opened, not_opened) = (walked.lockfiles.into_iter())
        .filter(|(_, kind, _)| reader_of(kind).is_some())
        .partition::<Vec<_>, _>(|(_, _, at)| *at == Where::Opened);
    let paths = |found: Vec<(String, &str, Where)>| found.into_iter().map(|(p, ..)| p).collect();
    Texts {
        opened: paths(opened),
        not_opened: paths(not_opened),
        look: walked.look,
    }
}

/// Reads one checkout. `None` when it holds no lockfile at all: then there is nothing
/// to cover. Where the checkout is, is said by the `checkouts` reader.
pub fn read(checkout: &Checkout, id: &str) -> Option<Outcome> {
    read_within(checkout, id, LOOK_LIMIT, CAP)
}

/// `read`, with the look for names below the folders opened stopping after `limit` folders,
/// and lockfiles read up to `cap`.
fn read_within(checkout: &Checkout, id: &str, limit: usize, cap: u64) -> Option<Outcome> {
    let prefix = if checkout.rel == "." {
        String::new()
    } else {
        format!("{}/", checkout.rel)
    };
    let say = Say {
        folder: Said::Unlisted,
        file: Said::Lockfile,
        stopped: format!(
            "{NOT_OPENED_SAID}what lies past the first {limit} folders looked through \
             for lockfiles below {MAX_DEPTH} folders or in vendor and hidden folders"
        ),
    };
    let walked = walk(&checkout.path, &prefix, limit, say);
    if walked.lockfiles.is_empty() && walked.look.cause().is_none() {
        return None;
    }
    let mut look = Look::default();
    // Kinds and versions with no reader, with the lockfiles of each.
    let mut not_supported: BTreeMap<String, Vec<Unit>> = BTreeMap::new();
    let mut not_told_kinds: BTreeSet<&str> = BTreeSet::new();
    // Lockfiles of a kind read here that were not opened, by where, and their kinds.
    let mut not_opened: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut lacks: BTreeSet<(&'static str, &str)> = BTreeSet::new();
    let mut lockfiles = Vec::new();
    // (ecosystem, name with its source) -> where it was first read, and version -> where
    // that version was first read.
    let mut deps: BTreeMap<(&str, String), Found> = BTreeMap::new();
    let mut no_reader = |kind: String, unit| not_supported.entry(kind).or_default().push(unit);

    for (rel, kind, at) in &walked.lockfiles {
        let source = format!("{prefix}{rel}");
        let (name, unit): (&str, _) = (kind, Unit::whole(&source));
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
                no_reader(name.to_string(), unit);
            }
            continue;
        }
        let path = checkout.path.join(rel);
        // Its size is the file's own, never what was read of it, 0 when that cannot be had. A
        // kind with no reader is never opened.
        let size = std::fs::symlink_metadata(&path).map_or(0, |m| m.len());
        lockfiles.push((source.clone(), size));
        let Some(reader) = reader_of(name) else {
            no_reader(name.to_string(), unit);
            continue;
        };
        // Opened as the walk found it: a regular file, a link in its place not followed,
        // without waiting, up to the cap. One refused could not be read.
        let text = crate::open::read(&path, crate::open::Reach::Place, cap)
            .map_err(|e| (e.errno(), e.to_string()))
            .and_then(|t| String::from_utf8(t).map_err(|_| (None, "not UTF-8 text".to_string())));
        let parsed = match text {
            Err((errno, why)) => {
                look.unread_as(unit, Said::Lockfile(name), errno, why);
                continue;
            }
            Ok(t) => reader(&t, name),
        };
        let (ecosystem, found) = match parsed {
            Parsed::Deps(ecosystem, found, unknown) => {
                if !unknown.is_empty() {
                    not_told_kinds.insert(name);
                }
                // Never a guess: an entry that is not known to be the package it names is
                // left out, and the reading is partial, so it never says that a package is
                // not there.
                for key in &unknown {
                    look.unread_as(Unit::part(&source, key), Said::Untold, None, String::new());
                }
                look.read(unit);
                (ecosystem, found)
            }
            Parsed::NoReader(kind) => {
                no_reader(kind, unit);
                continue;
            }
            Parsed::Failed => {
                let why = "it could not be parsed".to_string();
                look.unread_as(unit, Said::Lockfile(name), None, why);
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

    // Kinds with no reader and lockfiles not opened where they are are said together, each with
    // its lack by name, so that what it leaves unknown is decided from the lacks (`partial_for`).
    if !not_supported.is_empty() {
        let names: Vec<&str> = not_supported.keys().map(String::as_str).collect();
        let why = format!("{NOT_SUPPORTED_SAID}{}", names.join(", "));
        let units = not_supported.values().flatten().cloned();
        look.short_of(units, Cause::NoReader, why);
    }
    for (what, paths) in &not_opened {
        let place = match *what {
            DEEPER => format!("deeper than {MAX_DEPTH} folders"),
            LINKED if paths.len() == 1 => "that is a link".to_string(),
            LINKED => "that are links".to_string(),
            _ => "in vendor or hidden folders".to_string(),
        };
        let n = counted(paths.len(), "lockfile", "lockfiles");
        let why = format!("{NOT_OPENED_SAID}{n} {place}: {}", some_of(paths));
        look.short_of(paths.iter().map(Unit::whole), Cause::NoReader, why);
    }
    for name in not_supported.keys() {
        look.lack(Lack::new(LOCKFILE_KIND, Some(name)));
    }
    for (what, name) in lacks {
        look.lack(Lack::new(what, Some(name)));
    }
    for name in not_told_kinds {
        look.lack(Lack::new(NOT_TOLD, Some(name)));
    }
    look.add(walked.look);
    let (completeness, reason) = look.completeness_noted(None);
    Some(Outcome {
        completeness,
        reason,
        gap: look.gap(),
        statements,
        lockfiles,
    })
}

/// The clause of the units of one kind a reading of lockfiles did not read (`look::Said`):
/// lockfiles that could not be read, by their kinds; entries whose package cannot be told; and
/// folders that could not be listed in full, each with what the system said. Words for a person:
/// `partial_for` decides by the rows.
pub fn said(units: &[&Unread]) -> String {
    let n = units.len();
    let some = |each: fn(&Unread) -> String| {
        let named: Vec<String> = units.iter().map(|u| each(u)).collect();
        some_of(&named)
    };
    match units[0].said {
        Said::Lockfile(_) => {
            let kinds: BTreeSet<&str> = (units.iter())
                .filter_map(|u| match u.said {
                    Said::Lockfile(kind) => Some(kind),
                    _ => None,
                })
                .collect();
            format!("could not be read: {}", Vec::from_iter(kinds).join(", "))
        }
        Said::Untold => format!(
            "the package of {} cannot be told: {}",
            counted(n, "entry", "entries"),
            some(|u| format!("{}#{}", u.unit.path, u.unit.part))
        ),
        _ => format!(
            "{} could not be listed: {}",
            counted(n, "folder", "folders"),
            some(|u| format!("{} ({})", u.unit, u.why))
        ),
    }
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

/// npm's public registry. An entry is from it when its address is here; one that names no
/// address is from an unrecorded index. An address here is the package's own only as
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
mod tests;
