//! The `integrity` reader: whether what is installed changed while its version did not.
//! Persistence needs no autostart item: code appended to a program the owner starts every
//! day runs just as well. For every installed thing that has a version, content that
//! changed while the version stayed is the signal. This reader makes it visible as an
//! ordinary lifecycle event; turning that into a finding is a rule's work, see
//! `changed_in_place`.
//!
//! Three kinds of thing, each one reading scoped to the machine:
//!
//! - **Application bundles** in `/Applications` and `~/Applications`, direct children named
//!   `*.app`, and those one folder down (`/Applications/<folder>/<name>.app`), since
//!   installers put suites there. A symbolic link is not followed. Each is a component of
//!   the ecosystem `macos-app`, named by its bundle identifier, else by its folder name: its
//!   version, who signed it, whether its seal verifies, where it is, and a digest.
//! - **Homebrew kegs**, `<prefix>/Cellar/<name>/<version>` under the two prefixes Homebrew
//!   installs to. Each keg is a `file` entity named by its path, so a new version is a new
//!   entity and a file changed inside a keg is a `changed` digest of the same one.
//! - **Global npm packages**, `<prefix>/lib/node_modules/<name>` under the same prefixes, where
//!   Homebrew's node puts them. Each is a component of the ecosystem `npm`: version and digest.
//!
//! The digest is over every file's path and change time, never over content: content is never
//! read or kept. The kernel sets the change time on every write, rename, link and change of
//! mode, and a process cannot set it (setattrlist(2)), so a file written and given back its
//! old modification time still moves the digest; size, inode and modification time add
//! nothing to it. Folders themselves are left out, so that macOS adding an attribute to a
//! bundle's folder is not a change; so are Python's `__pycache__` folders, which Python writes
//! into kegs on its own.
//!
//! The seal of a bundle is verified by the Security framework (`codesign.rs`), with nested
//! code, every architecture and strict validation, which takes most of a minute for a
//! Mac's applications. So it is verified only for a bundle whose digest changed
//! since the last reading, or that has no verdict yet; otherwise the last verdict is carried
//! forward, and the reading's note says from when. Who signed it is asked on every reading:
//! that takes the signature alone.

use crate::baseline::Unit;
use crate::codesign;
use crate::look::{Look, NOT_HERE, Said};
use crate::store::{Gap, Statement};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

mod changes;
pub use changes::{LIST_CAP, changes_input, compare, files_changed, kept_file, list_input};

pub const READER: &str = "integrity";
pub const BASIS: &str = "observed";
pub const BUNDLES: &str = "application bundles in /Applications and ~/Applications";
pub const KEGS: &str = "Homebrew kegs";
pub const NPM: &str = "global npm packages";
pub const APP_SUPPORT: &str =
    "code kept by applications not signed by Apple under ~/Library/Application Support";
/// The raw copy: one line per thing with its path and facts, never content.
pub const RAW: &str = "integrity.txt";
/// Where Homebrew installs, Apple Silicon first, as paths from `/`.
const PREFIXES: [&str; 2] = ["opt/homebrew", "usr/local"];
/// Where Homebrew keeps kegs under a prefix.
const CELLAR: &str = "Cellar";
/// Where npm keeps global packages under a prefix.
const NODE_MODULES: &str = "lib/node_modules";
/// Folders a digest leaves out: Python writes them into a keg when it imports a module.
const SKIPPED: [&str; 1] = ["__pycache__"];

/// Kinds of file that are code, by extension: scripts, native modules and libraries, and
/// archives of code. A file anyone may run is code too, whatever its name, and so is a symbolic
/// link unless it leads nowhere or to a socket, a pipe or a device (`is_code`). Python's compiled
/// files are left out: Python writes them by itself.
const CODE: [&str; 13] = [
    "js", "mjs", "cjs", "node", "dylib", "so", "py", "asar", "jar", "wasm", "sh", "rb", "lua",
];
/// Folders applications fill by themselves as they run: caches, web storage, crash reports and
/// logs. Code there is not compared. A name containing `cache` is one too.
const NOT_CODE: [&str; 7] = [
    "service worker",
    "indexeddb",
    "local storage",
    "session storage",
    "blob_storage",
    "crashpad",
    "logs",
];
/// How deep under a matched folder, and how many code files in it, are compared. A folder over
/// either is not recorded, and the reading says so.
const MAX_DEPTH: usize = 16;
const MAX_FILES: usize = 20_000;

/// What a reading's note says the reader cannot judge, kind by kind.
const BUNDLES_CANNOT: &str = "not covered: extended attributes, which no seal covers; a bundle changed and signed again shows only as another signer at the same version; an application that updates itself in place shows as a change of its digest";
const KEGS_CANNOT: &str = "compared by files' metadata between readings, since Homebrew keeps no record of a keg's files to verify against; __pycache__ folders are not compared";
const APP_SUPPORT_CANNOT: &str = "compared by the metadata of code files between readings, a symbolic link among them unless it leads nowhere or to a socket, a pipe or a device; only a folder named like an application read here that Apple did not sign is looked into, and one an earlier reading held for as long as it is there, so code kept under another name is not compared; caches, web storage, crash reports and logs are not compared";
const NPM_CANNOT: &str = "compared by files' metadata between readings, since npm keeps no record of a global package's files to verify against; a global folder set in npm's configuration or by a version manager is not looked for, and a linked package is not read";

/// Where places are resolved: the home folder, and the root of the system, `/` unless a test
/// gives another. `store` is the store this run writes, whose folder is the program's own.
pub struct Roots<'a> {
    pub home: &'a Path,
    pub system: &'a Path,
    pub store: &'a Path,
}

/// One thing read: its entity, its path as ids name it, its facts, and how its verdict was
/// reached, for the raw copy. A thing whose only evidence is its digest keeps the list the digest
/// is made over, so that a change can say which files moved (`compare`); a bundle has none, its
/// evidence being its seal and signer.
pub struct Thing {
    pub subject: String,
    pub shown: String,
    pub facts: Vec<(&'static str, String)>,
    pub how: String,
    pub list: Option<Vec<u8>>,
}

/// One reading: a kind of thing on this machine.
pub struct Kind {
    pub kind: &'static str,
    pub things: Vec<Thing>,
    /// The places of this kind listed and what was not recorded, each with why: a place or
    /// thing that could not be read, one whose name another took first, one over a cap, one
    /// that leads into a folder macOS asks permission for. Its places there are `present`.
    pub look: Look,
    /// What the full reading's note says besides what it cannot judge.
    pub notes: Vec<String>,
    cannot: &'static str,
}

impl Kind {
    fn new(kind: &'static str, cannot: &'static str) -> Kind {
        Kind {
            kind,
            things: Vec::new(),
            look: Look::default(),
            notes: Vec::new(),
            cannot,
        }
    }

    /// Completeness, the reason or note, and why it is incomplete, as `look` says them, with
    /// the notes and what the reader cannot judge last. A place that is not there is not a
    /// failure; a place or thing not recorded makes the reading partial, so nothing of this
    /// kind is retracted, or none when nothing there was read.
    pub fn coverage(&self) -> (&'static str, Option<String>, Gap) {
        let notes = self.notes.iter().map(String::as_str);
        let note = notes.chain([self.cannot]).collect::<Vec<_>>().join("; ");
        let (completeness, reason) = self.look.completeness_here(NOT_HERE, Some(note));
        (completeness, reason, self.look.gap())
    }

    /// A place of this kind there, listed.
    fn listed(&mut self, shown: &str) {
        self.look.present += 1;
        self.look.listed(Unit::whole(shown));
    }

    /// A place or thing there that could not be read, with the system's error number and why.
    fn failed(&mut self, shown: String, errno: Option<i32>, why: String) {
        self.look.not_looked_at(Unit::whole(shown), errno, why);
    }

    /// A place or thing there that the system kept from being read, as it said.
    fn refused(&mut self, shown: String, e: &std::io::Error) {
        self.failed(shown, e.raw_os_error(), e.to_string());
    }

    /// A thing seen and not recorded, as `said` says, with why.
    fn not_recorded(&mut self, shown: String, said: Said, why: String) {
        self.look.unread_as(Unit::whole(shown), said, None, why);
    }

    /// The statements of this reading, each pointing at its line of the raw copy.
    pub fn statements(&self, raw_file: &str, lines: &[usize]) -> Vec<Statement> {
        let mut out = Vec::new();
        for (t, line) in self.things.iter().zip(lines) {
            for (predicate, object) in &t.facts {
                out.push(Statement {
                    subject: t.subject.clone(),
                    predicate,
                    object: object.clone(),
                    source_ref: format!("{raw_file}:{line}"),
                });
            }
        }
        out
    }
}

/// Reads every kind of thing. `conn` holds the last verdicts, carried forward for bundles that
/// did not move; `machine` is this machine's id.
pub fn read(conn: &Connection, roots: &Roots, machine: &str) -> rusqlite::Result<Vec<Kind>> {
    let bundles = bundles(conn, roots, machine)?;
    let held = held_folders(conn, machine)?;
    let app_support = app_support(roots, machine, &bundles, &held);
    Ok(vec![
        bundles,
        kegs(roots, machine),
        npm(roots, machine),
        app_support,
    ])
}

/// What a code walk ran into.
enum Walked {
    Done,
    /// Over a cap: which one.
    Capped(String),
}

/// The records of every code file under `dir`, by path and change time, as `walk` makes them,
/// within the caps. A symbolic link is recorded as itself and never walked into (`is_code`).
fn walk_code(
    dir: &Path,
    rel: &[u8],
    depth: usize,
    out: &mut Vec<u8>,
    files: &mut usize,
    homes: &[&Path],
) -> std::io::Result<Walked> {
    let mut names = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<OsString>>>()?;
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let m = std::fs::symlink_metadata(&path)?;
        let text = name.to_string_lossy().to_lowercase();
        let mut here = rel.to_vec();
        here.push(b'/');
        here.extend_from_slice(name.as_bytes());
        if m.is_dir() {
            if text.contains("cache") || NOT_CODE.contains(&text.as_str()) {
                continue;
            }
            if depth == MAX_DEPTH {
                return Ok(Walked::Capped(format!("deeper than {MAX_DEPTH} folders")));
            }
            if let Walked::Capped(cap) = walk_code(&path, &here, depth + 1, out, files, homes)? {
                return Ok(Walked::Capped(cap));
            }
            continue;
        }
        if !is_code(&path, &m, &text, homes) {
            continue;
        }
        *files += 1;
        if *files > MAX_FILES {
            return Ok(Walked::Capped(format!("more than {MAX_FILES} code files")));
        }
        out.extend_from_slice(&here);
        out.extend_from_slice(format!("\0{}.{}\n", m.ctime(), m.ctime_nsec()).as_bytes());
    }
    Ok(Walked::Done)
}

/// Whether an entry under a folder of code that is not a folder is code: by a code extension,
/// whatever it is; a regular file by its execute bit; a symbolic link by what it leads to.
fn is_code(path: &Path, m: &std::fs::Metadata, name: &str, homes: &[&Path]) -> bool {
    if CODE.contains(&name.rsplit_once('.').map_or("", |(_, e)| e)) {
        return true;
    }
    if m.file_type().is_symlink() {
        return leads_to_code(path, homes);
    }
    // A socket or a pipe an app keeps while it runs has execute bits too, and cannot be run.
    m.is_file() && m.mode() & 0o111 != 0
}

/// Whether a symbolic link with no code extension may lead to code. It may, unless nothing is
/// there, or what it leads to is a socket, a pipe or a device, which cannot be run. An app that
/// runs keeps such links beside its code and removes them as it quits, as Chromium does with its
/// single-instance lock, cookie and socket. A link to a regular file counts whatever the file's
/// mode and name, since an app can hand any file to its interpreter, and a link to a folder
/// counts, since which folder it names decides which code runs. The link is followed one part
/// at a time by `guarded::real`, which never looks into a folder macOS asks permission for and
/// counts the links it passes; a link that leads into one, or that cannot be followed for any
/// reason but nothing being there, counts. Anything the second look does not name, or cannot
/// make, stays compared: a link swapped in after `real` answered among them. Nothing it leads to
/// is opened.
fn leads_to_code(link: &Path, homes: &[&Path]) -> bool {
    use std::os::unix::fs::FileTypeExt;
    let to = match crate::guarded::real(link, homes) {
        crate::guarded::Real::At(to) => to,
        crate::guarded::Real::Guarded(_) => return true,
        crate::guarded::Real::Failed(e) => return e.kind() != ErrorKind::NotFound,
    };
    let Ok(m) = std::fs::symlink_metadata(&to) else {
        return true;
    };
    let t = m.file_type();
    !(t.is_socket() || t.is_fifo() || t.is_block_device() || t.is_char_device())
}

/// Code that applications keep outside their bundle, in `~/Library/Application Support`.
///
/// Only folders there whose name is, ignoring case, the bundle identifier or the name of an
/// application just read that Apple did not sign are looked into; the folder itself is listed
/// for names alone, and no other folder in it is ever opened. macOS guards some folders there
/// with a dialog or with Full Disk Access (contacts, call history, its own services), all
/// Apple's, so a folder named after an application from another developer is not one of them.
/// Each matched folder is one `file` entity with the version of its application, so a change
/// of its code while that version stayed is a `changed` digest with no `has_version` event.
///
/// The folder that holds the store in use is left out, whatever application it is named after.
/// It holds the program's own output: pages rewritten every few seconds and the scripts it
/// writes for the owner, so a change there says nothing about an application. And whoever can
/// write there can rewrite the store itself, which is not guarded against yet (`AGENTS.md`).
///
/// A folder the store holds or held, `held`, is opened whenever it is there, whether or not an
/// application read now matches it. Otherwise removing an application, or moving it out of the
/// places bundles are looked for, would stop the folder being opened while this reading stayed
/// full, and the lifecycle would retract it as looked for and not found: code that is still on
/// disk, and may still be run, would read as gone, and a change to it as nothing. Such a folder
/// keeps the version its application last had, since nothing says it has another, and the
/// reading's note names it. So a folder is retracted only while it is not there, or while no
/// application read now matches it and it holds no code file this reading compares: what an
/// uninstaller leaves, such as a settings file, is not code to hold. One that comes back is read
/// as for the first time, and compared from then on. Folders are matched by the key a Mac's
/// volumes compare names by (`spelling::key`).
fn app_support(
    roots: &Roots,
    machine: &str,
    bundles: &Kind,
    held: &BTreeMap<String, Held>,
) -> Kind {
    let mut kind = Kind::new(APP_SUPPORT, APP_SUPPORT_CANNOT);
    // Each name of an application not signed by Apple, by its key, with its version.
    let mut names: BTreeMap<String, Option<String>> = BTreeMap::new();
    for t in &bundles.things {
        let fact = |p: &str| t.facts.iter().find(|(q, _)| *q == p).map(|(_, o)| o);
        if fact("signed_by").is_some_and(|s| s == "apple") {
            continue;
        }
        let version = fact("has_version").cloned();
        for name in app_names(&t.subject, &t.shown) {
            names.entry(name).or_insert_with(|| version.clone());
        }
    }
    // An application that could not be read is not matched: its folder must not look gone.
    for u in bundles.look.not_read().filter(|u| u.said == Said::Failed) {
        kind.failed(
            u.unit.to_string(),
            u.errno,
            "applications there could not be read, so their folders were not looked for"
                .to_string(),
        );
    }
    let base = roots.home.join(APP_SUPPORT_PLACE);
    if !reachable(&base, APP_SUPPORT_PLACE, roots, &mut kind) {
        return kind;
    }
    let entries = match list(&base) {
        None => return kind,
        Some(Err(e)) => {
            kind.refused(APP_SUPPORT_PLACE.to_string(), &e);
            return kind;
        }
        Some(Ok(entries)) => entries,
    };
    let own = roots.store.parent().map(same_place);
    let [home, real_home] = crate::watched::homes(roots.home);
    kind.listed(APP_SUPPORT_PLACE);
    let (mut matched, mut files, mut kept) = (0, 0, Vec::new());
    for entry in entries {
        let text = entry.to_string_lossy().into_owned();
        let key = crate::spelling::key(&text);
        let before = held.get(&key);
        let (versions, unmatched): (Vec<String>, bool) = match (names.get(&key), before) {
            (Some(version), _) => (version.iter().cloned().collect(), false),
            (None, Some(h)) => (h.versions.clone(), true),
            (None, None) => continue,
        };
        let path = base.join(&entry);
        // A folder held before that is now a link or a file is there and is not opened: never
        // taken for a folder that went. One the system would not let be looked at may be a
        // folder: what it said is kept, with its number. Asked before anything that follows a
        // link.
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => {}
            Err(e) if e.kind() != ErrorKind::NotFound => {
                kind.refused(format!("{APP_SUPPORT_PLACE}/{text}"), &e);
                continue;
            }
            _ => {
                if before.is_some() {
                    kind.failed(
                        format!("{APP_SUPPORT_PLACE}/{text}"),
                        None,
                        NOT_A_FOLDER.to_string(),
                    );
                }
                continue;
            }
        }
        if own.as_ref() == Some(&same_place(&path)) {
            continue;
        }
        // A folder the store holds under another spelling of its name, in case or Unicode form,
        // keeps the store's: on a volume that ignores both, as a Mac's do by default, it is the
        // same folder, so a change to it is a change and not one folder gone and another new.
        let spelled = before.map_or_else(|| text.clone(), |h| h.name.clone());
        let shown = format!("{APP_SUPPORT_PLACE}/{spelled}");
        if !unmatched {
            matched += 1;
        }
        let (mut records, mut count) = (Vec::new(), 0);
        let homes: [&Path; 2] = [&home, &real_home];
        match walk_code(&path, b"", 0, &mut records, &mut count, &homes) {
            Err(e) => kind.refused(shown, &e),
            Ok(Walked::Capped(cap)) => kind.not_recorded(shown, Said::OverCap, cap),
            // No application read now matches it and no code is left in it: nothing to hold.
            Ok(Walked::Done) if unmatched && count == 0 => {}
            Ok(Walked::Done) => {
                if unmatched {
                    kept.push(shown.clone());
                }
                files += count;
                let mut facts = vec![("located_on", machine.to_string())];
                facts.extend(versions.into_iter().map(|v| ("has_version", v)));
                facts.push(("has_digest", stat(&records)));
                kind.things.push(Thing {
                    subject: format!("file:{machine}/{shown}"),
                    shown,
                    facts,
                    how: format!("{count} code files"),
                    list: Some(records),
                });
            }
        }
    }
    kind.notes.push(format!(
        "{matched} folders matched an application, {files} code files compared"
    ));
    if !kept.is_empty() {
        kind.notes.push(format!("{KEPT}{}", kept.join("; ")));
    }
    kind
}

/// Why a folder an earlier reading held is not opened when something else is at its path now.
const NOT_A_FOLDER: &str =
    "held from an earlier reading and no longer a folder; a link is not followed";

/// How the note begins that names the folders opened because an earlier reading held them.
const KEPT: &str = "still compared, since an earlier reading held them and they are there, though no application read now matches them: ";

/// A folder of code the store holds, or held, on this Mac.
struct Held {
    /// Its name as the store spells it in its id.
    name: String,
    /// The versions in force for it; none for a folder the store no longer holds.
    versions: Vec<String>,
}

/// Every folder of code the store holds or held on this Mac, by the name it is matched by
/// (`app_support_name`). A folder the store no longer holds is opened again once it is back:
/// otherwise a folder that missed one reading, renamed aside for a run or removed and made
/// again, would never be compared again while it is on disk.
///
/// The store can hold one name under two spellings, in case or Unicode form: a build that named
/// a folder by the spelling on disk wrote one for each, and a volume that tells them apart gives
/// two. The one in force is taken, and with none in force the one retracted last, so that a
/// folder on disk is never retracted to be added again under a stale spelling.
fn held_folders(conn: &Connection, machine: &str) -> rusqlite::Result<BTreeMap<String, Held>> {
    let mut stmt = conn.prepare(
        "SELECT subject, predicate, object, layer = 'live', retracted_at FROM assertion
         WHERE layer IN ('live', 'retracted') AND reader = ?1 AND scope = ?2 AND kind = ?3
         ORDER BY id",
    )?;
    type Row = (String, String, String, bool, Option<i64>);
    let mut by_subject: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for row in stmt.query_map(params![READER, machine, APP_SUPPORT], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    })? {
        let row: Row = row?;
        by_subject.entry(row.0.clone()).or_default().push(row);
    }
    let prefix = format!("file:{machine}/");
    // Each spelling, with whether it is in force and when it was last retracted, in the order
    // in which a later one is preferred.
    let mut spellings = Vec::new();
    for (subject, rows) in &by_subject {
        let Some(name) = subject.strip_prefix(&prefix).and_then(app_support_folder) else {
            continue;
        };
        let live = rows.iter().any(|r| r.3);
        let retracted = rows.iter().filter_map(|r| r.4).max();
        let versions = rows
            .iter()
            .filter(|r| r.1 == "has_version" && r.3)
            .map(|r| r.2.clone())
            .collect();
        spellings.push((live, retracted, name.to_string(), versions));
    }
    spellings.sort_by_key(|(live, retracted, _, _)| (*live, *retracted));
    let mut out: BTreeMap<String, Held> = BTreeMap::new();
    for (_, _, name, versions) in spellings {
        out.insert(crate::spelling::key(&name), Held { name, versions });
    }
    Ok(out)
}

/// The raw copy: kind, path, entity and facts, one line per thing; and each kind's line
/// numbers.
pub fn raw(kinds: &[Kind]) -> (String, Vec<Vec<usize>>) {
    let field = crate::watched::field;
    let (mut raw, mut lines, mut n) = (String::new(), Vec::new(), 0);
    for k in kinds {
        let mut mine = Vec::new();
        for t in &k.things {
            let facts: Vec<String> = t
                .facts
                .iter()
                .map(|(p, o)| format!("{p}={}", field(o)))
                .collect();
            raw.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                k.kind,
                field(&t.shown),
                field(&t.subject),
                facts.join("\t"),
                field(&t.how)
            ));
            n += 1;
            mine.push(n);
        }
        lines.push(mine);
    }
    (raw, lines)
}

/// The digest of a tree: every entry but folders, in order of path, by metadata alone.
fn digest(root: &Path) -> std::io::Result<String> {
    listing(root).map(|records| stat(&records))
}

/// The list a tree's digest is made over: for each entry but folders, in order of path, its path
/// from the tree, a NUL, its change time and a newline.
fn listing(root: &Path) -> std::io::Result<Vec<u8>> {
    let mut records = Vec::new();
    walk(root, b"", &mut records)?;
    Ok(records)
}

/// The digest of a list as `walk` or `walk_code` make it.
fn stat(records: &[u8]) -> String {
    format!("stat:{}", crate::sha256::hex(records))
}

fn walk(dir: &Path, rel: &[u8], out: &mut Vec<u8>) -> std::io::Result<()> {
    let mut names = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<OsString>>>()?;
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let m = std::fs::symlink_metadata(&path)?;
        let mut here = rel.to_vec();
        here.push(b'/');
        here.extend_from_slice(name.as_bytes());
        if m.is_dir() {
            if !SKIPPED.iter().any(|s| name == *s) {
                walk(&path, &here, out)?;
            }
            continue;
        }
        out.extend_from_slice(&here);
        out.extend_from_slice(format!("\0{}.{}\n", m.ctime(), m.ctime_nsec()).as_bytes());
    }
    Ok(())
}

/// Whether a place this reader starts at may be looked into: not when it leads into a folder
/// macOS asks permission for, through a link or as it is, which `kind` then says. Inside a
/// place no link is followed.
fn reachable(dir: &Path, shown: &str, roots: &Roots, kind: &mut Kind) -> bool {
    let homes = crate::watched::homes(roots.home);
    match crate::guarded::real(dir, &[&homes[0], &homes[1]]) {
        crate::guarded::Real::Guarded(g) => {
            kind.look.not_into(Unit::whole(shown), g, roots.home);
            false
        }
        _ => true,
    }
}

/// The names in a folder, sorted, or `None` when it is not there.
fn list(dir: &Path) -> Option<std::io::Result<Vec<OsString>>> {
    let listing = std::fs::read_dir(dir).and_then(|entries| {
        entries
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
    });
    match listing {
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Ok(mut names) => {
            names.sort();
            Some(Ok(names))
        }
        Err(e) => Some(Err(e)),
    }
}

/// Whether a path is a folder itself, not a link to one.
fn real_folder(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// A path by what it resolves to, so that one folder reached through a link or a relative
/// path is still one folder; as it is given when it cannot be resolved.
fn same_place(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The keys of a bundle's `Info.plist` read: its identifier, short version and build.
const INFO_KEYS: [&str; 3] = [
    "CFBundleIdentifier",
    "CFBundleShortVersionString",
    "CFBundleVersion",
];

/// A bundle's identifier, short version and build; all `None` when the bundle has no
/// `Info.plist`, and the identifier `None` only when the file holds none. Its `Contents` is not
/// followed when it is a link, as no link inside a place is. The error, with why, is an
/// `Info.plist` that is there and cannot be read or is not a property list, an identifier that
/// is not a string, and any of the three that cannot be told: a fallback to the folder's name
/// would move the app to another subject with no failure said, and a number could be another
/// app's identifier. A version or build of another type than a string or a number is none.
/// The error carries the system's error number when the system refused.
fn info(bundle: &Path) -> Result<[Option<String>; 3], (Option<i32>, String)> {
    use crate::plist::{NotRead, Text};
    let contents = bundle.join("Contents");
    if std::fs::symlink_metadata(&contents).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err((
            None,
            "its Contents is a symbolic link, which is not followed".into(),
        ));
    }
    let texts =
        crate::plist::texts_at(&contents.join("Info.plist"), &INFO_KEYS).map_err(|not| {
            let errno = match &not {
                NotRead::Refused(r) => r.errno(),
                NotRead::Texts(_) => None,
            };
            (errno, format!("its Info.plist: {not}"))
        })?;
    let mut out = [None, None, None];
    for (slot, key) in out.iter_mut().zip(INFO_KEYS) {
        let identifier = key == INFO_KEYS[0];
        *slot = match texts.iter().flatten().find(|(k, _)| *k == key) {
            None => None,
            Some((_, Text::One(s))) => Some(s.clone()),
            Some((_, Text::Number(s))) if !identifier => Some(s.clone()),
            Some((_, Text::Untold)) => return Err((None, format!("its {key} cannot be told"))),
            Some(_) if identifier => return Err((None, format!("its {key} is not a string"))),
            Some(_) => None,
        };
    }
    Ok(out)
}

/// The version as a bundle gives it: the short version, and the build in brackets when it
/// gives another one.
fn bundle_version(short: Option<String>, build: Option<String>) -> Option<String> {
    match (short, build) {
        (Some(s), Some(b)) if s != b => Some(format!("{s} ({b})")),
        (Some(s), _) => Some(s),
        (None, b) => b,
    }
}

/// A bundle found on disk.
struct Found {
    path: PathBuf,
    shown: String,
}

/// Where bundles are looked for, as ids name paths: the system's folder, and the home folder's.
const BUNDLE_PLACES: [&str; 2] = ["/Applications", "Applications"];

/// Where applications keep code outside their bundles, under the home folder.
const APP_SUPPORT_PLACE: &str = "Library/Application Support";

/// The names an application is matched by with the folder of code it keeps outside its bundle,
/// each by the key a Mac's volumes compare names by (`spelling::key`), so that a folder named in
/// another case or Unicode form is still its folder: its bundle identifier, the last part of its
/// id `subject`, and its folder's name without `.app`, the last part of where it is installed,
/// `shown`.
pub fn app_names(subject: &str, shown: &str) -> [String; 2] {
    let identifier = subject.rsplit_once("/macos-app/").map_or("", |(_, n)| n);
    let folder = shown.rsplit('/').next().unwrap_or_default();
    let stem = folder.strip_suffix(".app").unwrap_or(folder);
    [crate::spelling::key(identifier), crate::spelling::key(stem)]
}

/// The name of a folder of code kept outside a bundle, from the folder's path as ids name it
/// (`app_support`), as written; `None` for any other path.
fn app_support_folder(rel: &str) -> Option<&str> {
    let inside = rel.strip_prefix(APP_SUPPORT_PLACE)?.strip_prefix('/')?;
    Some(inside.split_once('/').map_or(inside, |(name, _)| name))
}

/// The name an application is matched by with a folder of code kept outside a bundle, by the
/// key `app_names` gives, from the folder's path as ids name it; `None` for any other path.
pub fn app_support_name(rel: &str) -> Option<String> {
    app_support_folder(rel).map(crate::spelling::key)
}

/// The formula a keg is of, from the keg's path as ids name it: `<name>` of
/// `/<prefix>/Cellar/<name>/<version>` under one of Homebrew's prefixes; `None` for any other
/// path. Homebrew names a formula's kegs by the last part of its name, whatever its tap.
pub fn keg_formula(rel: &str) -> Option<&str> {
    keg_of(rel).map(|(name, _)| name)
}

/// The formula's name and the version of a keg, from the keg's path as ids name it.
pub fn keg_of(rel: &str) -> Option<(&str, &str)> {
    PREFIXES.iter().find_map(|p| {
        rel.strip_prefix(&format!("/{p}/{CELLAR}/"))
            .and_then(|rest| rest.split_once('/'))
    })
}

/// The bundles of both places, with the places that could not be listed.
fn find_bundles(roots: &Roots, kind: &mut Kind) -> Vec<Found> {
    let [system, home] = BUNDLE_PLACES;
    let places = [
        (roots.system.join(&system[1..]), system.to_string()),
        (roots.home.join(home), home.to_string()),
    ];
    let mut found = Vec::new();
    for (dir, shown) in places {
        if !reachable(&dir, &shown, roots, kind) {
            continue;
        }
        let names = match list(&dir) {
            None => continue,
            Some(Err(e)) => {
                kind.refused(shown, &e);
                continue;
            }
            Some(Ok(names)) => names,
        };
        kind.listed(&shown);
        for name in names {
            let path = dir.join(&name);
            let text = name.to_string_lossy();
            if !real_folder(&path) {
                continue;
            }
            let here = format!("{shown}/{text}");
            if text.ends_with(".app") {
                found.push(Found { path, shown: here });
                continue;
            }
            // One folder down, where installers put suites.
            match list(&path) {
                None => {}
                Some(Err(e)) => kind.refused(here, &e),
                Some(Ok(inner)) => {
                    for name in inner {
                        let text = name.to_string_lossy();
                        let inside = path.join(&name);
                        if text.ends_with(".app") && real_folder(&inside) {
                            found.push(Found {
                                path: inside,
                                shown: format!("{here}/{text}"),
                            });
                        }
                    }
                }
            }
        }
    }
    found
}

/// What the store holds of a bundle from the last reading: digest and seal, and when
/// the digest was first seen, which is when its seal was last verified.
struct Previous {
    digest: Option<String>,
    seal: Option<String>,
    verified_at: i64,
}

fn previous(conn: &Connection, subject: &str) -> rusqlite::Result<Previous> {
    let mut stmt = conn.prepare(
        "SELECT predicate, object, observed_at FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND subject = ?2
           AND predicate IN ('has_digest', 'has_seal')",
    )?;
    let mut values: BTreeMap<String, Vec<(String, i64)>> = BTreeMap::new();
    for row in stmt.query_map(params![READER, subject], |r| {
        Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))
    })? {
        let (predicate, object, at) = row?;
        values.entry(predicate).or_default().push((object, at));
    }
    // Only one value is a value; two, left by a partial reading, are not to be trusted.
    let one = |p: &str| match values.get(p).map(Vec::as_slice) {
        Some([(object, at)]) => Some((object.clone(), *at)),
        _ => None,
    };
    let digest = one("has_digest");
    Ok(Previous {
        verified_at: digest.as_ref().map_or(0, |(_, at)| *at),
        digest: digest.map(|(d, _)| d),
        seal: one("has_seal").map(|(s, _)| s),
    })
}

/// A bundle read up to the point where the framework is asked about it.
struct Prepared {
    found: Found,
    subject: String,
    digest: String,
    version: Option<String>,
    /// The last verdict and when it was reached, when it is carried forward.
    carry: Option<(String, i64)>,
}

/// Who signed each bundle, and its seal unless its verdict is carried forward, asked of the
/// framework on several threads: verifying seals is most of this reader's time, and one call
/// takes one bundle. Each thread makes and drops its own code objects.
fn examine_all(prepared: &[Prepared]) -> Vec<(Option<String>, Option<String>)> {
    let next = AtomicUsize::new(0);
    let results = Mutex::new(vec![(None, None); prepared.len()]);
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(p) = prepared.get(i) else { break };
                    let verify = p.carry.is_none();
                    let result = match codesign::Code::at(&p.found.path) {
                        Ok(code) => (code.signer(), verify.then(|| code.seal())),
                        Err(status) => (None, verify.then(|| codesign::does_not_verify(status))),
                    };
                    if let Ok(mut all) = results.lock() {
                        all[i] = result;
                    }
                }
            });
        }
    });
    results.into_inner().unwrap_or_else(|e| e.into_inner())
}

fn bundles(conn: &Connection, roots: &Roots, machine: &str) -> rusqlite::Result<Kind> {
    let mut kind = Kind::new(BUNDLES, BUNDLES_CANNOT);
    let found = find_bundles(roots, &mut kind);
    let mut names = BTreeSet::new();
    let mut prepared = Vec::new();
    for f in found {
        let digest = match digest(&f.path) {
            Ok(d) => d,
            Err(e) => {
                kind.refused(f.shown, &e);
                continue;
            }
        };
        let [identifier, short, build] = match info(&f.path) {
            Ok(info) => info,
            Err((errno, why)) => {
                kind.failed(f.shown, errno, why);
                continue;
            }
        };
        let folder = f.path.file_name().unwrap_or_default().to_string_lossy();
        let name = identifier.unwrap_or_else(|| folder.to_string());
        if !names.insert(name.clone()) {
            kind.not_recorded(f.shown, Said::SameName, String::new());
            continue;
        }
        let version = bundle_version(short, build);
        let subject = format!("component:{machine}/macos-app/{name}");
        let before = previous(conn, &subject)?;
        // The Info.plist is in the digest: a new version is a new digest.
        let unmoved = before.digest.as_ref() == Some(&digest);
        let carry = before
            .seal
            .filter(|_| unmoved)
            .map(|s| (s, before.verified_at));
        prepared.push(Prepared {
            found: f,
            subject,
            digest,
            version,
            carry,
        });
    }
    let examined = examine_all(&prepared);
    let (mut verified, mut carried, mut oldest) = (0, 0, i64::MAX);
    for (p, (signer, seal)) in prepared.into_iter().zip(examined) {
        let (seal, how) = match (seal, p.carry) {
            (Some(seal), _) => {
                verified += 1;
                (seal, "verified".to_string())
            }
            (None, Some((seal, at))) => {
                carried += 1;
                oldest = oldest.min(at);
                (
                    seal,
                    format!("carried forward from {}", crate::view::iso(at)),
                )
            }
            // A thread that could not record its answer: never taken for a bundle gone.
            (None, None) => {
                kind.failed(p.found.shown, None, "not examined".to_string());
                continue;
            }
        };
        let mut facts = vec![
            ("part_of", machine.to_string()),
            ("installed_at", p.found.shown.clone()),
        ];
        facts.extend(p.version.map(|v| ("has_version", v)));
        facts.extend(signer.map(|s| ("signed_by", s)));
        facts.push(("has_seal", seal));
        facts.push(("has_digest", p.digest));
        kind.things.push(Thing {
            subject: p.subject,
            shown: p.found.shown,
            facts,
            how,
            list: None,
        });
    }
    let mut note = format!("seal verified for {verified}");
    if carried > 0 {
        note.push_str(&format!(
            ", carried forward for {carried} whose digest and version did not change, from their last verification, the oldest {}",
            crate::view::utc(oldest)
        ));
    }
    if kind.look.present > 0 {
        kind.notes.push(note);
    }
    Ok(kind)
}

/// Each prefix of Homebrew under the system root, and its path from `/`.
fn prefixes(roots: &Roots, under: &str) -> Vec<(PathBuf, String)> {
    PREFIXES
        .iter()
        .map(|p| (roots.system.join(p).join(under), format!("/{p}/{under}")))
        .collect()
}

fn kegs(roots: &Roots, machine: &str) -> Kind {
    let mut kind = Kind::new(KEGS, KEGS_CANNOT);
    for (cellar, shown) in prefixes(roots, CELLAR) {
        if !reachable(&cellar, &shown, roots, &mut kind) {
            continue;
        }
        let names = match list(&cellar) {
            None => continue,
            Some(Err(e)) => {
                kind.refused(shown, &e);
                continue;
            }
            Some(Ok(names)) => names,
        };
        kind.listed(&shown);
        for name in names {
            let formula = cellar.join(&name);
            let here = format!("{shown}/{}", name.to_string_lossy());
            if !real_folder(&formula) {
                continue;
            }
            let versions = match list(&formula) {
                None => continue,
                Some(Err(e)) => {
                    kind.refused(here, &e);
                    continue;
                }
                Some(Ok(versions)) => versions,
            };
            for version in versions {
                let keg = formula.join(&version);
                let shown = format!("{here}/{}", version.to_string_lossy());
                if !real_folder(&keg) {
                    continue;
                }
                match listing(&keg) {
                    Err(e) => kind.refused(shown, &e),
                    Ok(list) => kind.things.push(Thing {
                        subject: format!("file:{machine}/{shown}"),
                        facts: vec![
                            ("located_on", machine.to_string()),
                            ("has_digest", stat(&list)),
                        ],
                        shown,
                        how: String::new(),
                        list: Some(list),
                    }),
                }
            }
        }
    }
    kind
}

/// The version a package's `package.json`, `file`, gives, if it gives one.
fn package_version(file: &Path) -> Option<String> {
    let text = crate::open::read(file, crate::open::Reach::Place, crate::open::UNCAPPED).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&text).ok()?;
    v.get("version")?.as_str().map(str::to_string)
}

fn npm(roots: &Roots, machine: &str) -> Kind {
    let mut kind = Kind::new(NPM, NPM_CANNOT);
    let homes = crate::watched::homes(roots.home);
    let mut names = BTreeSet::new();
    for (root, shown) in prefixes(roots, NODE_MODULES) {
        if !reachable(&root, &shown, roots, &mut kind) {
            continue;
        }
        let entries = match list(&root) {
            None => continue,
            Some(Err(e)) => {
                kind.refused(shown, &e);
                continue;
            }
            Some(Ok(entries)) => entries,
        };
        kind.listed(&shown);
        let mut packages = Vec::new();
        for entry in entries {
            let text = entry.to_string_lossy().into_owned();
            let path = root.join(&entry);
            if text.starts_with('.') || !real_folder(&path) {
                continue;
            }
            if !text.starts_with('@') {
                packages.push((text, path));
                continue;
            }
            match list(&path) {
                None => {}
                Some(Err(e)) => kind.refused(format!("{shown}/{text}"), &e),
                Some(Ok(scoped)) => {
                    for name in scoped {
                        let inside = path.join(&name);
                        if !name.as_bytes().starts_with(b".") && real_folder(&inside) {
                            packages.push((format!("{text}/{}", name.to_string_lossy()), inside));
                        }
                    }
                }
            }
        }
        for (name, path) in packages {
            let here = format!("{shown}/{name}");
            let list = match listing(&path) {
                Ok(list) => list,
                Err(e) => {
                    kind.refused(here, &e);
                    continue;
                }
            };
            if !names.insert(name.clone()) {
                kind.not_recorded(here, Said::SameName, String::new());
                continue;
            }
            let mut facts = vec![
                ("part_of", machine.to_string()),
                ("installed_at", here.clone()),
            ];
            // Its `package.json`, or a folder above it, may be a link: made real, so that the
            // open, which passes no link, reads what the listing above read, and not followed
            // into a guarded folder. A version lost to a link would read as an update.
            match crate::guarded::real(&path.join("package.json"), &[&homes[0], &homes[1]]) {
                crate::guarded::Real::At(file) => {
                    facts.extend(package_version(&file).map(|v| ("has_version", v)));
                }
                crate::guarded::Real::Guarded(g) => {
                    let unit = Unit::whole(format!("{here}/package.json"));
                    kind.look.not_into(unit, g, roots.home);
                }
                crate::guarded::Real::Failed(_) => {}
            }
            facts.push(("has_digest", stat(&list)));
            kind.things.push(Thing {
                subject: format!("component:{machine}/npm/{name}"),
                shown: here,
                facts,
                how: String::new(),
                list: Some(list),
            });
        }
    }
    kind
}

/// One change in place: kind, subject, predicate and the new value.
pub type InPlace = (String, String, String, Option<String>);

/// The changes of one run that a finding rule looks for: content that changed while the
/// version stayed. Each is a `changed` event of this reader on `has_seal` or `signed_by` of a
/// bundle, or on `has_digest` of a keg, a global package or a folder of code, whose subject has
/// no `has_version` event in the same run. A first reading has no `changed` events, so it adds
/// nothing here, and neither does a folder of code read again after it was retracted: it is read
/// as for the first time. Returns kind, subject, predicate and new value, in the order of the
/// journal.
pub fn changed_in_place(conn: &Connection, run_id: &str) -> rusqlite::Result<Vec<InPlace>> {
    conn.prepare(
        "SELECT j.kind, j.subject, j.predicate, j.new_value FROM journal j
         WHERE j.run_id = ?1 AND j.reader = ?2 AND j.entry = 'changed'
           AND ((j.kind = ?3 AND j.predicate IN ('has_seal', 'signed_by'))
                OR (j.kind IN (?4, ?5, ?6) AND j.predicate = 'has_digest'))
           AND NOT EXISTS (SELECT 1 FROM journal v
                           WHERE v.run_id = j.run_id AND v.reader = j.reader
                             AND v.subject = j.subject AND v.predicate = 'has_version')
         ORDER BY j.seq",
    )?
    .query_map(
        params![run_id, READER, BUNDLES, KEGS, NPM, APP_SUPPORT],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?
    .collect()
}

/// What the rules read of a run, from `changed_in_place`. A seal that verifies again is not
/// one: only a seal that does not verify now is.
pub fn observed(
    conn: &Connection,
    run_id: &str,
) -> rusqlite::Result<Vec<crate::findings::Observed>> {
    let mut out = Vec::new();
    for (kind, subject, predicate, new) in changed_in_place(conn, run_id)? {
        if kind == BUNDLES && predicate == "has_seal" && new.as_deref() == Some(codesign::VERIFIES)
        {
            continue;
        }
        out.push(crate::findings::Observed {
            change: "changed",
            place: place(&kind, &predicate).to_string(),
            file: subject,
        });
    }
    Ok(out)
}

/// What the rules are told changed when a fact of an installed thing changed in place.
fn place(kind: &str, predicate: &str) -> &'static str {
    match (kind, predicate) {
        (BUNDLES, "has_seal") => SEAL_BROKEN,
        (BUNDLES, _) => SIGNER_CHANGED,
        (APP_SUPPORT, _) => CODE_OUTSIDE_CHANGED,
        _ => FILES_CHANGED,
    }
}

/// Everything the rules can be told about installed things of one kind: what `observed`
/// gives for each fact `changed_in_place` looks at.
pub fn places(kind: &str) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = ["has_seal", "signed_by", "has_digest"]
        .iter()
        .map(|p| place(kind, p))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// What the rules are told changed, each the kind of its findings.
pub const SEAL_BROKEN: &str = "application changed inside its signature";
pub const SIGNER_CHANGED: &str = "application signed by someone else";
pub const FILES_CHANGED: &str = "installed package changed in place";
pub const CODE_OUTSIDE_CHANGED: &str = "application code changed outside its bundle";

/// What the last run learned of what is installed, for the report line and `immunity status`.
pub struct Summary {
    /// No reading of this reader was made before this run: this one is the baseline.
    pub first: bool,
    pub bundles: i64,
    /// Live bundles by the class of who signed them: the literal before its first comma.
    pub signers: BTreeMap<String, i64>,
    pub not_verifying: i64,
    /// Of those, the ones that did not verify already at the reader's first reading.
    pub not_verifying_since_first: i64,
    /// Bundles whose seal this run verified, and those whose verdict it carried forward.
    pub verified: i64,
    pub carried: i64,
    pub kegs: i64,
    pub packages: i64,
    /// Folders of applications' code under Application Support.
    pub app_folders: i64,
    /// Things whose content changed while their version stayed, in this run.
    pub changed_in_place: usize,
    /// This run's readings, kind, completeness and reason, in the order of reading.
    pub readings: Vec<(String, String, Option<String>)>,
}

/// What `run_id` left, or `None` when this reader never read.
pub fn summary(conn: &Connection, run_id: &str) -> rusqlite::Result<Option<Summary>> {
    if !crate::store::read_any(conn, READER)? {
        return Ok(None);
    }
    let count = |sql: &str, kind: &str| -> rusqlite::Result<i64> {
        conn.query_row(sql, params![READER, kind], |r| r.get(0))
    };
    let live = "SELECT COUNT(DISTINCT subject) FROM assertion
                WHERE layer = 'live' AND reader = ?1 AND kind = ?2 AND predicate = 'has_digest'";
    let mut signers = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT object FROM assertion WHERE layer = 'live' AND reader = ?1 AND kind = ?2
           AND predicate = 'signed_by'",
    )?;
    for row in stmt.query_map(params![READER, BUNDLES], |r| r.get::<_, String>(0))? {
        let signer = row?;
        let class = signer.split(',').next().unwrap_or_default().to_string();
        *signers.entry(class).or_default() += 1;
    }
    let first_run: Option<String> = conn
        .query_row(
            "SELECT run_id FROM coverage WHERE reader = ?1 AND kind = ?2
               AND completeness != 'none' ORDER BY id LIMIT 1",
            params![READER, BUNDLES],
            |r| r.get(0),
        )
        .optional()?;
    let not_verifying = |since: Option<&str>| -> rusqlite::Result<i64> {
        conn.query_row(
            "SELECT COUNT(DISTINCT subject) FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND kind = ?2 AND predicate = 'has_seal'
               AND object != ?3 AND (?4 IS NULL OR run_id = ?4)",
            params![READER, BUNDLES, codesign::VERIFIES, since],
            |r| r.get(0),
        )
    };
    let verified: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT subject) FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND kind = ?2 AND run_id = ?3
           AND predicate IN ('has_digest', 'has_version', 'has_seal')",
        params![READER, BUNDLES, run_id],
        |r| r.get(0),
    )?;
    let bundles = count(live, BUNDLES)?;
    let mut readings = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT kind, completeness, reason FROM coverage WHERE reader = ?1 AND run_id = ?2
         ORDER BY id",
    )?;
    for row in stmt.query_map(params![READER, run_id], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })? {
        readings.push(row?);
    }
    Ok(Some(Summary {
        first: !conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND run_id != ?2)",
            params![READER, run_id],
            |r| r.get(0),
        )?,
        bundles,
        signers,
        not_verifying: not_verifying(None)?,
        not_verifying_since_first: match &first_run {
            Some(first) => not_verifying(Some(first))?,
            None => 0,
        },
        verified,
        carried: bundles - verified,
        kegs: count(live, KEGS)?,
        packages: count(live, NPM)?,
        app_folders: count(live, APP_SUPPORT)?,
        changed_in_place: changed_in_place(conn, run_id)?
            .iter()
            .map(|(_, subject, _, _)| subject)
            .collect::<BTreeSet<_>>()
            .len(),
        readings,
    }))
}

fn things(n: i64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// One sentence for the report line. Paths and names are never in it.
pub fn sentence(s: Option<&Summary>) -> String {
    let Some(s) = s else {
        return "Installed software: never read.".to_string();
    };
    let counted = format!(
        "Installed software: {}, {}, {}",
        things(s.bundles, "application bundle", "application bundles"),
        things(s.kegs, "Homebrew keg", "Homebrew kegs"),
        things(s.packages, "global npm package", "global npm packages")
    );
    let mut line = if s.first {
        format!("{counted}, first reading, kept as the baseline")
    } else {
        format!(
            "{counted}, {} changed while the version stayed, since the last reading",
            s.changed_in_place
        )
    };
    if s.not_verifying > 0 {
        line.push_str(&format!(
            "; {} not verify, {} of them since the first reading",
            things(s.not_verifying, "bundle does", "bundles do"),
            s.not_verifying_since_first
        ));
    }
    let not_full: Vec<String> = s
        .readings
        .iter()
        .filter(|(_, completeness, _)| completeness != "full")
        .map(|(kind, completeness, _)| {
            let words = if completeness == "partial" {
                "partial"
            } else {
                "nothing read"
            };
            format!("{kind} ({words})")
        })
        .collect();
    if !not_full.is_empty() {
        line.push_str(&format!("; not read in full: {}", not_full.join(", ")));
    }
    line.push('.');
    line
}

/// `integrity` of the contract's `Status`: counts only, and each reading's own words, whole.
pub fn message(s: &Summary) -> crate::contract::v1::Integrity {
    use crate::contract::{v1, value_of};
    let n = |x: i64| u64::try_from(x).unwrap_or(0);
    v1::Integrity {
        first_reading: s.first,
        bundles: n(s.bundles),
        bundles_by_signer: s
            .signers
            .iter()
            .map(|(name, count)| v1::Count {
                name: name.clone(),
                count: n(*count),
            })
            .collect(),
        bundles_not_verifying: n(s.not_verifying),
        not_verifying_since_first_reading: n(s.not_verifying_since_first),
        seals_verified_this_run: n(s.verified),
        seals_carried_forward: n(s.carried),
        homebrew_kegs: n(s.kegs),
        global_npm_packages: n(s.packages),
        application_code_folders: n(s.app_folders),
        changed_while_version_stayed: s.changed_in_place as u64,
        readings: s
            .readings
            .iter()
            .map(|(kind, completeness, reason)| v1::IntegrityReading {
                kind: kind.clone(),
                completeness: value_of::<v1::Completeness>(completeness),
                // A reader's reason, prose from its source: cut, as every such text.
                reason_text: reason.as_deref().map(crate::secrets::said),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Kind, NPM, NPM_CANNOT, Said, Unit, bundle_version};
    use crate::store::Cause;
    use std::path::Path;

    #[test]
    fn a_thing_not_recorded_is_named_with_its_cause_and_the_reading_is_never_full() {
        // A global package that could not be read failed; one over a cap, one whose name
        // another took, or one that leads into a folder macOS asks permission for was not
        // given. Each is named, and any one keeps the reading from being full.
        let home = Path::new("/Users/example");
        for (i, cause) in [
            (0, Cause::NotGiven),
            (1, Cause::NotGiven),
            (2, Cause::NotGiven),
        ]
        .into_iter()
        .chain([(3, Cause::Failed)])
        {
            let mut kind = Kind::new(NPM, NPM_CANNOT);
            kind.listed("/l");
            let tool = || "/l/tool".to_string();
            match i {
                0 => kind.not_recorded(tool(), Said::OverCap, "cap".into()),
                1 => kind.not_recorded(tool(), Said::SameName, String::new()),
                2 => (kind.look).not_into(Unit::whole(tool()), home.join("Documents"), home),
                _ => kind.failed(tool(), None, "denied".into()),
            }
            let (completeness, reason, gap) = kind.coverage();
            assert_eq!((completeness, gap.cause), ("partial", Some(cause)));
            assert!(reason.is_some_and(|r| r.contains("/l/tool")));
            assert_eq!(kind.look.not_read().count(), 1);
        }
        let mut whole = Kind::new(NPM, NPM_CANNOT);
        whole.listed("/l");
        assert_eq!(whole.coverage().0, "full");
    }

    #[test]
    fn a_place_or_an_app_shut_to_this_account_carries_the_systems_number_and_a_link_none() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::common::Scratch::new("integrity-errno");
        let (home, system) = (dir.join("home"), dir.join("system"));
        let places = system.join("Applications");
        let info = home.join("Applications/X.app/Contents/Info.plist");
        std::fs::create_dir_all(&places).unwrap();
        std::fs::create_dir_all(info.parent().unwrap()).unwrap();
        std::fs::write(&info, "<plist/>\n").unwrap();
        std::fs::create_dir_all(home.join("Applications/Y.app")).unwrap();
        let contents = home.join("Applications/Y.app/Contents");
        std::os::unix::fs::symlink(info.parent().unwrap(), contents).unwrap();
        let mode = |path: &Path, m| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(m)).unwrap()
        };
        mode(&places, 0o000);
        mode(&info, 0o000);
        let store = dir.join("store.db");
        let conn = crate::store::open_or_make(&store).unwrap();
        let roots = super::Roots {
            home: &home,
            system: &system,
            store: &store,
        };
        let kind = super::bundles(&conn, &roots, "machine:mac").unwrap();
        mode(&places, 0o755);
        mode(&info, 0o644);
        let errno: Vec<(String, Option<i32>)> = (kind.look.not_read())
            .map(|u| (u.unit.to_string(), u.errno))
            .collect();
        let denied = Some(libc::EACCES);
        let said = [
            ("/Applications".to_string(), denied),
            ("Applications/X.app".to_string(), denied),
            ("Applications/Y.app".to_string(), None),
        ];
        assert_eq!(errno, said);
    }

    /// An `Info.plist` of an invented app with these three values, each an XML element.
    fn info_plist(identifier: &str, short: &str, build: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n<key>CFBundleIdentifier</key>{identifier}\n<key>CFBundleExecutable</key><string>Tiny</string>\n<key>CFBundleShortVersionString</key>{short}\n<key>CFBundleVersion</key>{build}\n</dict></plist>\n"
        )
    }

    /// What `bundles` makes of apps under `/Applications` of a new system root, each a name and
    /// what to put at its `Contents/Info.plist`: each app's id and version, and each one not
    /// read with why. It runs on a thread of its own, so that a reading that waits fails the
    /// test after ten seconds.
    #[allow(clippy::type_complexity)]
    fn read_apps(
        apps: Vec<(&'static str, Box<dyn FnOnce(&Path) + Send>)>,
    ) -> (Vec<(String, Option<String>)>, Vec<(String, String)>) {
        let dir = crate::common::Scratch::new("integrity-info");
        let (home, system) = (dir.join("home"), dir.join("system"));
        for (app, put) in apps {
            let contents = system.join("Applications").join(app).join("Contents");
            std::fs::create_dir_all(&contents).unwrap();
            put(&contents.join("Info.plist"));
        }
        std::fs::create_dir_all(&home).unwrap();
        let store = dir.join("store.db");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok(conn) = crate::store::open_or_make(&store) else {
                panic!()
            };
            let roots = super::Roots {
                home: &home,
                system: &system,
                store: &store,
            };
            let kind = super::bundles(&conn, &roots, "machine:mac").unwrap();
            let read = kind.things.iter().map(|t| {
                let version = t.facts.iter().find(|(p, _)| *p == "has_version");
                (t.subject.clone(), version.map(|(_, v)| v.clone()))
            });
            let unread = kind
                .look
                .not_read()
                .map(|u| (u.unit.path.clone(), u.why.clone()));
            let _ = tx.send((read.collect(), unread.collect()));
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the reading of the apps waited")
    }

    #[test]
    fn an_apps_identifier_version_and_build_are_read_by_the_core_itself_in_xml_and_in_binary() {
        // The same values whichever form the file is in, a number as its text, and an app
        // without an `Info.plist` named by its folder. No program is started: the values come
        // from the file's bytes in this process (`plist::texts_at`).
        let s = |v: &str| format!("<string>{v}</string>");
        let xml =
            |id: &str, short: &str, build: &str| info_plist(&s(id), short, build).into_bytes();
        let binary = |bytes: Vec<u8>| crate::plist::binary_of(&bytes);
        let put = |bytes: Vec<u8>| -> Box<dyn FnOnce(&Path) + Send> {
            Box::new(move |p| std::fs::write(p, bytes).unwrap())
        };
        let (read, unread) = read_apps(vec![
            ("A.app", put(xml("org.example.a", &s("2.1"), &s("2104")))),
            (
                "B.app",
                put(binary(xml("org.example.b", &s("2.1"), &s("2104")))),
            ),
            (
                "C.app",
                put(xml(
                    "org.example.c",
                    "<integer>3</integer>",
                    "<real>2.5</real>",
                )),
            ),
            (
                "D.app",
                put(binary(xml(
                    "org.example.d",
                    "<integer>3</integer>",
                    "<real>2.5</real>",
                ))),
            ),
            (
                "E.app",
                put(xml(
                    "org.example.e",
                    "<date>2026-01-02T03:04:05Z</date>",
                    "<array/>",
                )),
            ),
            ("F.app", Box::new(|_| {})),
        ]);
        let app = |name: &str, version: Option<&str>| {
            (
                format!("component:machine:mac/macos-app/{name}"),
                version.map(str::to_string),
            )
        };
        let want = [
            app("org.example.a", Some("2.1 (2104)")),
            app("org.example.b", Some("2.1 (2104)")),
            app("org.example.c", Some("3 (2.500000)")),
            app("org.example.d", Some("3 (2.500000)")),
            app("org.example.e", None),
            app("F.app", None),
        ];
        assert_eq!(read, want);
        assert_eq!(unread, []);
    }

    #[test]
    fn an_info_plist_that_is_not_a_regular_file_does_not_hold_the_reading_and_that_app_failed() {
        // A named pipe would hold a reader that waits for a writer to open it; a link in the
        // last part or a `Contents` that is a link is not followed; a folder is not a file.
        let target = crate::common::Scratch::new("integrity-info-target");
        let elsewhere = target.join("Info.plist");
        let s = "<string>x</string>";
        std::fs::write(
            &elsewhere,
            info_plist("<string>org.example.x</string>", s, s),
        )
        .unwrap();
        let (to_file, to_folder) = (elsewhere.clone(), target.to_path_buf());
        let (read, unread) = read_apps(vec![
            (
                "Pipe.app",
                Box::new(|p| {
                    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: a valid C path.
                    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                }),
            ),
            ("Folder.app", Box::new(|p| std::fs::create_dir(p).unwrap())),
            (
                "Link.app",
                Box::new(move |p| std::os::unix::fs::symlink(to_file, p).unwrap()),
            ),
            (
                "Contents.app",
                Box::new(move |p| {
                    let contents = p.parent().unwrap();
                    std::fs::remove_dir(contents).unwrap();
                    std::os::unix::fs::symlink(to_folder, contents).unwrap();
                }),
            ),
        ]);
        assert_eq!(read, []);
        // Each is refused by what it is, before anything is opened.
        let failed: Vec<String> = unread
            .iter()
            .map(|(p, why)| format!("{p}: {why}"))
            .collect();
        assert_eq!(
            failed,
            [
                "/Applications/Contents.app: its Contents is a symbolic link, which is not followed",
                "/Applications/Folder.app: its Info.plist: a folder, not a regular file",
                "/Applications/Link.app: its Info.plist: a symbolic link, which is not followed",
                "/Applications/Pipe.app: its Info.plist: a fifo, not a regular file",
            ]
        );
    }

    #[test]
    fn an_identifier_that_is_not_a_string_or_cannot_be_told_fails_that_app_and_never_names_it_by_its_folder()
     {
        // A fallback to the folder's name would move the app to another subject with no failure
        // said, and a number could be another app's identifier. A version that cannot be told
        // fails the reading too. The long strings are past what the reader tells of one value.
        let long = format!("<string>{}</string>", "x".repeat(crate::plist::BYTES));
        let s = "<string>1.0</string>";
        let put = |text: String| -> Box<dyn FnOnce(&Path) + Send> {
            Box::new(move |p| std::fs::write(p, text).unwrap())
        };
        let (read, unread) = read_apps(vec![
            ("Number.app", put(info_plist("<integer>7</integer>", s, s))),
            ("Long.app", put(info_plist(&long, s, s))),
            (
                "Version.app",
                put(info_plist("<string>org.example.v</string>", &long, s)),
            ),
        ]);
        assert_eq!(read, []);
        let failed: Vec<String> = unread
            .iter()
            .map(|(p, why)| format!("{p}: {why}"))
            .collect();
        assert_eq!(
            failed,
            [
                "/Applications/Long.app: its CFBundleIdentifier cannot be told",
                "/Applications/Number.app: its CFBundleIdentifier is not a string",
                "/Applications/Version.app: its CFBundleShortVersionString cannot be told",
            ]
        );
    }

    #[test]
    fn a_bundles_version_is_its_short_version_with_the_build_only_where_it_differs() {
        let v = |s: Option<&str>, b: Option<&str>| {
            bundle_version(s.map(str::to_string), b.map(str::to_string))
        };
        assert_eq!(v(Some("2.1"), Some("2104")).as_deref(), Some("2.1 (2104)"));
        assert_eq!(v(Some("2.1"), Some("2.1")).as_deref(), Some("2.1"));
        assert_eq!(v(Some("2.1"), None).as_deref(), Some("2.1"));
        assert_eq!(v(None, Some("2104")).as_deref(), Some("2104"));
        assert_eq!(v(None, None), None);
    }
}
