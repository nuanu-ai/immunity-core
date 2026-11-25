//! Whether a file the system would not let this account read is a limit or a fault, decided
//! here alone (`cause`). A reader reports every failure to read a file's bytes as failed, with
//! what the system said and whose the file is (`watched::bytes`), and nothing else picks the
//! calm cause. `settle` decides each of a pass's failures before any row of the pass is
//! written.
//!
//! A failure is not given by its source, a limit, only when both hold:
//!
//! 1. Another account closed the file to this one, and every object that decides it is of
//!    another account and is the object that refused. The system refused with EACCES; EPERM
//!    never counts, since macOS gives it for its privacy protection and the sandbox, which the
//!    person or anything running as them grants and takes back with no change to the file.
//!    What refused is one of two (`By`):
//!    - the file itself, the same object (owner, device and inode) when the reader looked at
//!      it before the open and after the refusal, and of another account;
//!    - a folder on its path, where the reader's own walk stopped (`guarded::real_to`), never
//!      a second walk: a real folder by its own `lstat`, of another account, that this account
//!      cannot search (`faccessat`), reached by a walk none of whose parts, from the Mac's root
//!      to that folder, belongs to this account. A home folder is the person's, so nothing
//!      under one is ever this limit.
//!
//!    Nothing running as the person can close a file or a folder another account owns, or
//!    rename, move or retarget what lies in folders and links of other accounts.
//! 2. Nothing read it here under any name the reading and the store know: a content reading of
//!    any run, this one included, that read something (`partial` too), or an entry of this pass
//!    that did; by its name as met, by its name made real, by another spelling of either that a
//!    Mac volume takes as the same (`spelling::key`), or through a stored link that leads to it.
//!    When a folder refused, nothing was read inside that folder either, by its name made real:
//!    a file read there once shows the folder was open to this account. A program read in the
//!    same reading and refused at its second look was read here (`targets::read_target`).
//!
//! Everything else that failed is a fault. The stored form of the limit is cause `not_given`
//! with a fixed reason, `watched::CLOSED` for the file and `watched::CLOSED_ON_THE_WAY` for a
//! folder on its path, which `covered` lists under `other-accounts-files` (`of_another`).

use crate::guarded::Stopped;
use crate::look::Look;
use crate::store::Cause;
use crate::watched::{self, CLOSED, CLOSED_ON_THE_WAY, Content, Roots};
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// A file's bytes that could not be read, as the reader met it.
#[derive(Debug, PartialEq)]
pub struct Failure {
    /// The system's error number.
    pub errno: Option<i32>,
    /// What refused, as the reader found it, and the account reading, by uid.
    pub by: By,
    pub us: u32,
    /// The path that was opened, made real as far as the reader could.
    pub real: PathBuf,
    /// What the system said.
    pub why: String,
}

/// One object as its metadata names it: its owner, device and inode.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Object {
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
}

impl Object {
    pub fn of(m: &Metadata) -> Object {
        Object {
            uid: m.uid(),
            dev: m.dev(),
            ino: m.ino(),
        }
    }
}

/// The folder a reader's walk stopped in, as found there.
#[derive(Clone, Debug, PartialEq)]
pub struct Folder {
    /// Made real.
    pub path: PathBuf,
    pub owner: u32,
    /// A folder by its own `lstat`, not a link.
    pub dir: bool,
    /// A part the walk passed on the way, a folder or a link, belongs to this account
    /// (`guarded::Stopped`).
    pub own_on_the_way: bool,
    /// This account may search it.
    pub search: bool,
}

/// What refused a file, as the reader found it.
#[derive(Clone, Debug, PartialEq)]
pub enum By {
    /// The file itself, as looked at before the open and after the refusal.
    File(Object, Option<Object>),
    /// A folder on its path.
    Folder(Folder),
    /// Not found, or not to be weighed, as a program read in the same reading.
    Untold,
}

impl By {
    /// After the system refused to open `path`, which the reader looked at before as `before`:
    /// the object there now, by `lstat`, which does not follow a link in the last part.
    pub fn file(path: &Path, before: &Metadata) -> By {
        let after = std::fs::symlink_metadata(path).ok();
        By::File(Object::of(before), after.as_ref().map(Object::of))
    }

    /// The folder the reader's own walk stopped in, `stopped` as that walk returned it. A walk
    /// that stopped nowhere is `Untold`.
    pub fn stopped(stopped: &Stopped) -> By {
        let Some(folder) = stopped.part.as_deref().and_then(Path::parent) else {
            return By::Untold;
        };
        let Ok(m) = std::fs::symlink_metadata(folder) else {
            return By::Untold;
        };
        By::Folder(Folder {
            path: folder.to_path_buf(),
            owner: m.uid(),
            dir: m.file_type().is_dir(),
            own_on_the_way: stopped.own_on_the_way,
            search: searchable(folder),
        })
    }
}

/// Whether this account may search `folder`, as the system answers for the effective ids.
fn searchable(folder: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(folder.as_os_str().as_bytes()) else {
        return true;
    };
    // SAFETY: `c` is a valid NUL-terminated path; faccessat only reads it.
    unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 }
}

/// Whether a reason is one of the two this file writes for another account's closed file.
pub fn of_another(reason: Option<&str>) -> bool {
    matches!(reason, Some(CLOSED | CLOSED_ON_THE_WAY))
}

impl Failure {
    /// What the reader met, with what refused and the account reading.
    pub fn of(e: &std::io::Error, by: By, real: &Path, why: String) -> Failure {
        Failure {
            errno: e.raw_os_error(),
            by,
            // SAFETY: geteuid has no preconditions and cannot fail.
            us: unsafe { libc::geteuid() },
            real: real.to_path_buf(),
            why,
        }
    }

    /// Condition 1: another account closed the file to this one, and every object that
    /// decides it is of another account and is what refused.
    fn closed(&self) -> bool {
        let theirs = |uid: u32| uid != self.us;
        self.errno == Some(libc::EACCES)
            && match &self.by {
                By::File(before, after) => *after == Some(*before) && theirs(before.uid),
                By::Folder(f) => f.dir && !f.own_on_the_way && !f.search && theirs(f.owner),
                By::Untold => false,
            }
    }

    /// Why it was not read: a fixed reason for another account's closed file, which is not the
    /// person's to fix (`covered::not_permitted`), else what the system said.
    pub fn why(&self) -> String {
        match &self.by {
            _ if !self.closed() => self.why.clone(),
            By::Folder(..) => CLOSED_ON_THE_WAY.to_string(),
            _ => CLOSED.to_string(),
        }
    }
}

/// The keys of every name something was read under, here and in this pass (condition 2).
#[derive(Default)]
pub struct Read(BTreeSet<String>);

impl Read {
    /// What the store's content readings of `machine` read, of any run, and what the entries of
    /// `looks` read.
    pub fn of(conn: &Connection, machine: &str, looks: &[&Look]) -> rusqlite::Result<Read> {
        let mut read = Read::default();
        let prefix = format!("file:{machine}/");
        let mut stmt = conn.prepare(
            "SELECT c.scope, l.object
             FROM (SELECT DISTINCT scope FROM coverage
                   WHERE reader = ?1 AND kind = ?2 AND completeness != 'none') c
             LEFT JOIN assertion l
               ON l.layer IN ('live', 'retracted') AND l.reader = ?1 AND l.scope = c.scope
              AND l.kind = ?2 AND l.predicate = 'links_to'",
        )?;
        let rows = stmt.query_map([watched::READER, watched::CONTENT], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        })?;
        for row in rows {
            let (scope, link) = row?;
            if let Some(path) = scope.strip_prefix(&prefix) {
                read.add(path, link.as_deref());
            }
        }
        for e in looks.iter().flat_map(|l| &l.entries) {
            if watched::content_coverage(&e.content, e.link.is_some()).0 != "none" {
                read.add(&e.unit.path, e.link.as_deref());
            }
        }
        Ok(read)
    }

    /// A path as ids name it, read, and where its link leads: a relative target from the
    /// link's folder, `..` taken back by its text.
    fn add(&mut self, path: &str, link: Option<&str>) {
        self.0.insert(crate::spelling::key(path));
        if let Some(link) = link {
            let mut to = Path::new(path)
                .parent()
                .unwrap_or(Path::new(""))
                .to_path_buf();
            for part in Path::new(link).components() {
                match part {
                    Component::ParentDir => {
                        to.pop();
                    }
                    Component::CurDir => {}
                    part => to.push(part),
                }
            }
            self.0.insert(crate::spelling::key(&to.to_string_lossy()));
        }
    }

    fn has(&self, name: &str) -> bool {
        self.0.contains(&crate::spelling::key(name))
    }

    /// Whether anything was read inside `folder`: a key folds each part of a path apart, so
    /// what lies inside starts with the folder's key and a slash.
    fn inside(&self, folder: &str) -> bool {
        let under = format!("{}/", crate::spelling::key(folder));
        (self.0.range(under.clone()..).next()).is_some_and(|k| k.starts_with(&under))
    }
}

/// The one decision: a failure is not given only when another account closed the file and
/// nothing read it here under any of `names`, nor inside any of `folders`, the names of the
/// folder that refused; else it failed.
pub fn cause(failure: &Failure, names: &[String], folders: &[String], read: &Read) -> Cause {
    let seen = names.iter().any(|n| read.has(n)) || folders.iter().any(|f| read.inside(f));
    if failure.closed() && !seen {
        Cause::NotGiven
    } else {
        Cause::Failed
    }
}

/// Decides every failure among the entries of `looks` (`cause`), by what the store and the
/// looks of this pass read, `others` among them; returns the cause of each. A file is named as
/// it was met and as its real path is named under the Mac's root or a home folder, and so is a
/// folder that refused.
pub fn settle(
    conn: &Connection,
    machine: &str,
    roots: &Roots,
    looks: &mut [&mut Look],
    others: &[&Look],
) -> rusqlite::Result<Vec<Cause>> {
    let closed = |l: &Look| {
        (l.entries.iter()).any(|e| matches!(&e.content, Content::Failed(f) if f.closed()))
    };
    // Only another account's closed file needs what was read, which the store is asked once.
    let read = if looks.iter().any(|l| closed(l)) {
        let all: Vec<&Look> = (looks.iter().map(|l| &**l))
            .chain(others.iter().copied())
            .collect();
        Read::of(conn, machine, &all)?
    } else {
        Read::default()
    };
    let homes = watched::homes(roots.home);
    let named = |real: &Path| -> Vec<String> {
        let rel = homes.iter().filter_map(|h| real.strip_prefix(h).ok());
        let rel = rel.map(|r| r.to_string_lossy().into_owned());
        std::iter::once(crate::targets::from_root(roots.system, real))
            .chain(rel)
            .collect()
    };
    let mut out = Vec::new();
    for e in looks.iter_mut().flat_map(|l| &mut l.entries) {
        let Content::Failed(f) = &e.content else {
            continue;
        };
        let mut names = named(&f.real);
        names.push(e.unit.path.clone());
        let folders = match &f.by {
            By::Folder(folder) => named(&folder.path),
            _ => Vec::new(),
        };
        let cause = cause(f, &names, &folders, &read);
        e.content = Content::Unread(cause, f.why());
        out.push(cause);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::Unit;
    use crate::guarded::{self, Real};
    use crate::store::{Gap, Reading};
    use crate::watched::Entry;

    /// A store and the roots a reading is made under, the system's root made real.
    struct Here {
        _dir: crate::common::Scratch,
        conn: Connection,
        system: PathBuf,
        home: PathBuf,
    }

    fn here(tag: &str) -> Here {
        let dir = crate::common::Scratch::new(tag);
        let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let kinds = "INSERT OR IGNORE INTO coverage_kind (name) VALUES (?1)";
        conn.execute(kinds, [watched::CONTENT]).unwrap();
        let (system, home) = (dir.join("root"), dir.join("home"));
        for d in [&system, &home] {
            std::fs::create_dir_all(d).unwrap();
        }
        let system = std::fs::canonicalize(system).unwrap();
        Here {
            _dir: dir,
            conn,
            system,
            home,
        }
    }

    impl Here {
        /// A reading of the content of `path` on `machine` in `run`, with the link it stored.
        fn content(&self, machine: &str, path: &str, run: &str, read: &str, link: Option<&str>) {
            let row = match read {
                "full" => (read, None, Gap::default()),
                _ => (read, Some("invented"), Gap::of(Cause::Failed)),
            };
            self.row(machine, path, run, row, link);
        }

        /// A row of the content of `path` on `machine` in `run`, with the link it stored.
        fn row(
            &self,
            machine: &str,
            path: &str,
            run: &str,
            row: (&str, Option<&str>, Gap),
            link: Option<&str>,
        ) {
            let tx = self.conn.unchecked_transaction().unwrap();
            let scope = format!("file:{machine}/{path}");
            crate::store::put_entity(&tx, &scope).unwrap();
            let r = Reading {
                reader: watched::READER,
                scope: &scope,
                kind: watched::CONTENT,
                run_id: run,
                at: 1,
                observed_at: 1,
            };
            let (completeness, why, gap) = row;
            crate::store::put_coverage(&tx, &r, completeness, why, &gap).unwrap();
            if let Some(link) = link {
                tx.execute(
                    "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                            source_ref, basis, observed_at, run_id)
                     VALUES ('live', ?1, 'links_to', ?2, ?3, ?1, ?4, 'x', 'observed', 1, ?5)",
                    rusqlite::params![scope, link, watched::READER, watched::CONTENT, run],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        /// What a file met as `met` that the system refused as `failure` is, decided on
        /// `machine` with this pass's `others`.
        fn decided(&self, machine: &str, met: &str, failure: Failure, others: &[&Look]) -> Content {
            let mut look = Look::default();
            look.entries
                .push(entry(met, Content::Failed(failure), None));
            let roots = Roots {
                home: &self.home,
                system: &self.system,
            };
            settle(&self.conn, machine, &roots, &mut [&mut look], others).unwrap();
            look.entries.remove(0).content
        }
    }

    fn entry(path: &str, content: Content, link: Option<&str>) -> Entry {
        Entry {
            unit: Unit::whole(path),
            watched_as: watched::AUTOSTART,
            content,
            link: link.map(str::to_string),
            bytes: None,
        }
    }

    /// The system's refusal of `real`, by what `by` found, read as account 501.
    fn refused(errno: i32, by: By, real: PathBuf) -> Failure {
        let why = std::io::Error::from_raw_os_error(errno).to_string();
        Failure {
            errno: Some(errno),
            by,
            us: 501,
            real,
            why,
        }
    }

    /// A file of `uid` that refused, the same object before the open and after the refusal.
    fn file(uid: u32) -> By {
        let o = Object {
            uid,
            dev: 1,
            ino: 2,
        };
        By::File(o, Some(o))
    }

    /// A folder of `owner` that refused: real, reached by a walk that passed nothing of this
    /// account's, and closed to its search.
    fn folder(path: PathBuf, owner: u32) -> Folder {
        Folder {
            path,
            owner,
            dir: true,
            own_on_the_way: false,
            search: false,
        }
    }

    const MET: &str = "/Library/Example/helper.plist";
    const DENIED: &str = "Permission denied (os error 13)";

    #[test]
    fn a_file_another_account_closed_and_never_read_here_under_any_name_is_not_given_as_before() {
        let h = here("closed-never");
        let real = h.system.join("opt/example/helper.plist");
        // What reads nothing of it: a reading of its name that read nothing, one that read
        // another file, a link stored by a reading that read nothing, one of another machine.
        h.content("mac", MET, "run-1", "none", None);
        h.content("mac", "/Library/Example/other.plist", "run-1", "full", None);
        h.content("mac", "/usr/local/x", "run-1", "none", Some(MET));
        h.content("other-mac", MET, "run-1", "full", None);
        let decided = h.decided("mac", MET, refused(libc::EACCES, file(0), real), &[]);
        assert_eq!(
            decided,
            Content::Unread(Cause::NotGiven, CLOSED.to_string())
        );
        // The stored form is the one `covered` lists under `other-accounts-files`.
        let not_given = |c| (c, Some(CLOSED), Gap::of(Cause::NotGiven));
        assert_eq!(
            watched::content_coverage(&decided, false),
            not_given("none")
        );
        assert_eq!(
            watched::content_coverage(&decided, true),
            not_given("partial")
        );
    }

    #[test]
    fn a_file_another_account_closed_read_before_under_any_name_it_has_is_failed() {
        let h = here("closed-read");
        let real = h.system.join("opt/example/helper.plist");
        let in_home = h.home.join("dotfiles/helper.plist");
        // Each case on a machine of its own: by its name, as `partial` too; by its real path;
        // by another spelling; through a link, absolute or relative, stored by a reading that
        // read; by its real path inside the home folder.
        let cases = [
            ("as-met", MET, None, &real),
            ("partial", MET, None, &real),
            ("real", "/opt/example/helper.plist", None, &real),
            ("spelled", "/library/EXAMPLE/Helper.plist", None, &real),
            ("absolute", "/usr/local/x", Some(MET), &real),
            (
                "up",
                "/usr/local/x",
                Some("../../opt/example/helper.plist"),
                &real,
            ),
            ("here", "/opt/example/other", Some("./helper.plist"), &real),
            ("home", "dotfiles/helper.plist", None, &in_home),
        ];
        for (machine, read, link, real) in cases {
            let how = if machine == "partial" {
                "partial"
            } else {
                "full"
            };
            h.content(machine, read, "run-1", how, link);
            let refusal = refused(libc::EACCES, file(0), real.clone());
            let decided = h.decided(machine, MET, refusal, &[]);
            let failed = Content::Unread(Cause::Failed, CLOSED.to_string());
            assert_eq!(decided, failed, "{machine}");
        }
    }

    #[test]
    fn a_file_another_account_closed_read_earlier_in_the_same_check_is_failed() {
        // Read under its name by a reading of this run, stored or not stored yet, and refused
        // later in it.
        let h = here("closed-same-check");
        let real = h.system.join("Library/Example/helper.plist");
        h.content("stored", MET, "run-2", "full", None);
        let mut pass = Look::default();
        pass.entries
            .push(entry(MET, Content::Hash("sha256:00".into()), None));
        let failed = Content::Unread(Cause::Failed, CLOSED.to_string());
        for (machine, others) in [("stored", vec![]), ("in-the-pass", vec![&pass])] {
            let refusal = refused(libc::EACCES, file(0), real.clone());
            assert_eq!(
                h.decided(machine, MET, refusal, &others),
                failed,
                "{machine}"
            );
        }
    }

    #[test]
    fn a_refusal_with_eperm_is_failed_whoever_owns_the_file_or_a_folder_on_its_path() {
        // macOS gives EPERM for its privacy protection and the sandbox; a test cannot make it
        // without a prompt, so the decision is asked of the number.
        let h = here("closed-eperm");
        let real = h.system.join("Library/Example/helper.plist");
        let theirs = By::Folder(folder(h.system.join("Library/Example"), 0));
        for by in [file(0), file(501), theirs] {
            let said = format!("{by:?}");
            let decided = h.decided("mac", MET, refused(libc::EPERM, by, real.clone()), &[]);
            let why = "Operation not permitted (os error 1)";
            assert_eq!(
                decided,
                Content::Unread(Cause::Failed, why.into()),
                "{said}"
            );
        }
    }

    #[test]
    fn the_persons_own_closed_file_or_folder_on_its_path_is_failed_with_what_the_system_said() {
        let h = here("closed-own");
        let real = h.system.join("Library/Example/helper.plist");
        let own = By::Folder(folder(h.system.join("Library/Example"), 501));
        for by in [file(501), own] {
            let decided = h.decided("mac", MET, refused(libc::EACCES, by, real.clone()), &[]);
            assert_eq!(decided, Content::Unread(Cause::Failed, DENIED.into()));
        }
    }

    #[test]
    fn a_refusal_whose_walk_did_not_find_what_refused_is_failed() {
        let h = here("closed-untold");
        let real = h.system.join("opt/closed/helper");
        let decided = h.decided("mac", MET, refused(libc::EACCES, By::Untold, real), &[]);
        assert_eq!(decided, Content::Unread(Cause::Failed, DENIED.into()));
    }

    const BEHIND: &str = "/opt/closed/helper";

    #[test]
    fn a_program_behind_a_folder_another_account_closed_with_nothing_inside_read_is_not_given() {
        let h = here("closed-folder-never");
        let shut = By::Folder(folder(h.system.join("opt/closed"), 0));
        // What lies outside the folder: its neighbour of a longer name, a file beside it, one
        // inside it on another machine, and one inside it a reading of which read nothing.
        h.content("mac", "/opt/closed-old/helper", "run-1", "full", None);
        h.content("mac", "/opt/helper", "run-1", "full", None);
        h.content("other-mac", "/opt/closed/other", "run-1", "full", None);
        h.content("mac", "/opt/closed/other", "run-1", "none", None);
        let failed = refused(libc::EACCES, shut, h.system.join(BEHIND));
        let decided = h.decided("mac", BEHIND, failed, &[]);
        let why = CLOSED_ON_THE_WAY.to_string();
        assert_eq!(decided, Content::Unread(Cause::NotGiven, why));
        // Stored with the second reason, and listed under `other-accounts-files`.
        let not_given = |c| (c, Some(CLOSED_ON_THE_WAY), Gap::of(Cause::NotGiven));
        assert_eq!(
            watched::content_coverage(&decided, false),
            not_given("none")
        );
        assert_eq!(
            watched::content_coverage(&decided, true),
            not_given("partial")
        );
        let latest = crate::view::Latest {
            reader: watched::READER.to_string(),
            scope: format!("file:mac{BEHIND}"),
            kind: watched::CONTENT.to_string(),
            completeness: "none".to_string(),
            reason: Some(CLOSED_ON_THE_WAY.to_string()),
            cause: Some(Cause::NotGiven.literal().to_string()),
            at: 1,
            last_full: None,
        };
        let latest = [latest];
        let p = crate::status::problems(&h.conn, &latest).unwrap();
        let items = crate::covered::not_covered(&h.conn, &latest, &p, None, None).unwrap();
        let ids: Vec<(&str, usize)> = items.iter().map(|u| (u.cause.id, u.count)).collect();
        assert!(
            ids.contains(&(crate::covered::OTHER_ACCOUNTS.id, 1)),
            "{ids:?}"
        );
    }

    #[test]
    fn a_program_behind_a_folder_another_account_closed_is_failed_once_anything_inside_was_read() {
        let h = here("closed-folder-read");
        let shut = || By::Folder(folder(h.system.join("opt/closed"), 0));
        // Each case on a machine of its own: by its name, as `partial` too; by its name made
        // real, or another spelling of it; through a stored link, absolute or relative; and the
        // program's own name. In the home folder, by its name there.
        let cases = [
            ("inside", "/opt/closed/other", None),
            ("deeper", "/opt/closed/a/b", None),
            ("partial", "/opt/closed/other", None),
            ("spelled", "/OPT/Closed/other", None),
            ("absolute", "/usr/local/x", Some("/opt/closed/other")),
            ("relative", "/opt/x", Some("closed/other")),
            ("itself", BEHIND, None),
        ];
        let failed = Content::Unread(Cause::Failed, CLOSED_ON_THE_WAY.to_string());
        for (machine, read, link) in cases {
            let how = if machine == "partial" {
                "partial"
            } else {
                "full"
            };
            h.content(machine, read, "run-1", how, link);
            let refusal = refused(libc::EACCES, shut(), h.system.join(BEHIND));
            assert_eq!(
                h.decided(machine, BEHIND, refusal, &[]),
                failed,
                "{machine}"
            );
        }
        h.content("home", "tools/other", "run-1", "full", None);
        let tools = By::Folder(folder(h.home.join("tools"), 0));
        let refusal = refused(libc::EACCES, tools, h.home.join("tools/x"));
        assert_eq!(h.decided("home", "tools/x", refusal, &[]), failed);
        // Read earlier in this pass, not stored yet.
        let mut pass = Look::default();
        pass.entries.push(entry(
            "/opt/closed/other",
            Content::Hash("sha256:00".into()),
            None,
        ));
        let refusal = refused(libc::EACCES, shut(), h.system.join(BEHIND));
        assert_eq!(h.decided("pass", BEHIND, refusal, &[&pass]), failed);
    }

    #[test]
    fn rule_2_a_folder_reached_through_anything_of_this_accounts_on_the_way_is_failed() {
        // A folder or a link of the person's on the way can be renamed, moved or pointed
        // anywhere by anything running as them, a home folder and all it holds among them.
        let h = here("closed-own-on-the-way");
        let via = Folder {
            own_on_the_way: true,
            ..folder(h.system.join("opt/closed"), 0)
        };
        let refusal = refused(libc::EACCES, By::Folder(via), h.system.join(BEHIND));
        let decided = h.decided("mac", BEHIND, refusal, &[]);
        assert_eq!(decided, Content::Unread(Cause::Failed, DENIED.into()));
        // The walk says so of a folder of this account's on the way, and of a link of its
        // own; a path that lies in objects of root's, as macOS's own `/etc` to
        // `/private/etc`, passes nothing of this account's, its link included.
        let dir = crate::common::Scratch::new("closed-own-on-the-way-walk");
        let shut = shut(&dir);
        let real = std::fs::canonicalize(&*dir).unwrap();
        std::os::unix::fs::symlink(&shut, real.join("to-folder")).unwrap();
        let (_, folders) = guarded::real_to(&shut.join("helper"), &[]);
        let (_, through) = guarded::real_to(&real.join("to-folder/helper"), &[]);
        let (system, all_roots) = guarded::real_to(Path::new("/etc"), &[]);
        assert!(matches!(system, Real::At(p) if p == Path::new("/private/etc")));
        assert_eq!(
            (folders.own_on_the_way, through.own_on_the_way),
            (true, true)
        );
        assert!(!all_roots.own_on_the_way);
    }

    #[test]
    fn rule_3_a_folder_that_did_not_refuse_is_failed() {
        // A link where a folder was, a folder this account can search (a child refused for a
        // reason of its own), and one of this account's.
        let h = here("closed-not-refused");
        let theirs = || folder(h.system.join("opt/closed"), 0);
        let cases = [
            Folder {
                dir: false,
                ..theirs()
            },
            Folder {
                search: true,
                ..theirs()
            },
            folder(h.system.join("opt/closed"), 501),
        ];
        for f in cases {
            let said = format!("{f:?}");
            let refusal = refused(libc::EACCES, By::Folder(f), h.system.join(BEHIND));
            let decided = h.decided("mac", BEHIND, refusal, &[]);
            assert_eq!(
                decided,
                Content::Unread(Cause::Failed, DENIED.into()),
                "{said}"
            );
        }
    }

    #[test]
    fn rule_3_the_walk_finds_the_folder_it_stopped_in_with_whether_this_account_can_search_it() {
        let dir = crate::common::Scratch::new("closed-walk");
        let real = std::fs::canonicalize(&*dir).unwrap();
        let shut = shut(&dir);
        // SAFETY: geteuid has no preconditions and cannot fail.
        let us = unsafe { libc::geteuid() };
        let (Real::Failed(_), stopped) = guarded::real_to(&shut.join("helper"), &[]) else {
            panic!("walked");
        };
        let found = By::Folder(Folder {
            own_on_the_way: true,
            ..folder(shut.clone(), us)
        });
        assert_eq!(By::stopped(&stopped), found);
        // A folder this account can search, put where a part below it failed, says so; a
        // file where a folder was is no folder.
        std::fs::create_dir(real.join("open")).unwrap();
        std::fs::write(real.join("file"), "invented\n").unwrap();
        let below = |p: &str| Stopped {
            part: Some(real.join(p).join("helper")),
            own_on_the_way: false,
        };
        let open = By::stopped(&below("open"));
        assert!(
            matches!(&open, By::Folder(f) if f.search && f.dir),
            "{open:?}"
        );
        let not_one = By::stopped(&below("file"));
        assert!(matches!(&not_one, By::Folder(f) if !f.dir), "{not_one:?}");
        // A walk that stopped nowhere, or at a folder gone since, found nothing.
        let (_, nowhere) = guarded::real_to(&real.join("open"), &[]);
        assert_eq!(
            (By::stopped(&nowhere), By::stopped(&below("gone"))),
            (By::Untold, By::Untold)
        );
    }

    #[test]
    fn rule_4_a_file_that_was_not_one_object_before_the_open_and_after_the_refusal_is_failed() {
        let h = here("closed-one-object");
        let real = h.system.join("Library/Example/helper.plist");
        let o = Object {
            uid: 0,
            dev: 1,
            ino: 2,
        };
        // Replaced between the two looks, by a file of another account or of this one, or
        // gone after the refusal.
        let cases = [
            By::File(o, Some(Object { ino: 3, ..o })),
            By::File(o, Some(Object { uid: 501, ..o })),
            By::File(Object { uid: 501, ..o }, Some(o)),
            By::File(o, None),
        ];
        for by in cases {
            let said = format!("{by:?}");
            let decided = h.decided("mac", MET, refused(libc::EACCES, by, real.clone()), &[]);
            assert_eq!(
                decided,
                Content::Unread(Cause::Failed, DENIED.into()),
                "{said}"
            );
        }
        // Made real: the file as looked at before and as it is after the refusal.
        let dir = crate::common::Scratch::new("closed-one-object-real");
        let (one, other) = (dir.join("one"), dir.join("other"));
        for p in [&one, &other] {
            std::fs::write(p, "invented\n").unwrap();
        }
        let meta = |p: &Path| std::fs::symlink_metadata(p).unwrap();
        let same = By::File(Object::of(&meta(&one)), Some(Object::of(&meta(&one))));
        assert_eq!(By::file(&one, &meta(&one)), same);
        let replaced = By::File(Object::of(&meta(&other)), Some(Object::of(&meta(&one))));
        assert_eq!(By::file(&one, &meta(&other)), replaced);
        let gone = By::File(Object::of(&meta(&one)), None);
        assert_eq!(By::file(&dir.join("gone"), &meta(&one)), gone);
    }

    #[test]
    fn rule_6_the_limits_own_row_of_a_link_counts_as_read_at_the_next_check() {
        // As on main: the row a watched link to another account's closed file is stored with,
        // `partial`, read the link, and counts as a reading that read the name.
        let h = here("closed-own-row");
        let real = h.system.join("opt/example/helper.plist");
        let limit = Content::Unread(Cause::NotGiven, CLOSED.into());
        let row = watched::content_coverage(&limit, true);
        h.row("mac", MET, "run-1", row, Some("/opt/example/helper.plist"));
        let decided = h.decided("mac", MET, refused(libc::EACCES, file(0), real), &[]);
        assert_eq!(decided, Content::Unread(Cause::Failed, CLOSED.into()));
    }

    /// A folder of this account's own, closed to it, in `dir`, with a file inside, made real.
    fn shut(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let shut = std::fs::canonicalize(dir).unwrap().join("shut");
        std::fs::create_dir_all(&shut).unwrap();
        std::fs::write(shut.join("helper"), "invented\n").unwrap();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
        shut
    }
}
