//! Whether a file the system would not let this account read is a limit or a fault, decided
//! here alone (`cause`). A reader reports every failure to read a file's bytes as failed, with
//! what the system said and whose the file is (`watched::bytes`), and nothing else picks the
//! calm cause. `settle` decides each of a pass's failures before any row of the pass is
//! written.
//!
//! A failure is not given by its source, a limit, only when both hold:
//!
//! 1. Another account closed the file to this one: the system refused with EACCES, and what
//!    refused belongs to another account. What refused is found after the refusal (`By`): the
//!    file itself, or the deepest folder on its path that this account can see and cannot
//!    enter. Nothing running as the person can close a file or a folder another account owns.
//!    EPERM never counts: macOS gives it for its privacy protection and the sandbox, which the
//!    person or anything running as them grants and takes back with no change to the file.
//! 2. Nothing read it here under any name the reading and the store know: a content reading of
//!    any run, this one included, that read something (`partial` too), or an entry of this pass
//!    that did; by its name as met, by its name made real, by another spelling of either that a
//!    Mac volume takes as the same (`spelling::key`), or through a stored link that leads to it.
//!    When a folder refused, nothing was read inside that folder either, by its name made real:
//!    a file read there once shows the folder was open to this account.
//!
//! Everything else that failed is a fault. The stored form of the limit is cause `not_given`
//! with a fixed reason, `watched::CLOSED` for the file and `watched::CLOSED_ON_THE_WAY` for a
//! folder on its path, which `covered` lists under `other-accounts-files` (`of_another`).

use crate::guarded::{self, Real};
use crate::look::Look;
use crate::store::Cause;
use crate::watched::{self, CLOSED, CLOSED_ON_THE_WAY, Content, Roots};
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// A file's bytes that could not be read, as the reader met it.
#[derive(Debug, PartialEq)]
pub struct Failure {
    /// The system's error number.
    pub errno: Option<i32>,
    /// What refused, found after the refusal, and the account reading, by uid.
    pub by: By,
    pub us: u32,
    /// The path that was opened, made real as far as the reader could.
    pub real: PathBuf,
    /// What the system said.
    pub why: String,
}

/// What refused a file, with its owner's uid, as found after the refusal.
#[derive(Clone, Debug, PartialEq)]
pub enum By {
    /// The file itself.
    File(u32),
    /// The deepest folder on its path that this account can see and cannot enter, made real.
    Folder(PathBuf, u32),
    /// Not found: the state changed since, the walk met another error, or a guarded folder.
    Untold,
}

impl By {
    /// After the system refused to open `path`, which the reader made real up to its last part
    /// and opened without following a link there: every part of it can be seen, so the file
    /// itself refused, and its owner is taken now rather than from what was looked at before
    /// the open, which may have been another file.
    pub fn file(path: &Path) -> By {
        std::fs::symlink_metadata(path).map_or(By::Untold, |m| By::File(m.uid()))
    }

    /// After the system refused to look up `path`, the path as the reader met it: walked again
    /// by the reader's own guard (`guarded::real_to`), which makes each part real in order and
    /// follows the links the reader followed and no other, never into a guarded folder. The
    /// first part whose `lstat` is refused with EACCES was refused by the folder it reached
    /// before, real and so no link, whose owner its own `lstat` gives. Anything else is
    /// `Untold`, every part seen included: the refusal was of a lookup, so something changed.
    pub fn walk(path: &Path, homes: &[&Path]) -> By {
        let (Real::Failed(e), Some(part)) = guarded::real_to(path, homes) else {
            return By::Untold;
        };
        let eacces = e.raw_os_error() == Some(libc::EACCES);
        match part.parent().map(|f| (f, std::fs::symlink_metadata(f))) {
            Some((f, Ok(m))) if eacces => By::Folder(f.to_path_buf(), m.uid()),
            _ => By::Untold,
        }
    }

    fn owner(&self) -> Option<u32> {
        match self {
            By::File(owner) | By::Folder(_, owner) => Some(*owner),
            By::Untold => None,
        }
    }
}

/// The two reasons this file writes for another account's closed file.
const REASONS: [&str; 2] = [CLOSED, CLOSED_ON_THE_WAY];

/// Whether a reason is one of the two this file writes for another account's closed file.
pub fn of_another(reason: Option<&str>) -> bool {
    reason.is_some_and(|r| REASONS.contains(&r))
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

    /// Condition 1: another account closed the file to this one.
    fn closed(&self) -> bool {
        self.errno == Some(libc::EACCES) && self.by.owner().is_some_and(|o| o != self.us)
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
    /// `looks` read. A row of the limit itself (cause `not_given` with one of `REASONS`) read a
    /// link and not what it leads to, so it is no evidence, whatever its completeness: else a
    /// watched link to another account's closed file, stored `partial`, would be read at the
    /// next check. The statement is given the two reasons so that it still keeps one row per
    /// scope; every other row counts. No entry of a pass is in that state before `settle`: a
    /// look settled earlier, the programs', keeps no link on a failure, so its rows are `none`.
    pub fn of(conn: &Connection, machine: &str, looks: &[&Look]) -> rusqlite::Result<Read> {
        let mut read = Read::default();
        let prefix = format!("file:{machine}/");
        let mut stmt = conn.prepare(
            "SELECT c.scope, l.object
             FROM (SELECT DISTINCT scope FROM coverage
                   WHERE reader = ?1 AND kind = ?2 AND completeness != 'none'
                     AND NOT (coalesce(cause, '') = ?3 AND coalesce(reason, '') IN (?4, ?5))) c
             LEFT JOIN assertion l
               ON l.layer IN ('live', 'retracted') AND l.reader = ?1 AND l.scope = c.scope
              AND l.kind = ?2 AND l.predicate = 'links_to'",
        )?;
        let limit = Cause::NotGiven.literal();
        let given = [
            watched::READER,
            watched::CONTENT,
            limit,
            REASONS[0],
            REASONS[1],
        ];
        let rows = stmt.query_map(given, |r| {
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
            By::Folder(folder, _) => named(folder),
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

        /// The row a reading of `path` writes for what it found, `content`, reached by `link`.
        fn wrote(
            &self,
            machine: &str,
            path: &str,
            run: &str,
            content: &Content,
            link: Option<&str>,
        ) {
            let row = watched::content_coverage(content, link.is_some());
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

    const MET: &str = "/Library/Example/helper.plist";

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
        let failed = refused(libc::EACCES, By::File(0), real);
        let decided = h.decided("mac", MET, failed, &[]);
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
            let decided = h.decided(
                machine,
                MET,
                refused(libc::EACCES, By::File(0), real.clone()),
                &[],
            );
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
            let refusal = refused(libc::EACCES, By::File(0), real.clone());
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
        let folder = || h.system.join("Library/Example");
        for by in [By::File(0), By::File(501), By::Folder(folder(), 0)] {
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
        let folder = h.system.join("Library/Example");
        for by in [By::File(501), By::Folder(folder, 501)] {
            let decided = h.decided("mac", MET, refused(libc::EACCES, by, real.clone()), &[]);
            let why = "Permission denied (os error 13)";
            assert_eq!(decided, Content::Unread(Cause::Failed, why.into()));
        }
    }

    #[test]
    fn a_refusal_whose_walk_did_not_find_what_refused_is_failed() {
        let h = here("closed-untold");
        let real = h.system.join("opt/closed/helper");
        let decided = h.decided("mac", MET, refused(libc::EACCES, By::Untold, real), &[]);
        let why = "Permission denied (os error 13)";
        assert_eq!(decided, Content::Unread(Cause::Failed, why.into()));
    }

    const BEHIND: &str = "/opt/closed/helper";

    #[test]
    fn a_program_behind_a_folder_another_account_closed_with_nothing_inside_read_is_not_given() {
        let h = here("closed-folder-never");
        let folder = h.system.join("opt/closed");
        // What lies outside the folder: its neighbour of a longer name, a file beside it, one
        // inside it on another machine, and one inside it a reading of which read nothing.
        h.content("mac", "/opt/closed-old/helper", "run-1", "full", None);
        h.content("mac", "/opt/helper", "run-1", "full", None);
        h.content("other-mac", "/opt/closed/other", "run-1", "full", None);
        h.content("mac", "/opt/closed/other", "run-1", "none", None);
        let failed = refused(libc::EACCES, By::Folder(folder, 0), h.system.join(BEHIND));
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
        let items = crate::covered::not_covered(&h.conn, &latest, &p, None).unwrap();
        let ids: Vec<(&str, usize)> = items.iter().map(|u| (u.cause.id, u.count)).collect();
        assert!(
            ids.contains(&(crate::covered::OTHER_ACCOUNTS.id, 1)),
            "{ids:?}"
        );
    }

    #[test]
    fn a_program_behind_a_folder_another_account_closed_is_failed_once_anything_inside_was_read() {
        let h = here("closed-folder-read");
        let folder = h.system.join("opt/closed");
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
            let refusal = refused(
                libc::EACCES,
                By::Folder(folder.clone(), 0),
                h.system.join(BEHIND),
            );
            assert_eq!(
                h.decided(machine, BEHIND, refusal, &[]),
                failed,
                "{machine}"
            );
        }
        h.content("home", "tools/other", "run-1", "full", None);
        let refusal = refused(
            libc::EACCES,
            By::Folder(h.home.join("tools"), 0),
            h.home.join("tools/x"),
        );
        assert_eq!(h.decided("home", "tools/x", refusal, &[]), failed);
        // Read earlier in this pass, not stored yet.
        let mut pass = Look::default();
        pass.entries.push(entry(
            "/opt/closed/other",
            Content::Hash("sha256:00".into()),
            None,
        ));
        let refusal = refused(libc::EACCES, By::Folder(folder, 0), h.system.join(BEHIND));
        assert_eq!(h.decided("pass", BEHIND, refusal, &[&pass]), failed);
    }

    /// The rows stored of `path` on `machine`: completeness, reason and cause, oldest first.
    fn rows(h: &Here, machine: &str, path: &str) -> Vec<(String, Option<String>, Option<String>)> {
        let mut stmt = (h.conn)
            .prepare(
                "SELECT completeness, reason, cause FROM coverage WHERE scope = ?1 ORDER BY id",
            )
            .unwrap();
        let scope = format!("file:{machine}/{path}");
        let rows = stmt.query_map([scope], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)));
        rows.unwrap().map(Result::unwrap).collect()
    }

    /// Another account's refusal of the file met as `MET`, by the file or by a folder on its
    /// path, with the reason each is written with.
    fn closings(h: &Here) -> [(By, &'static str); 2] {
        let folder = h.system.join("Library/Example");
        [
            (By::File(0), CLOSED),
            (By::Folder(folder, 0), CLOSED_ON_THE_WAY),
        ]
    }

    const TO: &str = "/opt/example/helper.plist";

    #[test]
    fn a_watched_link_to_another_accounts_closed_file_never_read_stays_a_limit_at_every_check() {
        // The link is read and stored `partial`; that row is the limit's own and is no
        // evidence that what it leads to was read, so the next check decides the same.
        let h = here("closed-link-checks");
        for (by, why) in closings(&h) {
            for run in ["run-1", "run-2", "run-3"] {
                let refusal = refused(libc::EACCES, by.clone(), h.system.join(TO));
                let decided = h.decided(why, MET, refusal, &[]);
                assert_eq!(
                    decided,
                    Content::Unread(Cause::NotGiven, why.into()),
                    "{run}"
                );
                h.wrote(why, MET, run, &decided, Some(TO));
            }
            let row = (
                "partial".to_string(),
                Some(why.to_string()),
                Some("not_given".into()),
            );
            assert_eq!(rows(&h, why, MET), vec![row; 3]);
        }
    }

    #[test]
    fn a_program_closed_by_another_account_stays_a_limit_at_every_check_with_its_row_none() {
        // A program that could not be opened keeps no link, so its row is `none`, as before.
        let h = here("closed-program-checks");
        for (by, why) in closings(&h) {
            for run in ["run-1", "run-2"] {
                let refusal = refused(libc::EACCES, by.clone(), h.system.join(TO));
                let decided = h.decided(why, MET, refusal, &[]);
                assert_eq!(
                    decided,
                    Content::Unread(Cause::NotGiven, why.into()),
                    "{run}"
                );
                h.wrote(why, MET, run, &decided, None);
            }
            let row = (
                "none".to_string(),
                Some(why.to_string()),
                Some("not_given".into()),
            );
            assert_eq!(rows(&h, why, MET), vec![row; 2]);
        }
    }

    #[test]
    fn a_watched_link_read_once_and_closed_later_is_failed_at_every_later_check() {
        // Also after a check that wrote the failed row, and also when a row of the limit came
        // before the reading that read it.
        let h = here("closed-link-read");
        let hash = Content::Hash("sha256:00".into());
        for (by, why) in closings(&h) {
            for limit_first in [false, true] {
                let machine = format!("{why}-{limit_first}");
                if limit_first {
                    let limit = Content::Unread(Cause::NotGiven, why.into());
                    h.wrote(&machine, MET, "run-0", &limit, Some(TO));
                }
                h.wrote(&machine, MET, "run-1", &hash, Some(TO));
                for run in ["run-2", "run-3", "run-4"] {
                    let refusal = refused(libc::EACCES, by.clone(), h.system.join(TO));
                    let decided = h.decided(&machine, MET, refusal, &[]);
                    let failed = Content::Unread(Cause::Failed, why.into());
                    assert_eq!(decided, failed, "{machine} {run}");
                    h.wrote(&machine, MET, run, &decided, Some(TO));
                }
            }
        }
    }

    #[test]
    fn a_row_of_any_other_cause_or_reason_is_evidence_that_it_was_read() {
        // Only the limit's own row is left out: one not given for another reason, as a link
        // into a folder macOS asks permission for, and one of another cause with a reason of
        // the limit, still count.
        let h = here("closed-other-rows");
        let guarded = "not looked into: it leads into a folder macOS asks permission for";
        let cases = [
            ("guarded", guarded, Cause::NotGiven),
            ("failed", CLOSED, Cause::Failed),
            ("no-reader", CLOSED_ON_THE_WAY, Cause::NoReader),
        ];
        for (machine, why, cause) in cases {
            h.row(
                machine,
                MET,
                "run-1",
                ("partial", Some(why), Gap::of(cause)),
                Some(TO),
            );
            let refusal = refused(libc::EACCES, By::File(0), h.system.join(TO));
            let decided = h.decided(machine, MET, refusal, &[]);
            assert_eq!(
                decided,
                Content::Unread(Cause::Failed, CLOSED.into()),
                "{machine}"
            );
        }
    }

    /// A folder of this account's own, closed to it, in `dir`, with a file inside.
    fn shut(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let shut = std::fs::canonicalize(dir).unwrap().join("shut");
        std::fs::create_dir_all(&shut).unwrap();
        std::fs::write(shut.join("helper"), "invented\n").unwrap();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
        shut
    }

    #[test]
    fn the_walk_finds_the_folder_that_refused_made_real_with_its_owner() {
        let dir = crate::common::Scratch::new("closed-walk");
        let shut = shut(&dir);
        // SAFETY: geteuid has no preconditions and cannot fail.
        let us = unsafe { libc::geteuid() };
        let found = By::Folder(shut.clone(), us);
        // As met, through a link to the file, and through a link to the folder.
        std::os::unix::fs::symlink("shut/helper", dir.join("to-file")).unwrap();
        std::os::unix::fs::symlink("shut", dir.join("to-folder")).unwrap();
        for path in ["shut/helper", "to-file", "to-folder/helper"] {
            assert_eq!(By::walk(&dir.join(path), &[]), found, "{path}");
        }
        // Not found: every part seen, a part not there.
        std::fs::write(dir.join("open"), "invented\n").unwrap();
        for path in ["open", "gone/helper"] {
            assert_eq!(By::walk(&dir.join(path), &[]), By::Untold, "{path}");
        }
        // The file itself, taken after the refusal; gone since, not found.
        let open = dir.join("open");
        assert_eq!(By::file(&open), By::File(us));
        assert_eq!(By::file(&dir.join("gone")), By::Untold);
    }
}
