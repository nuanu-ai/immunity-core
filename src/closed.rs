//! Whether a file the system would not let this account read is a limit or a fault, decided
//! here alone (`cause`). A reader reports every failure to read a file's bytes as failed, with
//! what the system said and whose the file is (`watched::bytes`), and nothing else picks the
//! calm cause. `settle` decides each of a pass's failures before any row of the pass is
//! written.
//!
//! A failure is not given by its source, a limit, only when both hold:
//!
//! 1. Another account closed the file to this one: the system refused with EACCES, and the file
//!    belongs to another account. Nothing running as the person can close a file another
//!    account owns. EPERM never counts: macOS gives it for its privacy protection and the
//!    sandbox, which the person or anything running as them grants and takes back with no
//!    change to the file.
//! 2. Nothing read it here under any name the reading and the store know: a content reading of
//!    any run, this one included, that read something (`partial` too), or an entry of this pass
//!    that did; by its name as met, by its name made real, by another spelling of either that a
//!    Mac volume takes as the same (`spelling::key`), or through a stored link that leads to it.
//!
//! Everything else that failed is a fault. The stored form of the limit is what it was before
//! this file: cause `not_given` with the reason `watched::CLOSED`, which `covered` lists under
//! `other-accounts-files`.

use crate::look::Look;
use crate::store::Cause;
use crate::watched::{self, CLOSED, Content, Roots};
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// A file's bytes that could not be read, as the reader met it.
#[derive(Debug, PartialEq)]
pub struct Failure {
    /// The system's error number.
    pub errno: Option<i32>,
    /// The account that owns the file, and the one reading, by uid.
    pub owner: u32,
    pub us: u32,
    /// The path that was opened, made real.
    pub real: PathBuf,
    /// What the system said.
    pub why: String,
}

impl Failure {
    /// Condition 1: another account closed the file to this one.
    fn closed(&self) -> bool {
        self.errno == Some(libc::EACCES) && self.owner != self.us
    }

    /// Why it was not read: `CLOSED` for another account's closed file, which is not the
    /// person's to fix (`covered::not_permitted`), else what the system said.
    pub fn why(&self) -> String {
        if self.closed() {
            CLOSED.to_string()
        } else {
            self.why.clone()
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
}

/// The one decision: a failure is not given only when another account closed the file and
/// nothing read it here under any of `names`; else it failed.
pub fn cause(failure: &Failure, names: &[String], read: &Read) -> Cause {
    if failure.closed() && !names.iter().any(|n| read.has(n)) {
        Cause::NotGiven
    } else {
        Cause::Failed
    }
}

/// Decides every failure among the entries of `looks` (`cause`), by what the store and the
/// looks of this pass read, `others` among them; returns the cause of each. A file is named as
/// it was met and as its real path is named under the Mac's root or a home folder.
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
    let mut out = Vec::new();
    for e in looks.iter_mut().flat_map(|l| &mut l.entries) {
        let Content::Failed(f) = &e.content else {
            continue;
        };
        let mut names = vec![
            e.unit.path.clone(),
            crate::targets::from_root(roots.system, &f.real),
        ];
        let rel = homes.iter().filter_map(|h| f.real.strip_prefix(h).ok());
        names.extend(rel.map(|r| r.to_string_lossy().into_owned()));
        let cause = cause(f, &names, &read);
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
            let (why, gap) = match read {
                "full" => (None, Gap::default()),
                _ => (Some("invented"), Gap::of(Cause::Failed)),
            };
            crate::store::put_coverage(&tx, &r, read, why, &gap).unwrap();
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

    /// The system's refusal of `real`, a file of `owner`, read as account 501.
    fn refused(errno: i32, owner: u32, real: PathBuf) -> Failure {
        let why = std::io::Error::from_raw_os_error(errno).to_string();
        Failure {
            errno: Some(errno),
            owner,
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
        let failed = refused(libc::EACCES, 0, real);
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
            let decided = h.decided(machine, MET, refused(libc::EACCES, 0, real.clone()), &[]);
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
            let refusal = refused(libc::EACCES, 0, real.clone());
            assert_eq!(
                h.decided(machine, MET, refusal, &others),
                failed,
                "{machine}"
            );
        }
    }

    #[test]
    fn a_refusal_with_eperm_is_failed_whoever_owns_the_file() {
        // macOS gives EPERM for its privacy protection and the sandbox; a test cannot make it
        // without a prompt, so the decision is asked of the number.
        let h = here("closed-eperm");
        let real = h.system.join("Library/Example/helper.plist");
        for owner in [0, 501] {
            let why = "Operation not permitted (os error 1)";
            let decided = h.decided("mac", MET, refused(libc::EPERM, owner, real.clone()), &[]);
            assert_eq!(
                decided,
                Content::Unread(Cause::Failed, why.into()),
                "{owner}"
            );
        }
    }

    #[test]
    fn the_persons_own_closed_file_is_failed_with_what_the_system_said() {
        let h = here("closed-own");
        let real = h.system.join("Library/Example/helper.plist");
        let decided = h.decided("mac", MET, refused(libc::EACCES, 501, real), &[]);
        let why = "Permission denied (os error 13)";
        assert_eq!(decided, Content::Unread(Cause::Failed, why.into()));
    }
}
