//! Whether what was not read is a fault or a limit. A fault is a shortfall Immunity Core has
//! reason to expect met on this Mac now: its own work (a full check, the watcher, the collector
//! once installed, current downloads), which is said where that work is; a reading that failed;
//! or something read here before and not read now, which this file finds. What is left is a
//! limit of this version here, as no reader and a source that does not give it are. Who can
//! fix it chooses only the words, never the sort.
//!
//! The invariant: for every store, the faults of this build are a superset of what main calls
//! failed, plus the units of rule 1. Every reading that failed is a fault (`covered::failed`),
//! as it is a failure on main; a file of another account closed to this one and never read here
//! is not given by its source, as on main (`closed::cause`), and so is no failure.
//!
//! 1. A unit of the watched places, the startup programs or the checkout walk is a fault when
//!    the baseline marks it not read now (`unit_unread`, `part_unread`) and it was read here
//!    before by the baseline's own predicate, the one that makes losing sight of it a finding
//!    (`baseline::Judge::facts`), which counts what was read inside a folder: whatever the
//!    cause, and whatever the latest reading of its kind says. A failure of these readings names its unit where it has one: a
//!    file or a folder not read, a folder the walk could not list or its root, what Git's
//!    configuration says of a checkout's hooks (`watched::hooks_told`), and what a startup item
//!    runs, the item standing for it. The content of a watched file is a unit of its own
//!    reading, lost when that reading is not full and an earlier one was (`Latest::last_full`).
//!    A mark ends when its unit is read again, something inside it is read, it or a folder
//!    holding it is found absent, or what holds it is gone: its file, or for a kind read in
//!    projects the deepest checkout the store ever knew that held it.
//! 2. One line for one thing: a unit of rule 1 is left out while a failed reading of its reader
//!    and kind stands in the same answer, which tells it; the content of a file, while its own
//!    reading failed. It is named where no such reading stands, as when a later, narrower
//!    reading of its kind was full. It only ever removes a line beside another fault of the
//!    same kind, never the last one.

use crate::baseline::{self, Unit};
use crate::covered::{self, Cause, Example, Uncovered};
use crate::store;
use crate::view::Latest;
use crate::watched;
use rusqlite::Connection;
use std::collections::BTreeSet;

/// The deepest checkout the store ever knew on `machine` that holds `path`, as
/// `<machine>/<path>`, the way `baseline::past_checkouts` names it.
fn deepest<'a>(known: &'a BTreeSet<String>, machine: &str, path: &str) -> Option<&'a str> {
    let rel = |c: &'a String| c.strip_prefix(machine)?.strip_prefix('/');
    (known.iter())
        .filter(|c| rel(c).is_some_and(|rel| baseline::under(path, rel)))
        .max_by_key(|c| c.len())
        .map(String::as_str)
}

/// Whether a unit marked unread by `run_id` was read before that run, by the baseline's own
/// predicate.
fn read_before(
    conn: &Connection,
    reader: &str,
    kind: &str,
    unit: &Unit,
    run_id: &str,
) -> rusqlite::Result<bool> {
    let judge = baseline::Judge {
        tx: conn,
        reader,
        kind,
        run_id,
        first_check: false,
        checkouts: &[],
    };
    Ok(judge.facts(unit)?.read_before)
}

/// A unit read here before and not read now, by rule 1.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lost {
    /// The file it is, as ids name it: `file:<machine>/<unit>`.
    pub id: String,
    /// Whether the readings of its kind are of a checkout, as a checkout's hooks are, rather
    /// than of this Mac (`covered::this_mac`).
    pub project: bool,
}

/// Every unit read here before and not read now, each once, by rule 1, less those a failed
/// reading in `latest` tells by rule 2.
pub fn lost(conn: &Connection, latest: &[Latest]) -> rusqlite::Result<Vec<Lost>> {
    let Some(machine) = covered::this_machine(conn)? else {
        return Ok(Vec::new());
    };
    let gone: Vec<String> = conn
        .prepare("SELECT id FROM gone_entity")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let file = format!("file:{machine}/");
    let known = baseline::past_checkouts(conn)?;
    // A gone file takes its marks; a gone checkout, those of the kinds read in projects whose
    // deepest known checkout it was.
    let held = |project: bool, unit: &Unit| {
        let checkout = (deepest(&known, &machine, &unit.path)).map(|c| format!("checkout:{c}"));
        !gone.iter().any(|g| {
            g.strip_prefix(&file) == Some(&unit.to_string())
                || project && checkout.as_ref() == Some(g)
        })
    };
    let marks: Vec<(String, String, Unit, String)> = conn
        .prepare(
            "SELECT reader, kind, unit, '', run_id FROM unit_unread
             UNION ALL SELECT reader, kind, unit, part, run_id FROM part_unread",
        )?
        .query_map([], |r| {
            let unit = Unit::part(r.get::<_, String>(2)?, r.get::<_, String>(3)?);
            Ok((r.get(0)?, r.get(1)?, unit, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let failed: BTreeSet<(&str, &str)> = (latest.iter())
        .filter(|r| covered::failed(r))
        .map(|r| (r.reader.as_str(), r.kind.as_str()))
        .collect();
    let mut out = Vec::new();
    for (reader, kind, unit, run_id) in marks {
        let told = failed.contains(&(reader.as_str(), kind.as_str()));
        let in_projects = crate::autorun::in_projects(&kind);
        if !told && held(in_projects, &unit) && read_before(conn, &reader, &kind, &unit, &run_id)? {
            out.push(Lost {
                id: format!("{file}{unit}"),
                project: kind == watched::HOOK_KIND,
            });
        }
    }
    let content = (latest.iter())
        .filter(|r| r.reader == watched::READER && r.kind == watched::CONTENT)
        .filter(|r| r.completeness != "full" && r.last_full.is_some())
        .filter(|r| !covered::failed(r));
    out.extend(content.map(|r| Lost {
        id: r.scope.clone(),
        project: false,
    }));
    out.sort();
    out.dedup();
    Ok(out)
}

/// What was read here before and is not read now, by name, whatever the cause (`lost`).
pub const NO_LONGER_READ: Cause = Cause {
    id: "read-before-not-read-now",
    who: covered::YOU,
    class: store::Cause::Failed,
    scope: "this_mac",
    kind: "read here before, not read now",
    title: [
        "{n} thing read here before can no longer be read.",
        "{n} things read here before can no longer be read.",
    ],
    meaning: "An earlier check read them and the latest could not, so a change in them goes unseen. They are listed by name.",
    meaning_none: None,
    advice: "If you did not change them on purpose, your agent can find out why. Each stays here until a check reads it again or finds it gone.",
};

/// The item of rule 1: what was read here before and is not read now, each by its name as
/// `place` gives it; `None` when nothing is.
pub fn item(
    conn: &Connection,
    latest: &[Latest],
    place: impl Fn(&str) -> String,
) -> rusqlite::Result<Option<Uncovered>> {
    let lost = lost(conn, latest)?;
    let scope = match lost.iter().all(|l| l.project) {
        true => "projects",
        false => "this_mac",
    };
    Ok((!lost.is_empty()).then(|| Uncovered {
        scope,
        examples: lost.iter().map(|l| Example::named(place(&l.id))).collect(),
        ..Uncovered::new(&NO_LONGER_READ, lost.len())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkouts;
    use crate::contract::v1::{Headline, ThisMacState};
    use crate::covered::{NOT_PERMITTED, OTHER_ACCOUNTS, READING_FAILED};
    use crate::store::{Cause, Gap, Reading};
    use rusqlite::params;

    const MAC: &str = "machine:example-mac";
    const AGENTS: &str = "launch agents and daemons";
    const DENIED: &str = "Permission denied (os error 13)";

    /// A reading: its reader, scope and kind.
    type Of<'a> = (&'a str, &'a str, &'a str);

    const PLACES: Of = (watched::READER, MAC, AGENTS);

    /// A store with this Mac read in it.
    fn store(tag: &str) -> (crate::common::Scratch, Connection) {
        let dir = crate::common::Scratch::new(tag);
        let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        put(&conn, PLACES, "run-0", None);
        (dir, conn)
    }

    /// One reading in a run: full, or not with why and its cause (`partial` when the cause is
    /// not given, as a link into a protected folder is; `None` for a cause not kept).
    fn put(conn: &Connection, (reader, scope, kind): Of, run: &str, not: Option<(&str, Cause)>) {
        let tx = conn.unchecked_transaction().unwrap();
        crate::store::put_entity(&tx, scope).unwrap();
        let kinds = "INSERT OR IGNORE INTO coverage_kind (name) VALUES (?1)";
        tx.execute(kinds, [kind]).unwrap();
        let at = run[4..].parse::<i64>().unwrap();
        let r = Reading {
            reader,
            scope,
            kind,
            run_id: run,
            at,
            observed_at: at,
        };
        let (completeness, reason, gap) = match not {
            None => ("full", None, Gap::default()),
            Some((why, Cause::NotGiven)) => ("partial", Some(why), Gap::of(Cause::NotGiven)),
            Some((why, cause)) => ("none", Some(why), Gap::of(cause)),
        };
        crate::store::put_coverage(&tx, &r, completeness, reason, &gap).unwrap();
        tx.commit().unwrap();
    }

    /// A unit as `file` or `file#part`.
    fn unit(u: &str) -> Unit {
        match u.split_once('#') {
            Some((path, part)) => Unit::part(path, part),
            None => Unit::whole(u),
        }
    }

    /// Records units of `kind` of the watched places read in full and seen in a run.
    fn record(conn: &Connection, kind: &str, run: &str, read: &[&str], seen: &[&str]) {
        let tx = conn.unchecked_transaction().unwrap();
        let (read, seen): (Vec<Unit>, Vec<Unit>) = (
            read.iter().map(|u| unit(u)).collect(),
            seen.iter().map(|u| unit(u)).collect(),
        );
        baseline::record(&tx, watched::READER, kind, run, 1, &read, &seen).unwrap();
        tx.commit().unwrap();
    }

    /// Marks units of `kind` of the watched places not read in a run, as a reading does.
    fn unread(conn: &Connection, kind: &str, run: &str, units: &[&str]) {
        let tx = conn.unchecked_transaction().unwrap();
        for u in units {
            baseline::judged_unread(&tx, watched::READER, kind, &unit(u), run).unwrap();
        }
        tx.commit().unwrap();
    }

    /// The names of what is read before and not read now.
    fn lost_ids(conn: &Connection) -> Vec<String> {
        let latest = crate::view::latest_coverage(conn).unwrap();
        lost(conn, &latest)
            .unwrap()
            .into_iter()
            .map(|l| l.id)
            .collect()
    }

    /// The items of the causes of what was not read, each with its count and whether it is a
    /// fault; the state of this Mac; and the headline.
    fn sorted(conn: &Connection) -> (Vec<(&'static str, usize, bool)>, &'static str, &'static str) {
        let latest = crate::view::latest_coverage(conn).unwrap();
        let p = crate::status::problems(conn, &latest).unwrap();
        let ids = [
            NO_LONGER_READ.id,
            NOT_PERMITTED.id,
            READING_FAILED.id,
            OTHER_ACCOUNTS.id,
            covered::SERVERS_NOT_OPENED.id,
            covered::SERVERS_NOT_CHECKED.id,
        ];
        let items = covered::not_covered(conn, &latest, &p, None).unwrap();
        let this_mac = covered::this_mac(conn, &latest, false).unwrap().state;
        // The headline by its own rule, all else as calm needs it.
        let mut status = crate::headline::tests::calm();
        status.this_mac.as_mut().unwrap().state = match this_mac {
            "watched" => ThisMacState::Watched,
            _ => ThisMacState::WatchedInPart,
        } as i32;
        status.not_covered = items.iter().map(crate::status::uncovered_message).collect();
        let headline = match crate::headline::headline(&status).0 {
            Headline::Calm => "calm",
            Headline::InPart => "in_part",
            other => panic!("{other:?}"),
        };
        let items = (items.iter().filter(|u| ids.contains(&u.cause.id)))
            .map(|u| (u.cause.id, u.count, u.fault))
            .collect();
        (items, this_mac, headline)
    }

    /// The scope of the content of a watched file.
    fn content(path: &str) -> String {
        format!("file:{MAC}/{path}")
    }

    const A: &str = "Library/LaunchAgents/a.plist";
    const B: &str = "Library/LaunchAgents/b.plist";

    #[test]
    fn a_unit_read_before_and_not_read_now_is_a_fault_until_it_is_read_again_whatever_the_latest_reading_says()
     {
        let (_dir, conn) = store("fault-units");
        record(&conn, AGENTS, "run-1", &[A], &[]);
        // Whatever the cause: here not given, as a link into a folder macOS protects is.
        unread(&conn, AGENTS, "run-2", &[A]);
        put(
            &conn,
            PLACES,
            "run-2",
            Some(("not looked into", Cause::NotGiven)),
        );
        let lost = (
            vec![(NO_LONGER_READ.id, 1, true)],
            "watched_in_part",
            "in_part",
        );
        assert_eq!(sorted(&conn), lost);
        assert_eq!(lost_ids(&conn), [format!("file:{MAC}/{A}")]);
        // A later reading that does not look at it again, a check limited to some projects,
        // leaves it standing, full as that reading is.
        put(&conn, PLACES, "run-3", None);
        assert_eq!(sorted(&conn), lost);
        // Read again: it ends.
        record(&conn, AGENTS, "run-4", &[A], &[]);
        assert_eq!(sorted(&conn), (vec![], "watched", "calm"));
    }

    #[test]
    fn a_unit_read_before_and_found_absent_now_or_in_a_checkout_gone_is_no_fault() {
        let (_dir, conn) = store("fault-absent");
        record(&conn, AGENTS, "run-1", &[A, B], &[]);
        unread(&conn, AGENTS, "run-2", &[A, B]);
        assert_eq!(lost_ids(&conn).len(), 2);
        // The folder listed in full without it shows it gone; the one still met stays.
        let tx = conn.unchecked_transaction().unwrap();
        let listed = [Unit::whole("Library/LaunchAgents")];
        let met = std::collections::BTreeSet::from([B]);
        baseline::found_absent(&tx, watched::READER, AGENTS, &listed, &met).unwrap();
        tx.commit().unwrap();
        assert_eq!(lost_ids(&conn), [format!("file:{MAC}/{B}")]);
        // Hooks of a checkout read before and not read now stand while the store holds the
        // checkout, and go with it.
        let hook = "dev/shop/.git/hooks/pre-commit";
        record(&conn, watched::HOOK_KIND, "run-1", &[hook], &[]);
        unread(&conn, watched::HOOK_KIND, "run-2", &[hook]);
        let hook = Lost {
            id: format!("file:{MAC}/{hook}"),
            project: true,
        };
        let latest = crate::view::latest_coverage(&conn).unwrap();
        assert!(lost(&conn, &latest).unwrap().contains(&hook));
        // Told among the projects once nothing of this Mac's own places stands beside them.
        let scope = |conn: &Connection| {
            let p = crate::status::problems(conn, &latest).unwrap();
            let items = covered::not_covered(conn, &latest, &p, None).unwrap();
            let item = items.iter().find(|u| u.cause.id == NO_LONGER_READ.id);
            item.unwrap().scope
        };
        assert_eq!(scope(&conn), "this_mac");
        record(&conn, AGENTS, "run-3", &[B], &[]);
        assert_eq!(scope(&conn), "projects");
        // A project's hooks leave this Mac's own places watched, as their reading does.
        let state = covered::this_mac(&conn, &latest, false).unwrap().state;
        assert_eq!(state, "watched");
        let shop = format!("checkout:{MAC}/dev/shop");
        located(&conn, &shop, checkouts::READER, checkouts::KIND, false);
        assert!(!lost(&conn, &latest).unwrap().contains(&hook));
    }

    /// A thing, `subject`, located on this Mac by a reading of `reader` and `kind`: still
    /// there, or gone.
    fn located(conn: &Connection, subject: &str, reader: &str, kind: &str, there: bool) {
        let tx = conn.unchecked_transaction().unwrap();
        crate::store::put_entity(&tx, subject).unwrap();
        let kinds = "INSERT OR IGNORE INTO coverage_kind (name) VALUES (?1)";
        tx.execute(kinds, [kind]).unwrap();
        let (layer, retracted) = if there {
            ("live", None)
        } else {
            ("retracted", Some(3))
        };
        tx.execute(
            "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                    source_ref, basis, observed_at, run_id, retracted_at)
             VALUES (?5, ?1, 'located_on', ?2, ?3, ?2, ?4, 'x', 'observed', 1, 'run-1', ?6)",
            params![subject, MAC, reader, kind, layer, retracted],
        )
        .unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn a_gone_checkout_takes_only_the_marks_of_projects_it_held_deepest_and_a_gone_file_its_own() {
        let (_dir, conn) = store("fault-gone");
        // The home folder was once a checkout, as a repository of settings files is, and so
        // was `dev`, which holds a checkout still there.
        for (rel, there) in [(".", false), ("dev", false), ("dev/shop", true)] {
            let checkout = format!("checkout:{MAC}/{rel}");
            located(&conn, &checkout, checkouts::READER, checkouts::KIND, there);
        }
        let (kept, gone) = (
            "dev/shop/.git/hooks/pre-commit",
            "dev/.git/hooks/pre-commit",
        );
        record(&conn, AGENTS, "run-1", &[A, B], &[]);
        record(&conn, watched::HOOK_KIND, "run-1", &[kept, gone], &[]);
        unread(&conn, AGENTS, "run-2", &[A, B]);
        unread(&conn, watched::HOOK_KIND, "run-2", &[kept, gone]);
        // A file gone takes its own mark alone.
        located(
            &conn,
            &format!("file:{MAC}/{B}"),
            watched::READER,
            AGENTS,
            false,
        );
        assert_eq!(
            lost_ids(&conn),
            [A, kept].map(|u| format!("file:{MAC}/{u}"))
        );
    }

    #[test]
    fn a_part_of_a_unit_read_whole_before_is_a_fault_and_so_is_a_file_one_of_whose_parts_was_read()
    {
        let (_dir, conn) = store("fault-parts");
        let prefs = "Library/Preferences/p.plist";
        let key = format!("{prefs}#/LoginHook");
        record(&conn, AGENTS, "run-1", &[prefs], &[]);
        unread(&conn, AGENTS, "run-2", &[&key]);
        assert_eq!(lost_ids(&conn), [format!("file:{MAC}/{key}")]);
        record(&conn, AGENTS, "run-3", &[prefs], &[]);
        assert!(lost_ids(&conn).is_empty());
        // The reverse: one key read, the file seen; then the whole file unreadable.
        let other = "Library/Preferences/q.plist";
        record(
            &conn,
            AGENTS,
            "run-4",
            &[&format!("{other}#/LoginHook")],
            &[other],
        );
        unread(&conn, AGENTS, "run-5", &[other]);
        assert_eq!(lost_ids(&conn), [format!("file:{MAC}/{other}")]);
    }

    #[test]
    fn a_unit_never_read_here_or_read_only_in_the_run_that_marks_it_is_not_named() {
        let (_dir, conn) = store("fault-never");
        // Only seen, its name listed and what it holds never read; and never met.
        record(&conn, AGENTS, "run-1", &[], &[A]);
        unread(&conn, AGENTS, "run-2", &[A, B]);
        put(
            &conn,
            PLACES,
            "run-2",
            Some(("not looked into", Cause::NotGiven)),
        );
        assert!(lost_ids(&conn).is_empty());
        // Read in the run that judged it unread is not read before it, and neither is a
        // folder something inside which was read in that run.
        record(&conn, AGENTS, "run-2", &[B], &[]);
        unread(&conn, AGENTS, "run-2", &[B, "Library/LaunchAgents"]);
        assert!(lost_ids(&conn).is_empty());
        assert_eq!(sorted(&conn), (vec![], "watched", "calm"));
    }

    #[test]
    fn a_unit_read_before_is_left_out_while_a_failed_reading_of_its_kind_tells_it_and_named_once_none_does()
     {
        let (_dir, conn) = store("fault-told");
        record(&conn, AGENTS, "run-1", &[A], &[]);
        unread(&conn, AGENTS, "run-2", &[A]);
        put(&conn, PLACES, "run-2", Some((DENIED, Cause::Failed)));
        let told = (
            vec![(NOT_PERMITTED.id, 1, true)],
            "watched_in_part",
            "in_part",
        );
        assert_eq!(sorted(&conn), told);
        // A failed reading of another kind tells nothing of it.
        let other = (watched::READER, MAC, watched::LOGIN_HOOK_KIND);
        put(&conn, other, "run-2", Some((DENIED, Cause::Failed)));
        put(&conn, PLACES, "run-3", None);
        let named = vec![(NO_LONGER_READ.id, 1, true), (NOT_PERMITTED.id, 1, true)];
        assert_eq!(sorted(&conn), (named, "watched_in_part", "in_part"));
    }

    #[test]
    fn a_failed_reading_of_a_whole_source_is_a_fault_whether_or_not_it_was_ever_full() {
        let (_dir, conn) = store("fault-source");
        let integrity = (crate::integrity::READER, MAC, "installed applications");
        put(&conn, integrity, "run-1", Some(("denied", Cause::Failed)));
        let held = (
            vec![(READING_FAILED.id, 1, true)],
            "watched_in_part",
            "in_part",
        );
        assert_eq!(sorted(&conn), held);
        // A reading not full that kept no cause is read as failed.
        let lockfiles = (crate::lockfiles::READER, MAC, crate::lockfiles::KIND);
        put(&conn, integrity, "run-2", None);
        conn.execute(
            "INSERT OR IGNORE INTO coverage_kind (name) VALUES (?1)",
            [crate::lockfiles::KIND],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO coverage (reader, scope, kind, completeness, reason, run_id, observed_at)
             VALUES (?1, ?2, ?3, 'none', 'lost', 'run-3', 3)",
            params![lockfiles.0, lockfiles.1, lockfiles.2],
        )
        .unwrap();
        assert_eq!(sorted(&conn), held);
    }

    #[test]
    fn the_content_of_a_file_read_in_full_before_is_named_while_no_failed_reading_of_it_tells_it() {
        let (_dir, conn) = store("fault-content");
        fn of(scope: &str) -> Of<'_> {
            (watched::READER, scope, watched::CONTENT)
        }
        let paths = [
            "Users/example/.zshrc",
            "Library/Example/helper",
            "Users/example/.bashrc",
        ];
        let [read, theirs, linked] = paths.map(content);
        // Another account's file closed here, never read: not given, never the person's to fix.
        put(
            &conn,
            of(&theirs),
            "run-1",
            Some((watched::CLOSED, Cause::NotGiven)),
        );
        let closed = (vec![(OTHER_ACCOUNTS.id, 1, false)], "watched", "calm");
        assert_eq!(sorted(&conn), closed);
        // Read only through a link, where it points and never what it leads to: never full.
        put(
            &conn,
            of(&linked),
            "run-1",
            Some(("not looked into", Cause::NotGiven)),
        );
        put(&conn, of(&linked), "run-2", Some((DENIED, Cause::Failed)));
        assert!(!lost_ids(&conn).contains(&linked));
        // Read in full, then grown past what is read: no reader, and named.
        put(&conn, of(&read), "run-1", None);
        put(
            &conn,
            of(&read),
            "run-2",
            Some(("too large", Cause::NoReader)),
        );
        assert_eq!(lost_ids(&conn), std::slice::from_ref(&read));
        // Then closed: its failed reading tells it, once.
        put(&conn, of(&read), "run-3", Some((DENIED, Cause::Failed)));
        assert!(lost_ids(&conn).is_empty());
        let (items, state, headline) = sorted(&conn);
        assert_eq!((state, headline), ("watched_in_part", "in_part"));
        assert!(items.contains(&(NOT_PERMITTED.id, 2, true)), "{items:?}");
    }
}
