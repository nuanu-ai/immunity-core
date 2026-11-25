//! Whether what was not read is a fault or a limit. A fault is a shortfall Immunity Core has
//! reason to expect met on this Mac now: its own work (a full check, the watcher, the collector
//! once installed, current downloads), which is said where that work is; or something read here
//! before, which this file decides. What is left is a limit of this version here, as no reader
//! and a source that does not give it are. Who can fix it chooses only the words, never the
//! sort. Everything here is decided from the store's tables, never from a reading's reason.
//!
//! 1. A unit is a fault when the baseline marks it not read now (`unit_unread`, `part_unread`)
//!    and it was read here before by the baseline's own predicate, the one that makes losing
//!    sight of it a finding (`baseline::Judge::facts`): whatever the cause, and whatever the
//!    latest reading of its kind says, so a later reading that did not look at it again leaves
//!    it standing. It ends when the baseline forgets the mark, as a reading reads it again or
//!    finds it absent (`baseline::record`, `baseline::found_absent`), or when what holds it is
//!    gone (`gone_entity`). The content of a watched file is never recorded as read in the
//!    baseline, and its mark outlives the file: it has a reading of its own per file, which goes
//!    with the file, and is a fault when that reading is not full and an earlier one was
//!    (`Latest::last_full`), whatever its cause.
//! 2. A failed reading of a reader with units (the watched places, the checkout walk) that
//!    marked no unit unread in its run failed as a whole, the source not walked or not told: a
//!    fault. So is a failed reading of any other reader, which reads a whole source present on
//!    this Mac.
//! 3. A failed reading that marked units unread in its run is a limit as a reading, whatever
//!    those units are: the ones read before are told by rule 1, each once. So is the reading of
//!    one file's content and the reading of the programs startup items run: each program it
//!    could not open has a content reading of its own, and each startup item it could not tell
//!    is a unit of its own kind, so what of them was read before is told by rule 1 too.
//!
//! A server is judged by the machine where its causes are made (`server_read`).

use crate::baseline::{self, Unit};
use crate::view::Latest;
use crate::{checkouts, servers, targets, watched};
use rusqlite::{Connection, params};

/// Whether `r`, a reading that failed, is a fault by rules 2 and 3.
pub fn reading(conn: &Connection, r: &Latest) -> rusqlite::Result<bool> {
    match r.reader.as_str() {
        watched::READER if [watched::CONTENT, targets::KIND].contains(&r.kind.as_str()) => {
            Ok(false)
        }
        watched::READER | checkouts::READER => Ok(!marked_unread(conn, r)?),
        _ => Ok(true),
    }
}

/// Whether the reading `r` marked a unit unread in its run: within its checkout, for a reading
/// of one.
fn marked_unread(conn: &Connection, r: &Latest) -> rusqlite::Result<bool> {
    let checkout = r
        .scope
        .strip_prefix("checkout:")
        .map(|c| match c.split_once('/') {
            Some((_, rel)) => rel,
            None => c,
        });
    let units: Vec<String> = conn
        .prepare(
            "SELECT unit FROM unit_unread WHERE reader = ?1 AND kind = ?2 AND run_id = ?3
             UNION ALL SELECT unit FROM part_unread
             WHERE reader = ?1 AND kind = ?2 AND run_id = ?3",
        )?
        .query_map(params![r.reader, r.kind, r.run_id], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(units
        .iter()
        .any(|u| checkout.is_none_or(|rel| baseline::under(u, rel))))
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
    /// Whether it is in a project, as a checkout's hooks are, rather than in this Mac's own
    /// places.
    pub project: bool,
}

/// Every unit read here before and not read now, each once, by rule 1.
pub fn lost(conn: &Connection, latest: &[Latest]) -> rusqlite::Result<Vec<Lost>> {
    let Some(machine) = crate::covered::this_machine(conn)? else {
        return Ok(Vec::new());
    };
    let gone: Vec<String> = conn
        .prepare("SELECT id FROM gone_entity")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let file = format!("file:{machine}/");
    let checkout = format!("checkout:{machine}/");
    let held = |unit: &Unit| {
        !gone.iter().any(|g| {
            g.strip_prefix(&file) == Some(&unit.to_string())
                || g.strip_prefix(&checkout)
                    .is_some_and(|rel| baseline::under(&unit.path, rel))
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
    let mut out = Vec::new();
    for (reader, kind, unit, run_id) in marks {
        if held(&unit) && read_before(conn, &reader, &kind, &unit, &run_id)? {
            out.push(Lost {
                id: format!("{file}{unit}"),
                project: kind == watched::HOOK_KIND,
            });
        }
    }
    let content = (latest.iter())
        .filter(|r| r.reader == watched::READER && r.kind == watched::CONTENT)
        .filter(|r| r.completeness != "full" && r.last_full.is_some());
    out.extend(content.map(|r| Lost {
        id: r.scope.clone(),
        project: false,
    }));
    out.sort();
    out.dedup();
    Ok(out)
}

/// Whether the server check ever read something of a machine, `scope`.
pub fn server_read(conn: &Connection, scope: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage
                        WHERE reader = ?1 AND scope = ?2 AND completeness != 'none')",
        params![servers::READER, scope],
        |r| r.get(0),
    )
}

/// `things` in two lists by whether each is a fault, the faults first, an empty one left out:
/// a cause is told once for its faults and once for its limits, each holding only its own.
pub fn split<T>(
    things: Vec<T>,
    fault: impl Fn(&T) -> rusqlite::Result<bool>,
) -> rusqlite::Result<Vec<(bool, Vec<T>)>> {
    let (mut faults, mut limits) = (Vec::new(), Vec::new());
    for t in things {
        match fault(&t)? {
            true => faults.push(t),
            false => limits.push(t),
        }
    }
    Ok([(true, faults), (false, limits)]
        .into_iter()
        .filter(|(_, list)| !list.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::v1::{Headline, ThisMacState};
    use crate::covered::{self, NO_LONGER_READ, NOT_PERMITTED, OTHER_ACCOUNTS, READING_FAILED};
    use crate::store::{Cause, Gap, Reading};

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

    /// Whether the latest reading `of` is a fault by rules 2 and 3.
    fn fault(conn: &Connection, of: Of) -> bool {
        let latest = crate::view::latest_coverage(conn).unwrap();
        let r = latest
            .iter()
            .find(|r| (r.reader.as_str(), r.scope.as_str(), r.kind.as_str()) == of);
        reading(conn, r.unwrap()).unwrap()
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
        let shop = format!("checkout:{MAC}/dev/shop");
        let tx = conn.unchecked_transaction().unwrap();
        crate::store::put_entity(&tx, &shop).unwrap();
        tx.execute(
            "INSERT OR IGNORE INTO coverage_kind (name) VALUES (?1)",
            [checkouts::KIND],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                    source_ref, basis, observed_at, run_id, retracted_at)
             VALUES ('retracted', ?1, 'located_on', ?2, ?3, ?2, ?4, 'x', 'observed', 1, 'run-1', 3)",
            params![shop, MAC, checkouts::READER, checkouts::KIND],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(!lost(&conn, &latest).unwrap().contains(&hook));
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
    fn a_unit_never_read_here_is_a_limit_and_leaves_calm() {
        let (_dir, conn) = store("fault-never");
        // Only seen, its name listed and what it holds never read; and never met.
        record(&conn, AGENTS, "run-1", &[], &[A]);
        unread(&conn, AGENTS, "run-2", &[A, B]);
        put(&conn, PLACES, "run-2", Some((DENIED, Cause::Failed)));
        let limit = (vec![(NOT_PERMITTED.id, 1, false)], "watched", "calm");
        assert_eq!(sorted(&conn), limit);
        // Read in the run that judged it unread is not read before it.
        record(&conn, AGENTS, "run-2", &[B], &[]);
        unread(&conn, AGENTS, "run-2", &[B]);
        assert_eq!(sorted(&conn), limit);
    }

    #[test]
    fn a_reading_that_failed_as_a_whole_after_a_full_one_is_a_fault_and_one_that_left_units_unread_a_limit()
     {
        let (_dir, conn) = store("fault-whole");
        record(&conn, AGENTS, "run-1", &[A], &[]);
        // No unit marked unread in its run, as when the source could not be walked or told.
        put(
            &conn,
            PLACES,
            "run-2",
            Some(("could not be told", Cause::Failed)),
        );
        assert!(fault(&conn, PLACES));
        assert_eq!(sorted(&conn).0, [(READING_FAILED.id, 1, true)]);
        // A unit marked unread in an earlier run is not this reading's.
        unread(&conn, AGENTS, "run-1", &[B]);
        assert!(fault(&conn, PLACES));
        // Its own unread unit, never read here: a limit.
        unread(&conn, AGENTS, "run-2", &[B]);
        assert!(!fault(&conn, PLACES));
        // Beside one read before: still a limit as a reading, the unit told by its name alone.
        unread(&conn, AGENTS, "run-2", &[A]);
        assert!(!fault(&conn, PLACES));
        assert_eq!(lost_ids(&conn), [format!("file:{MAC}/{A}")]);
        // A reading of one checkout is judged by the units within it.
        let hooks = (
            watched::READER,
            "checkout:machine:example-mac/dev/shop",
            watched::HOOK_KIND,
        );
        put(
            &conn,
            hooks,
            "run-3",
            Some(("could not be told", Cause::Failed)),
        );
        unread(
            &conn,
            watched::HOOK_KIND,
            "run-3",
            &["dev/other/.git/hooks/x"],
        );
        assert!(fault(&conn, hooks));
        unread(
            &conn,
            watched::HOOK_KIND,
            "run-3",
            &["dev/shop/.git/hooks/x"],
        );
        assert!(!fault(&conn, hooks));
        // The checkout walk the same: a folder it could not list is a unit of its own.
        let walk = (checkouts::READER, MAC, checkouts::KIND);
        put(
            &conn,
            walk,
            "run-4",
            Some(("could not list", Cause::Failed)),
        );
        assert!(fault(&conn, walk));
        let tx = conn.unchecked_transaction().unwrap();
        let folder = Unit::whole("dev/closed");
        baseline::judged_unread(&tx, checkouts::READER, checkouts::KIND, &folder, "run-4").unwrap();
        tx.commit().unwrap();
        assert!(!fault(&conn, walk));
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
    fn the_content_of_a_file_read_in_full_before_is_a_fault_whatever_its_cause_and_one_never_read_full_a_limit()
     {
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
        // Another account's file closed here, never read: a limit, never the person's to fix.
        put(
            &conn,
            of(&theirs),
            "run-1",
            Some((watched::CLOSED, Cause::Failed)),
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
        // Read in full, then grown past what is read: no reader, and a fault.
        put(&conn, of(&read), "run-1", None);
        put(
            &conn,
            of(&read),
            "run-2",
            Some(("too large", Cause::NoReader)),
        );
        assert_eq!(lost_ids(&conn), std::slice::from_ref(&read));
        // Then closed: told once, by its name; its failed reading is a limit beside the one
        // read only through a link.
        put(&conn, of(&read), "run-3", Some((DENIED, Cause::Failed)));
        let (items, state, headline) = sorted(&conn);
        assert_eq!((state, headline), ("watched_in_part", "in_part"));
        assert!(items.contains(&(NO_LONGER_READ.id, 1, true)), "{items:?}");
        assert!(items.contains(&(NOT_PERMITTED.id, 2, false)), "{items:?}");
    }

    /// The reading of the programs startup items run, short of one it could not open, and that
    /// program's own content reading, as a check stores them: closed, of another account.
    fn startup_program(conn: &Connection, run: &str, read_before: bool) {
        let program = content("Library/Example/helper");
        let program = (watched::READER, program.as_str(), watched::CONTENT);
        if read_before {
            put(conn, program, "run-1", None);
        }
        put(conn, program, run, Some((watched::CLOSED, Cause::Failed)));
        let short = "not read in full: startup programs that could not be opened: 1";
        let targets = (watched::READER, MAC, targets::KIND);
        put(conn, targets, run, Some((short, Cause::Failed)));
    }

    #[test]
    fn a_startup_program_never_opened_here_is_a_limit_and_leaves_calm() {
        let (_dir, conn) = store("fault-program-never");
        startup_program(&conn, "run-2", false);
        let (items, state, headline) = sorted(&conn);
        assert_eq!((state, headline), ("watched", "calm"), "{items:?}");
        assert!(items.iter().all(|(_, _, fault)| !fault), "{items:?}");
    }

    #[test]
    fn a_startup_program_opened_before_and_closed_now_is_one_fault_by_its_name() {
        let (_dir, conn) = store("fault-program-before");
        startup_program(&conn, "run-2", true);
        let (items, state, headline) = sorted(&conn);
        assert_eq!((state, headline), ("watched_in_part", "in_part"));
        let faults: Vec<_> = items.iter().filter(|(_, _, fault)| *fault).collect();
        assert_eq!(faults, [&(NO_LONGER_READ.id, 1, true)], "{items:?}");
        assert_eq!(lost_ids(&conn), [content("Library/Example/helper")]);
    }

    #[test]
    fn a_server_read_before_and_not_reached_now_is_a_fault_and_one_never_opened_a_limit() {
        let (_dir, conn) = store("fault-servers");
        let visit = |m| (servers::READER, m, servers::VISIT);
        let refused = Some(("connection refused", Cause::Failed));
        put(&conn, visit("machine:example-server"), "run-1", None);
        put(&conn, visit("machine:example-server"), "run-2", refused);
        put(&conn, visit("machine:example-new"), "run-2", refused);
        let opened = covered::SERVERS_NOT_OPENED.id;
        assert_eq!(sorted(&conn).0, [(opened, 1, true), (opened, 1, false)]);
        // Read in part before is read before.
        let part = Some(("not looked into: /srv", Cause::NotGiven));
        put(
            &conn,
            (servers::READER, "machine:example-part", "packages"),
            "run-1",
            part,
        );
        put(&conn, visit("machine:example-part"), "run-2", refused);
        assert_eq!(sorted(&conn).0, [(opened, 2, true), (opened, 1, false)]);
        // A check that did not finish on them is sorted the same way.
        let unfinished = Some((servers::NOT_COMPLETE, Cause::Failed));
        put(&conn, visit("machine:example-server"), "run-3", unfinished);
        put(&conn, visit("machine:example-new"), "run-3", unfinished);
        let checked = covered::SERVERS_NOT_CHECKED.id;
        let all = [(checked, 1, true), (checked, 1, false), (opened, 1, true)];
        assert_eq!(sorted(&conn).0, all);
    }
}
