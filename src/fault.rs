//! Whether a reading that failed is a fault or a limit. A fault is a shortfall Immunity Core has
//! reason to expect met on this Mac now: its own work (a full check, the watcher, the collector
//! once installed, current downloads), which is said where that work is; or something given
//! here before, which this file decides for a reading whose cause is `failed`. What is left of
//! a failed reading is a limit of this version here, as no reader and a source that does not
//! give it are. Who can fix it chooses only the words, never the sort.
//!
//! Given here before, by how the store keeps each reader's readings:
//! - a reader that records units in the baseline (`baseline.rs`: the watched places, autorun
//!   parts, startup programs, the checkout walk) is judged by unit. A unit its reading names as
//!   one it could not read (`look::names_failed`) was given before when `unit_read` holds it
//!   with `how = 'read'`, or `part_read` the part. The content of a watched file has a reading of
//!   its own per file, and was given before when one of them was full (`Latest::last_full`). A
//!   checkout the walk could not look at, or one that is now a link and was not looked into, is
//!   one the store holds, so it was found before. A unit only seen, never read, was not given.
//! - a server is judged by the machine: given before when a reading of it read anything. Its
//!   readings are sorted where the servers' causes are made (`server_read`), never here.
//! - any other reader reads a whole source that is present on this Mac, so its reading that
//!   failed is a fault whether it was full before or never was: the check's own work.
//!
//! A unit read in full earlier in the same check counts as given, the louder of the two
//! readings.

use crate::baseline::Unit;
use crate::view::Latest;
use crate::{checkouts, servers, watched};
use rusqlite::{Connection, params};

/// Whether `r`, a reading whose cause is `failed`, is a fault by the rule above.
pub fn reading(conn: &Connection, r: &Latest) -> rusqlite::Result<bool> {
    match r.reader.as_str() {
        watched::READER if r.kind == watched::CONTENT => Ok(r.last_full.is_some()),
        // A known checkout the walk could not look at, or one a link took the place of, is one
        // the store holds: found before.
        watched::READER | checkouts::READER if held_checkout(r) => Ok(true),
        watched::READER | checkouts::READER => unit_read_before(conn, r),
        _ => Ok(true),
    }
}

/// Whether a reading says it could not look at a checkout the store holds.
fn held_checkout(r: &Latest) -> bool {
    let reason = r.reason.as_deref().unwrap_or_default();
    [checkouts::NOT_TOLD, checkouts::MOVED]
        .iter()
        .any(|held| reason.contains(held))
}

/// Whether a reading names as not read a unit or a part that its reader read in full before.
fn unit_read_before(conn: &Connection, r: &Latest) -> rusqlite::Result<bool> {
    let reason = r.reason.as_deref().unwrap_or_default();
    let mut stmt = conn.prepare(
        "SELECT unit, '' FROM unit_read WHERE reader = ?1 AND kind = ?2 AND how = 'read'
         UNION ALL SELECT unit, part FROM part_read WHERE reader = ?1 AND kind = ?2",
    )?;
    for unit in stmt.query_map(params![r.reader, r.kind], |row| {
        Ok(Unit::part(
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
        ))
    })? {
        if crate::look::names_failed(reason, &unit?.to_string()) {
            return Ok(true);
        }
    }
    Ok(false)
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
    use crate::covered::{self, NOT_PERMITTED, OTHER_ACCOUNTS, READING_FAILED};
    use crate::store::{Cause, Gap, Reading};

    const MAC: &str = "machine:example-mac";
    const AGENTS: &str = "launch agents and daemons";
    const DENIED: &str = "Permission denied (os error 13)";

    /// A reading: its reader, scope and kind.
    type Of<'a> = (&'a str, &'a str, &'a str);

    /// A store with this Mac read in it.
    fn store(tag: &str) -> (crate::common::Scratch, Connection) {
        let dir = crate::common::Scratch::new(tag);
        let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        put(&conn, (watched::READER, MAC, AGENTS), "run-0", None);
        (dir, conn)
    }

    /// One reading in a run: full, or not with why and its cause (`partial` when the cause is
    /// not given, as a link into a protected folder is).
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

    /// Records units of the watched launch agents read in full in a run, a part as `file#part`.
    fn read(conn: &Connection, run: &str, units: &[&str]) {
        record(conn, run, units, &[]);
    }

    /// Records units of the watched launch agents read and seen in a run.
    fn record(conn: &Connection, run: &str, read: &[&str], seen: &[&str]) {
        let tx = conn.unchecked_transaction().unwrap();
        let units = |units: &[&str]| -> Vec<Unit> {
            (units.iter())
                .map(|u| match u.split_once('#') {
                    Some((path, part)) => Unit::part(path, part),
                    None => Unit::whole(*u),
                })
                .collect()
        };
        let (read, seen) = (units(read), units(seen));
        crate::baseline::record(&tx, watched::READER, AGENTS, run, 1, &read, &seen).unwrap();
        tx.commit().unwrap();
    }

    /// Whether the latest reading `of` is a fault.
    fn fault(conn: &Connection, of: Of) -> bool {
        let latest = crate::view::latest_coverage(conn).unwrap();
        let r = latest
            .iter()
            .find(|r| (r.reader.as_str(), r.scope.as_str(), r.kind.as_str()) == of);
        reading(conn, r.unwrap()).unwrap()
    }

    /// The items of the causes of readings that failed, each with its count and whether it is a
    /// fault, and the state of this Mac.
    fn sorted(conn: &Connection) -> (Vec<(&'static str, usize, bool)>, &'static str) {
        let latest = crate::view::latest_coverage(conn).unwrap();
        let p = crate::status::problems(conn, &latest).unwrap();
        let ids = [
            NOT_PERMITTED.id,
            READING_FAILED.id,
            OTHER_ACCOUNTS.id,
            covered::SERVERS_NOT_OPENED.id,
            covered::SERVERS_NOT_CHECKED.id,
        ];
        let items = covered::not_covered(conn, &latest, &p, None).unwrap();
        let items = (items.iter().filter(|u| ids.contains(&u.cause.id)))
            .map(|u| (u.cause.id, u.count, u.fault))
            .collect();
        (
            items,
            covered::this_mac(conn, &latest, false).unwrap().state,
        )
    }

    /// The scope of the content of a watched file.
    fn content(path: &str) -> String {
        format!("file:{MAC}/{path}")
    }

    #[test]
    fn a_unit_or_a_part_read_before_and_named_unreadable_now_is_a_fault_and_one_never_read_a_limit()
    {
        let (_dir, conn) = store("fault-units");
        let agents = (watched::READER, MAC, AGENTS);
        let (a, part) = (
            "Library/LaunchAgents/a.plist",
            "Library/Preferences/p.plist#/LoginHook",
        );
        read(&conn, "run-1", &[a, part]);
        let failed = |units: &[&str]| {
            let said: Vec<String> = units.iter().map(|u| format!("{u} (denied)")).collect();
            format!("could not be read: {}", said.join("; "))
        };
        let never = "Library/LaunchAgents/b.plist";
        for (units, expected) in [
            (vec![never], false),
            (vec![never, a], true),
            (vec![part], true),
            // A name that holds one read before is not it.
            (vec!["Library/LaunchAgents/a.plist.bak"], false),
        ] {
            put(
                &conn,
                agents,
                "run-2",
                Some((&failed(&units), Cause::Failed)),
            );
            assert_eq!(fault(&conn, agents), expected, "{units:?}");
        }
        // Read before and not looked into now, as a link into a folder macOS protects: not named
        // as a unit that could not be read.
        let into = format!(
            "{}; not looked into: {a}: leads into ~/Documents",
            failed(&[never])
        );
        put(&conn, agents, "run-3", Some((&into, Cause::Failed)));
        assert!(!fault(&conn, agents));
        // A unit only seen before, its name listed and its content never read, was not given.
        let seen = "Library/LaunchAgents/seen.plist";
        record(&conn, "run-3", &[], &[seen]);
        put(
            &conn,
            agents,
            "run-3",
            Some((&failed(&[seen]), Cause::Failed)),
        );
        assert!(!fault(&conn, agents));
        // A unit read in full earlier in the same check is given here before.
        read(&conn, "run-4", &[never]);
        put(
            &conn,
            agents,
            "run-4",
            Some((&failed(&[never]), Cause::Failed)),
        );
        assert!(fault(&conn, agents));
    }

    #[test]
    fn a_file_read_before_under_its_name_is_given_and_one_reached_under_a_new_name_is_not() {
        // The store keys a file by its name. A file renamed, or a link put under a new name, is
        // a file never read under that name: a limit. A link put in its place under the name
        // read before is a fault, as is any file read there before.
        let (_dir, conn) = store("fault-renamed");
        let (old, new) = (content(".zshrc"), content(".zshrc-renamed"));
        let old = (watched::READER, old.as_str(), watched::CONTENT);
        let new = (watched::READER, new.as_str(), watched::CONTENT);
        put(&conn, old, "run-1", None);
        put(&conn, old, "run-2", Some((DENIED, Cause::Failed)));
        put(&conn, new, "run-2", Some((DENIED, Cause::Failed)));
        assert!(fault(&conn, old));
        assert!(!fault(&conn, new));
        // The same for units: a unit read before is judged by its own name.
        let agents = (watched::READER, MAC, AGENTS);
        read(&conn, "run-1", &["Library/LaunchAgents/a.plist"]);
        let renamed = "could not be read: Library/LaunchAgents/renamed.plist (denied)";
        put(&conn, agents, "run-2", Some((renamed, Cause::Failed)));
        assert!(!fault(&conn, agents));
    }

    #[test]
    fn a_content_read_full_earlier_in_the_same_check_is_given_and_one_read_only_through_a_link_never_was()
     {
        let (_dir, conn) = store("fault-same-check");
        let same = content(".zshrc");
        let same = (watched::READER, same.as_str(), watched::CONTENT);
        put(&conn, same, "run-1", None);
        put(&conn, same, "run-1", Some((DENIED, Cause::Failed)));
        assert!(fault(&conn, same));
        // Partial only: a link into a folder macOS protects, where it points read and never
        // what it leads to. Then a failure: never given here.
        let linked = content(".bashrc");
        let linked = (watched::READER, linked.as_str(), watched::CONTENT);
        put(
            &conn,
            linked,
            "run-1",
            Some(("not looked into: ~/Documents", Cause::NotGiven)),
        );
        put(&conn, linked, "run-2", Some((DENIED, Cause::Failed)));
        assert!(!fault(&conn, linked));
    }

    #[test]
    fn a_file_of_another_account_closed_here_is_never_the_persons_to_fix_and_a_fault_only_once_read_here()
     {
        // Each as the reading of a watched file's content stores it: one never read here is a
        // limit and leaves this Mac watched; one read here before is a fault and holds it in
        // part, whoever owns it; neither of another account is the person's to fix, as their
        // own closed file is.
        let (_dir, conn) = store("fault-closed");
        let closed = Some((watched::CLOSED, Cause::Failed));
        let paths = [
            "Library/Example/helper",
            "Users/example/.zprofile",
            "Users/example/.zshrc",
        ];
        let [theirs, read_here, own] = paths.map(content);
        fn of(scope: &str) -> Of<'_> {
            (watched::READER, scope, watched::CONTENT)
        }
        put(&conn, of(&theirs), "run-1", closed);
        assert_eq!(
            sorted(&conn),
            (vec![(OTHER_ACCOUNTS.id, 1, false)], "watched")
        );
        put(&conn, of(&read_here), "run-1", None);
        put(&conn, of(&read_here), "run-2", closed);
        let both = vec![(OTHER_ACCOUNTS.id, 1, true), (OTHER_ACCOUNTS.id, 1, false)];
        assert_eq!(sorted(&conn), (both, "watched_in_part"));
        put(&conn, of(&own), "run-1", None);
        put(&conn, of(&own), "run-2", Some((DENIED, Cause::Failed)));
        assert_eq!(sorted(&conn).0[0], (NOT_PERMITTED.id, 1, true));
    }

    #[test]
    fn a_failed_reading_of_a_whole_source_is_a_fault_whether_or_not_it_was_ever_full() {
        let (_dir, conn) = store("fault-whole");
        let integrity = (crate::integrity::READER, MAC, "installed applications");
        let denied = "could not be read: /Applications/Example.app (denied)";
        put(&conn, integrity, "run-1", Some((denied, Cause::Failed)));
        let held = (vec![(READING_FAILED.id, 1, true)], "watched_in_part");
        assert_eq!(sorted(&conn), held);
        put(&conn, integrity, "run-2", None);
        let lockfiles = (crate::lockfiles::READER, MAC, crate::lockfiles::KIND);
        put(&conn, lockfiles, "run-1", None);
        let lockfile = "could not be read: package-lock.json";
        put(&conn, lockfiles, "run-2", Some((lockfile, Cause::Failed)));
        assert!(fault(&conn, lockfiles));
    }

    #[test]
    fn a_known_checkout_the_walk_could_not_look_at_is_a_fault_and_a_folder_never_listed_a_limit() {
        let (_dir, conn) = store("fault-walk");
        let walk = (checkouts::READER, MAC, checkouts::KIND);
        let shut = "could not be read: Library/Shut (denied)";
        put(&conn, walk, "run-1", Some((shut, Cause::Failed)));
        assert!(!fault(&conn, walk));
        let known = format!("{}dev/shop", checkouts::NOT_TOLD);
        put(&conn, walk, "run-2", Some((&known, Cause::Failed)));
        assert!(fault(&conn, walk));
        // The hooks of a checkout the store holds that a link took the place of.
        let hooks = (
            watched::READER,
            "checkout:example-mac/dev/shop",
            watched::HOOK_KIND,
        );
        let moved = format!("dev/shop {}", checkouts::MOVED);
        put(&conn, hooks, "run-2", Some((&moved, Cause::Failed)));
        assert!(fault(&conn, hooks));
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
