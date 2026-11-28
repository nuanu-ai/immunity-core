//! Draft becomes live at the end of a run, for one reading, by its coverage.
//! Full: new assertions become live and those no longer made are retracted, unless the reading
//! does not cover where they were (`may_go`): those are held back as they were.
//! Partial: new assertions become live and nothing is retracted.
//! None: nothing changes. A missing reading is not evidence of absence.
//!
//! A container or checkout that is no longer anywhere takes what was read inside it along:
//! when its last `located_on` is retracted, every live assertion of a reading scoped to it
//! is retracted in the same run, whatever that reading's completeness was, and with it what
//! was read inside anything located there. The entity's removal is the one event; what was
//! inside it adds none. This is decided once, after the run's last reader (`Run::settle` in
//! `main.rs`), so that no order of readers decides what goes.
//!
//! A kind an earlier version read and this one does not is retired, which is neither a full
//! reading nor a removal: nothing was looked at, so nothing is known to be gone. Its facts are
//! closed with a journal entry of their own, `retired`, that says why, and its reading becomes
//! `none` with no reader. It is done once per scope.

use crate::store::{Cause, Event, Gap, Reading};
use rusqlite::{Transaction, params};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

/// Objects per (subject, predicate), each with the id of one row that holds it.
type Layer = BTreeMap<(String, String), BTreeMap<String, i64>>;

fn load(tx: &Transaction, r: &Reading, layer: &str) -> rusqlite::Result<Layer> {
    // Draft holds only this run: promote empties it for the reading.
    let mut stmt = tx.prepare(
        "SELECT id, subject, predicate, object FROM assertion
         WHERE layer = ?1 AND reader = ?2 AND scope = ?3 AND kind = ?4",
    )?;
    let mut out = Layer::new();
    let rows = stmt.query_map(params![layer, r.reader, r.scope, r.kind], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    for row in rows {
        let (id, subject, predicate, object): (i64, String, String, String) = row?;
        out.entry((subject, predicate))
            .or_default()
            .entry(object)
            .or_insert(id);
    }
    Ok(out)
}

fn joined(objects: &BTreeMap<String, i64>) -> Option<String> {
    if objects.is_empty() {
        return None;
    }
    Some(objects.keys().cloned().collect::<Vec<_>>().join(", "))
}

/// What a reading held back as it was, not having read it now: subject, predicate and object.
pub type Held = (String, String, String);

/// Compares this run's draft with live and returns the differences as events, and what was
/// held back: all a partial reading did not see, and what `may_go` says a full one does not
/// cover.
/// A different set of objects for the same subject and predicate is one
/// `changed` event, so a new version of a component is not a remove plus an add.
/// Under partial coverage only growth is seen: `added` and `changed`, never `removed`.
pub fn promote(
    tx: &Transaction,
    r: &Reading,
    completeness: &str,
    may_go: &dyn Fn(&str) -> bool,
) -> rusqlite::Result<(Vec<Event>, Vec<Held>)> {
    let mut events = (Vec::new(), Vec::new());
    if completeness != "none" {
        events = compare(tx, r, completeness == "full", may_go)?;
    }
    // What is still draft was already live, repeated within the run, or not read.
    tx.execute(
        "DELETE FROM assertion
         WHERE layer = 'draft' AND reader = ?1 AND scope = ?2 AND kind = ?3",
        params![r.reader, r.scope, r.kind],
    )?;
    Ok(events)
}

fn compare(
    tx: &Transaction,
    r: &Reading,
    full: bool,
    may_go: &dyn Fn(&str) -> bool,
) -> rusqlite::Result<(Vec<Event>, Vec<Held>)> {
    let draft = load(tx, r, "draft")?;
    let live = load(tx, r, "live")?;
    let empty = BTreeMap::new();
    let keys: BTreeSet<_> = draft.keys().chain(live.keys()).cloned().collect();
    let (mut events, mut held) = (Vec::new(), Vec::new());

    for key in keys {
        let old = live.get(&key).unwrap_or(&empty);
        let mut new = draft.get(&key).unwrap_or(&empty).clone();
        if !(full && may_go(&key.0)) {
            // What a partial reading did not see, or a full one does not cover, stays as it was.
            for (object, id) in old {
                if let Entry::Vacant(v) = new.entry(object.clone()) {
                    v.insert(*id);
                    held.push((key.0.clone(), key.1.clone(), object.clone()));
                }
            }
        }
        let new = &new;
        if new.keys().eq(old.keys()) {
            continue;
        }
        for (object, id) in new {
            if !old.contains_key(object) {
                tx.execute("UPDATE assertion SET layer = 'live' WHERE id = ?1", [id])?;
            }
        }
        for (object, id) in old {
            if !new.contains_key(object) {
                tx.execute(
                    "UPDATE assertion SET layer = 'retracted', retracted_at = ?1, retracted_by = ?2
                     WHERE id = ?3",
                    params![r.at, r.run_id, id],
                )?;
            }
        }
        let kind = match (old.is_empty(), new.is_empty()) {
            (true, _) => "added",
            (_, true) => "removed",
            _ => "changed",
        };
        events.push(Event {
            kind,
            subject: key.0,
            predicate: key.1,
            old: joined(old),
            new: joined(new),
        });
    }
    Ok((events, held))
}

/// How the reason of the reading of a retired kind begins; why follows.
pub const NO_LONGER_READ: &str = "no longer read by this version: ";

/// Retires one kind of one reader (see the top of this file) in every scope that holds live
/// facts of it, or whose latest reading of it does not say it is retired yet. `r` gives the
/// reader, the kind, the run and its time; its scope is ignored. Returns the facts closed and
/// the scopes retired, both 0 once it was done.
pub fn retire(tx: &Transaction, r: &Reading, why: &str) -> rusqlite::Result<(usize, usize)> {
    let reason = format!("{NO_LONGER_READ}{why}");
    let scopes: Vec<String> = tx
        .prepare(
            "SELECT scope FROM assertion WHERE layer = 'live' AND reader = ?1 AND kind = ?2
             UNION
             SELECT c.scope FROM coverage c
             WHERE c.reader = ?1 AND c.kind = ?2
               AND c.id = (SELECT MAX(id) FROM coverage
                           WHERE reader = c.reader AND scope = c.scope AND kind = c.kind)
               AND NOT (c.completeness = 'none' AND c.reason IS ?3)
             ORDER BY 1",
        )?
        .query_map(params![r.reader, r.kind, reason], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut closed = 0;
    for scope in &scopes {
        let here = Reading { scope, ..*r };
        for ((subject, predicate), objects) in load(tx, &here, "live")? {
            for id in objects.values() {
                tx.execute(
                    "UPDATE assertion SET layer = 'retracted', retracted_at = ?1, retracted_by = ?2
                     WHERE id = ?3",
                    params![r.at, r.run_id, id],
                )?;
            }
            closed += objects.len();
            tx.execute(
                "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, predicate,
                                      old_value, text)
                 VALUES (?1, ?2, 'retired', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    r.at,
                    r.run_id,
                    r.reader,
                    scope,
                    r.kind,
                    subject,
                    predicate,
                    joined(&objects),
                    reason
                ],
            )?;
        }
        crate::store::put_coverage(tx, &here, "none", Some(&reason), &Gap::of(Cause::NoReader))?;
    }
    Ok((closed, scopes.len()))
}

/// How many facts were set aside as no longer read, each with a journal entry `retired`, since
/// the check before `run_id`: by that check, and by every watcher's reading in between, which
/// prints no line a person reads. Of `reader` alone, or of every reader. The window is the
/// journal after the last `report` entry before the check started, up to the check's own last
/// entry, so it is the same while the check runs and after it. Facts are counted one by one,
/// as `retire` counts them.
pub fn set_aside(
    conn: &rusqlite::Connection,
    run_id: &str,
    reader: Option<&str>,
) -> rusqlite::Result<u64> {
    conn.query_row(
        "SELECT COUNT(*) FROM assertion a
         JOIN (SELECT DISTINCT run_id, reader, scope, kind, subject, predicate FROM journal
               WHERE entry = 'retired' AND (?2 IS NULL OR reader = ?2)
                 AND seq > COALESCE((SELECT seq FROM journal
                                     WHERE entry = 'report'
                                       AND seq < (SELECT MIN(seq) FROM journal WHERE run_id = ?1)
                                     ORDER BY seq DESC LIMIT 1), 0)
                 AND seq <= (SELECT MAX(seq) FROM journal WHERE run_id = ?1)) j
           ON a.subject = j.subject AND a.predicate = j.predicate AND a.reader = j.reader
          AND a.scope = j.scope AND a.kind = j.kind AND a.retracted_by = j.run_id",
        params![run_id, reader],
        |row| row.get::<_, i64>(0),
    )
    .map(|n| n as u64)
}

/// Retracts everything read inside an entity once nothing says where it is any more, and
/// so on down: a file located in a checkout that is gone takes its own readings along. The
/// record of the files a reading inside it opened goes too (`unchanged::forget`): this is the
/// one way the facts of a reading leave with no reading of their own. Returns whether nothing
/// says where it is.
pub(crate) fn retract_inside(
    tx: &Transaction,
    r: &Reading,
    entity: &str,
) -> rusqlite::Result<bool> {
    if placed(tx, entity, None)? {
        return Ok(false);
    }
    let inside: Vec<String> = tx
        .prepare(
            "SELECT DISTINCT subject FROM assertion
             WHERE layer = 'live' AND scope = ?1 AND predicate = 'located_on'",
        )?
        .query_map([entity], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    tx.execute(
        "UPDATE assertion SET layer = 'retracted', retracted_at = ?1, retracted_by = ?2
         WHERE layer = 'live' AND scope = ?3",
        params![r.at, r.run_id, entity],
    )?;
    crate::unchanged::forget(tx, entity)?;
    for thing in inside {
        retract_inside(tx, r, &thing)?;
    }
    Ok(true)
}

/// Whether something live says where `entity` is. With `kind`, only a reading of that kind
/// counts: one of another scope, since the reading that no longer places it retracted its own.
pub(crate) fn placed(tx: &Transaction, entity: &str, kind: Option<&str>) -> rusqlite::Result<bool> {
    tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM assertion
                        WHERE layer = 'live' AND predicate = 'located_on' AND subject = ?1
                          AND (?2 IS NULL OR kind = ?2))",
        params![entity, kind],
        |row| row.get(0),
    )
}

/// Every live placement of `reader`'s readings, as subject and kind: what a run starts from.
pub(crate) fn placements(
    tx: &Transaction,
    reader: &str,
) -> rusqlite::Result<BTreeSet<[String; 2]>> {
    tx.prepare(
        "SELECT DISTINCT subject, kind FROM assertion
         WHERE layer = 'live' AND predicate = 'located_on' AND reader = ?1",
    )?
    .query_map([reader], |row| Ok([row.get(0)?, row.get(1)?]))?
    .collect()
}
