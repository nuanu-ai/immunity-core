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

use crate::store::{Cause, Event, Gap, Reading, Statement};
use rusqlite::{Transaction, params};
use std::cmp::Ordering;
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

fn joined_strs(objects: &BTreeSet<&str>) -> Option<String> {
    if objects.is_empty() {
        return None;
    }
    Some(objects.iter().copied().collect::<Vec<_>>().join(", "))
}

/// What a reading held back as it was, not having read it now: subject, predicate and object.
pub type Held = (String, String, String);

/// Compares this run's incoming statements directly with live without writing unchanged rows to
/// the draft layer, and returns the differences as events plus what was held back: all a partial
/// reading did not see, and what `may_go` says a full one does not cover.
/// A different set of objects for the same subject and predicate is one
/// `changed` event, so a new version of a component is not a remove plus an add.
/// Under partial coverage only growth is seen: `added` and `changed`, never `removed`.
pub fn promote_statements(
    tx: &Transaction,
    r: &Reading,
    completeness: &str,
    statements: &[(&str, &Statement)],
    may_go: &dyn Fn(&str) -> bool,
) -> rusqlite::Result<(Vec<Event>, Vec<Held>)> {
    if completeness == "none" {
        return Ok((Vec::new(), Vec::new()));
    }
    let full = completeness == "full";
    let live = load(tx, r, "live")?;
    type Incoming<'a> = BTreeMap<(&'a str, &'a str), BTreeMap<&'a str, (&'a str, &'a Statement)>>;
    let mut incoming: Incoming<'_> = BTreeMap::new();
    for &(basis, s) in statements {
        incoming
            .entry((s.subject.as_str(), s.predicate))
            .or_default()
            .entry(s.object.as_str())
            .or_insert((basis, s));
    }

    let empty_old = BTreeMap::new();
    let empty_inc = BTreeMap::new();
    let mut insert_entity: Option<rusqlite::Statement<'_>> = None;
    let mut insert_live: Option<rusqlite::Statement<'_>> = None;
    let mut retract: Option<rusqlite::Statement<'_>> = None;
    let (mut events, mut held) = (Vec::new(), Vec::new());

    let mut live_it = live.iter().peekable();
    let mut inc_it = incoming.iter().peekable();
    while live_it.peek().is_some() || inc_it.peek().is_some() {
        let ord = match (live_it.peek(), inc_it.peek()) {
            (Some(((ls, lp), _)), Some(((is, ip), _))) => {
                (ls.as_str(), lp.as_str()).cmp(&(*is, *ip))
            }
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => break,
        };
        let (subject, predicate, old, inc) = match ord {
            Ordering::Equal => {
                let (_, old) = live_it.next().unwrap();
                let (&(s, p), inc) = inc_it.next().unwrap();
                (s, p, old, inc)
            }
            Ordering::Less => {
                let ((s, p), old) = live_it.next().unwrap();
                (s.as_str(), p.as_str(), old, &empty_inc)
            }
            Ordering::Greater => {
                let (&(s, p), inc) = inc_it.next().unwrap();
                (s, p, &empty_old, inc)
            }
        };
        if old.len() == inc.len() && old.keys().map(String::as_str).eq(inc.keys().copied()) {
            continue;
        }
        let mut new_objs: BTreeSet<&str> = inc.keys().copied().collect();
        if !(full && may_go(subject)) {
            // What a partial reading did not see, or a full one does not cover, stays as it was.
            for object in old.keys() {
                if new_objs.insert(object.as_str()) {
                    held.push((subject.to_string(), predicate.to_string(), object.clone()));
                }
            }
        }
        if new_objs.len() == old.len()
            && new_objs.iter().copied().eq(old.keys().map(String::as_str))
        {
            continue;
        }
        for &object in &new_objs {
            if !old.contains_key(object) {
                let (basis, s) = inc[object];
                let entity_stmt = match &mut insert_entity {
                    Some(stmt) => stmt,
                    None => insert_entity.insert(
                        tx.prepare("INSERT OR IGNORE INTO entity (id, type) VALUES (?1, ?2)")?,
                    ),
                };
                let subj_type = s.subject.split(':').next().unwrap_or(&s.subject);
                entity_stmt.execute(params![s.subject, subj_type])?;
                if crate::store::predicate_is_entity(tx, s.predicate)? {
                    let obj_type = s.object.split(':').next().unwrap_or(&s.object);
                    entity_stmt.execute(params![s.object, obj_type])?;
                }
                let live_stmt = match &mut insert_live {
                    Some(stmt) => stmt,
                    None => insert_live.insert(tx.prepare(
                        "INSERT INTO assertion (layer, subject, predicate, object, reader, scope,
                                                kind, source_ref, basis, observed_at, run_id)
                         VALUES ('live', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    )?),
                };
                live_stmt.execute(params![
                    s.subject,
                    s.predicate,
                    s.object,
                    r.reader,
                    r.scope,
                    r.kind,
                    s.source_ref,
                    basis,
                    r.observed_at,
                    r.run_id
                ])?;
            }
        }
        for (object, id) in old {
            if !new_objs.contains(object.as_str()) {
                let retract_stmt = match &mut retract {
                    Some(stmt) => stmt,
                    None => retract.insert(tx.prepare(
                        "UPDATE assertion SET layer = 'retracted', retracted_at = ?1,
                                              retracted_by = ?2
                         WHERE id = ?3",
                    )?),
                };
                retract_stmt.execute(params![r.at, r.run_id, id])?;
            }
        }
        let kind = match (old.is_empty(), new_objs.is_empty()) {
            (true, _) => "added",
            (_, true) => "removed",
            _ => "changed",
        };
        events.push(Event {
            kind,
            subject: subject.to_string(),
            predicate: predicate.to_string(),
            old: joined(old),
            new: joined_strs(&new_objs),
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
/// so on down: a file located in a checkout that is gone takes its own readings along.
/// Returns whether nothing says where it is.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;

    fn stmt(subject: &str, predicate: &'static str, object: &str) -> Statement {
        Statement {
            subject: subject.to_string(),
            predicate,
            object: object.to_string(),
            source_ref: "test:1".to_string(),
        }
    }

    #[test]
    fn unchanged_statements_write_no_rows_and_partial_or_excluded_subjects_are_held_back() {
        let dir = crate::common::Scratch::new("lifecycle-promote");
        let mut conn = store::open_or_make(&dir.0.join("store.db")).unwrap();
        let r1 = Reading {
            reader: "test",
            scope: "machine:m",
            kind: crate::integrity::KEGS,
            run_id: "r1",
            at: 100,
            observed_at: 100,
        };
        let a = stmt("file:m/a", "has_content", "sha256:1");
        let b = stmt("file:m/b", "has_content", "sha256:2");
        let dup_a = Statement {
            source_ref: "test:99".to_string(),
            ..stmt("file:m/a", "has_content", "sha256:1")
        };
        let tx = conn.transaction().unwrap();
        store::put_entity(&tx, "machine:m").unwrap();
        let (events, held) = promote_statements(
            &tx,
            &r1,
            "full",
            &[("observed", &a), ("observed", &dup_a), ("observed", &b)],
            &|_| true,
        )
        .unwrap();
        assert_eq!(events.len(), 2);
        assert!(held.is_empty());
        let max_id: i64 = tx
            .query_row("SELECT MAX(id) FROM assertion", [], |r| r.get(0))
            .unwrap();
        let drafts: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM assertion WHERE layer = 'draft'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(drafts, 0);

        // Re-promoting identical statements inserts no assertion rows at all.
        let r2 = Reading {
            run_id: "r2",
            at: 200,
            observed_at: 200,
            ..r1
        };
        let (events, held) = promote_statements(
            &tx,
            &r2,
            "full",
            &[("observed", &a), ("observed", &b)],
            &|_| true,
        )
        .unwrap();
        assert!(events.is_empty());
        assert!(held.is_empty());
        let max_id_after: i64 = tx
            .query_row("SELECT MAX(id) FROM assertion", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_id_after, max_id);

        // Partial reading holds back missing `b` without retracting it.
        let (events, held) =
            promote_statements(&tx, &r2, "partial", &[("observed", &a)], &|_| true).unwrap();
        assert!(events.is_empty());
        assert_eq!(
            held,
            vec![(
                "file:m/b".to_string(),
                "has_content".to_string(),
                "sha256:2".to_string()
            )]
        );

        // Full reading where `may_go` excludes `b` holds back `b`, while retracting `a`.
        let (events, held) =
            promote_statements(&tx, &r2, "full", &[], &|s| s != "file:m/b").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            (events[0].kind, events[0].subject.as_str()),
            ("removed", "file:m/a")
        );
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].0, "file:m/b");
        tx.commit().unwrap();
    }
}
