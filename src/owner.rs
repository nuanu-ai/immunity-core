//! The owner's word: the owner says that a machine is retired or not theirs. A statement is
//! kept next to the facts and never edits them: readers go on writing what they see.
//!
//! A statement names one entity, and covers the machine as the resolver groups it. While it
//! stands, the machine is not offered for the sweep and is not counted among the servers.
//! It never hides a machine seen alive after it: anything a reader other than the resolver
//! learned about the machine later than the statement contradicts it, and the machine is
//! counted and shown again. Only a withdrawal or a later statement clears that.

use crate::findings::Via;
use crate::{resolver, store};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub const RETIRED: &str = "retired";
pub const NOT_MINE: &str = "not mine";

/// One statement as it was made.
pub struct Word {
    pub entity: String,
    pub said: String,
    /// Cut, as `secrets::Kept::OwnerReason` keeps it.
    pub reason: crate::secrets::Text,
    pub made_at: i64,
    /// How it was given; `Unknown` for a value this build does not know.
    pub via: Via,
}

/// Something read about the machine after the statement.
pub struct Evidence {
    pub at: i64,
    pub what: String,
}

/// A statement that stands, with the machine it covers.
pub struct Standing {
    pub word: Word,
    /// The entities the resolver found to be the machine the statement names.
    pub machine: Vec<String>,
    /// Every name and address the store knows the machine by, the statement's own first.
    pub names: Vec<String>,
    /// Something seen alive after the statement, if anything was.
    pub seen: Option<Evidence>,
}

impl Standing {
    pub fn covers(&self, id: &str) -> bool {
        self.machine.iter().any(|m| m == id)
    }

    /// The name the statement was made under.
    pub fn name(&self) -> &str {
        bare(&self.word.entity)
    }

    /// `retired by the owner on <date>: <reason>`.
    pub fn summary(&self) -> String {
        format!(
            "{} by the owner on {}: {}",
            self.word.said,
            crate::view::utc(self.word.made_at),
            self.word.reason.said()
        )
    }

    /// `<date>, <what was seen>`, when the statement is contradicted.
    pub fn contradiction(&self) -> Option<String> {
        self.seen
            .as_ref()
            .map(|e| format!("{}, {}", crate::view::utc(e.at), e.what))
    }
}

pub fn bare(id: &str) -> &str {
    id.strip_prefix("machine:").unwrap_or(id)
}

/// The statements that stand.
pub fn standing(conn: &Connection) -> rusqlite::Result<Vec<Standing>> {
    let words: Vec<Word> = conn
        .prepare(
            "SELECT entity, said, reason, made_at, via FROM owner_statement
             WHERE withdrawn_at IS NULL",
        )?
        .query_map([], |r| {
            Ok(Word {
                entity: r.get(0)?,
                said: r.get(1)?,
                reason: crate::secrets::Kept::OwnerReason.read(&r.get::<_, String>(2)?),
                made_at: r.get(3)?,
                via: Via::stored(r.get::<_, Option<String>>(4)?.as_deref()),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    // Without a word in force there is nothing to place on a machine, and finding the
    // machines reads every live assertion.
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let groups = store::machine_groups(conn)?;
    let known_as = store::live_known_as(conn)?;
    let mut out: Vec<Standing> = Vec::new();
    for word in words {
        let machine = groups
            .iter()
            .find(|g| g.contains(&word.entity))
            .cloned()
            .unwrap_or_else(|| vec![word.entity.clone()]);
        let mut names = vec![bare(&word.entity).to_string()];
        let others = machine.iter().map(|m| bare(m).to_string()).chain(
            known_as
                .iter()
                .filter(|k| machine.contains(&k.entity))
                .map(|k| k.value.clone()),
        );
        for name in others {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        names[1..].sort();
        let seen = evidence(conn, &machine, word.made_at)?;
        out.push(Standing {
            word,
            machine,
            names,
            seen,
        });
    }
    out.sort_by(|a, b| a.name().cmp(b.name()));
    Ok(out)
}

/// Something a reader other than the resolver learned about the machine after the time: a
/// reading of it that read something, or an assertion first made then, whether it is still
/// made or was retracted since. A link the resolver makes later is not a sign of life, and
/// its readings are never of a server.
fn evidence(
    conn: &Connection,
    machine: &[String],
    after: i64,
) -> rusqlite::Result<Option<Evidence>> {
    for m in machine {
        let reading = conn
            .query_row(
                "SELECT observed_at, reader, kind FROM coverage
                 WHERE scope = ?1 AND completeness != 'none' AND observed_at > ?2
                 ORDER BY observed_at DESC, id DESC LIMIT 1",
                params![m, after],
                |r| {
                    Ok(Evidence {
                        at: r.get(0)?,
                        what: format!(
                            "{} read {} on {}",
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            bare(m)
                        ),
                    })
                },
            )
            .optional()?;
        if reading.is_some() {
            return Ok(reading);
        }
        let assertion = conn
            .query_row(
                "SELECT observed_at, reader, subject, predicate, object FROM assertion
                 WHERE reader != ?2 AND (subject = ?1 OR scope = ?1)
                   AND observed_at > ?3
                 ORDER BY observed_at DESC, id DESC LIMIT 1",
                params![m, resolver::READER, after],
                |r| {
                    Ok(Evidence {
                        at: r.get(0)?,
                        what: format!(
                            "{} saw {} {} {}",
                            r.get::<_, String>(1)?,
                            bare(&r.get::<_, String>(2)?),
                            r.get::<_, String>(3)?,
                            bare(&r.get::<_, String>(4)?)
                        ),
                    })
                },
            )
            .optional()?;
        if assertion.is_some() {
            return Ok(assertion);
        }
    }
    Ok(None)
}

/// What a name given by the owner fits.
pub enum Found {
    /// One machine: the entity the statement names, and the machine as grouped.
    One(String, Vec<String>),
    Unknown,
    /// Several machines that are not known to be one.
    Several(Vec<Vec<String>>),
}

/// The machine a name or address fits, or a full entity id. Names compare the way the
/// resolver compares them. Nothing is guessed: a name that fits several machines is not one.
pub fn find(conn: &Connection, name: &str) -> rusqlite::Result<Found> {
    let mut groups = store::machine_groups(conn)?;
    // A machine no trace names any more can still have a statement to withdraw.
    for s in standing(conn)? {
        if !groups.iter().any(|g| g.contains(&s.word.entity)) {
            groups.push(s.machine);
        }
    }
    if let Some(g) = groups.iter().find(|g| g.iter().any(|m| m == name)) {
        return Ok(Found::One(name.to_string(), g.clone()));
    }
    let norm = |v: &str| resolver::key(v).unwrap_or_else(|| v.trim().to_string());
    // A machine's id is compared as its bare name is, so `machine:<name>` fits as `<name>` does.
    let wanted = norm(bare(name));
    let mut hits: Vec<String> = Vec::new();
    for m in groups.iter().flatten() {
        if norm(bare(m)) == wanted {
            hits.push(m.clone());
        }
    }
    for k in store::live_known_as(conn)? {
        if norm(&k.value) == wanted && !hits.contains(&k.entity) {
            hits.push(k.entity);
        }
    }
    let fits: Vec<&Vec<String>> = groups
        .iter()
        .filter(|g| g.iter().any(|m| hits.contains(m)))
        .collect();
    Ok(match fits.as_slice() {
        [] => Found::Unknown,
        [machine] => {
            let named = hits.iter().find(|h| machine.contains(h)).unwrap();
            Found::One(named.clone(), machine.to_vec())
        }
        several => Found::Several(several.iter().map(|g| g.to_vec()).collect()),
    })
}

/// Withdraws every statement that stands about the machine, journals each with how it was
/// withdrawn, and returns what each said and about which entity. They are kept, with the
/// time of withdrawal.
fn withdraw_in(
    tx: &Transaction,
    machine: &[String],
    at: i64,
    run_id: &str,
    how: &str,
    via: Via,
) -> rusqlite::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for m in machine {
        let said: Vec<(i64, String)> = tx
            .prepare(
                "SELECT id, said FROM owner_statement WHERE entity = ?1 AND withdrawn_at IS NULL",
            )?
            .query_map([m], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, said) in said {
            tx.execute(
                "UPDATE owner_statement SET withdrawn_at = ?1 WHERE id = ?2",
                params![at, id],
            )?;
            store::journal_owner(
                tx,
                at,
                run_id,
                "owner_withdrew",
                m,
                &said,
                how,
                via.literal(),
            )?;
            out.push((m.clone(), said));
        }
    }
    Ok(out)
}

/// Makes a statement about the entity. One that stood about the same machine is withdrawn
/// in the same transaction: a machine has one standing statement. The reason is taken whatever
/// it holds and kept cut, in its row and its journal entry (`secrets::Kept::OwnerReason`);
/// returned with how many statements it replaced, as it is kept.
#[allow(clippy::too_many_arguments)]
pub fn say(
    tx: &Transaction,
    entity: &str,
    machine: &[String],
    said: &str,
    reason: &str,
    via: Via,
    at: i64,
    run_id: &str,
) -> rusqlite::Result<(usize, crate::secrets::Text)> {
    let kept = crate::secrets::Text::source(reason);
    let reason = kept.store();
    let reason = reason.as_str();
    let replaced = withdraw_in(
        tx,
        machine,
        at,
        run_id,
        "replaced by a later statement",
        via,
    )?
    .len();
    tx.execute(
        "INSERT INTO owner_statement (entity, said, reason, made_at, via)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![entity, said, reason, at, via.literal()],
    )?;
    store::journal_owner(
        tx,
        at,
        run_id,
        "owner_said",
        entity,
        said,
        reason,
        via.literal(),
    )?;
    Ok((replaced, kept))
}

/// Withdraws what stands about the machine. Returns what was withdrawn: entity and what was
/// said about it.
pub fn withdraw(
    tx: &Transaction,
    machine: &[String],
    via: Via,
    at: i64,
    run_id: &str,
) -> rusqlite::Result<Vec<(String, String)>> {
    withdraw_in(tx, machine, at, run_id, "withdrawn by the owner", via)
}

/// How many statements were withdrawn and are kept.
pub fn withdrawn(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM owner_statement WHERE withdrawn_at IS NOT NULL",
        [],
        |r| r.get(0),
    )
}

/// A statement that stands, as the contract gives it. The machine's names are the owner's or a
/// source's text, so they are only in `_text` fields, whole.
pub fn statement(s: &Standing) -> crate::contract::v1::Statement {
    use crate::contract::{v1, value_of};
    use crate::known::whole;
    v1::Statement {
        machine_text: whole(s.name()),
        entity_text: whole(&s.word.entity),
        said: s.word.said.clone(),
        via: value_of::<v1::Via>(s.word.via.literal()),
        at: s.word.made_at,
        reason_text: s.word.reason.said(),
        reason_cuts: crate::answer::reason_cuts(&s.word.reason),
        names_text: s.names.iter().skip(1).map(|n| whole(n)).collect(),
        seen_after: s.seen.as_ref().map(|e| v1::SeenAfter {
            at: e.at,
            what_text: whole(&e.what),
        }),
    }
}

/// The answer of `immunity owner` without a statement: the statements that stand, and the machines
/// beyond this Mac a statement can be made about, told apart once, here (`beyond::split`). The
/// pages are drawn from it too.
pub fn statements(
    conn: &Connection,
    now: i64,
) -> rusqlite::Result<crate::contract::v1::Statements> {
    use crate::contract::v1;
    use crate::known::whole;
    let this = crate::covered::this_machine(conn)?.unwrap_or_default();
    let split = crate::beyond::split(conn, &this)?;
    let known_as = store::live_known_as(conn)?;
    let visited: Vec<String> = conn
        .prepare("SELECT DISTINCT scope FROM coverage WHERE reader = ?1 AND kind = ?2")?
        .query_map([crate::servers::READER, crate::servers::VISIT], |r| {
            r.get(0)
        })?
        .collect::<rusqlite::Result<_>>()?;
    // The readings that name each machine, by the kind of what they say of it.
    let named_by: Vec<(String, String)> = conn
        .prepare("SELECT DISTINCT subject, kind FROM assertion WHERE layer = 'live' AND predicate = 'known_as'")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let kinds = [
        (v1::MachineKind::Server, &split.servers),
        (v1::MachineKind::OwnDevice, &split.own_devices),
        (v1::MachineKind::OtherDevice, &split.other_devices),
    ];
    let mut machines: Vec<v1::KnownMachine> = Vec::new();
    for (kind, groups) in kinds {
        let first = machines.len();
        for (i, group) in groups.iter().enumerate() {
            let shown = (group.iter().find(|m| visited.contains(m)))
                .or(group.first())
                .map_or("", |m| bare(m));
            let known: Vec<&str> = (known_as.iter())
                .filter(|k| group.contains(&k.entity))
                .map(|k| k.value.as_str())
                .collect();
            let mut names: Vec<&str> = group.iter().map(|m| bare(m)).chain(known).collect();
            names.sort();
            names.dedup();
            let known_from: std::collections::BTreeSet<&String> = (named_by.iter())
                .filter(|(m, _)| group.contains(m))
                .map(|(_, k)| k)
                .collect();
            machines.push(v1::KnownMachine {
                machine_text: whole(shown),
                entities_text: group.iter().map(|m| whole(m)).collect(),
                names_text: (names.iter())
                    .filter(|n| **n != shown)
                    .map(|n| whole(n))
                    .collect(),
                kind: kind as i32,
                system_text: group
                    .iter()
                    .find_map(|m| split.platform.get(m))
                    .map(|p| whole(p)),
                system_not_given: kind == v1::MachineKind::Server
                    && split.system_not_given.contains(&i),
                known_from: known_from.into_iter().cloned().collect(),
            });
        }
        machines[first..].sort_by(|a, b| a.machine_text.cmp(&b.machine_text));
    }
    // What the list rests on: the readings on this Mac that find machines, each taken in full by
    // the latest run that finished, or it may not be whole.
    let latest_run = crate::status::latest_finished(conn)?.map(|r| r.started_at);
    let mut machines_not_read = Vec::new();
    let mut taken = Vec::new();
    for r in crate::known::latest(conn)? {
        let key = (r.reader.clone(), r.kind.clone());
        let finds = crate::machine::FOUND_BY.contains(&(key.0.as_str(), key.1.as_str()));
        // A reading under a former id of this Mac neither stands for this Mac's nor is its gap.
        if !finds || r.scope != this {
            continue;
        }
        taken.push(key);
        if r.completeness != "full" || !crate::look::fresh(r.at, latest_run, now) {
            machines_not_read.push(crate::known::coverage(conn, r)?);
        }
    }
    for (reader, kind) in crate::machine::FOUND_BY {
        if !taken.contains(&(reader.to_string(), kind.to_string())) {
            machines_not_read.push(v1::Coverage {
                reader: reader.to_string(),
                kind: kind.to_string(),
                scope_text: whole(&this),
                completeness: v1::Completeness::None as i32,
                ..Default::default()
            });
        }
    }
    Ok(v1::Statements {
        format: 1,
        answered_at: now,
        store_id: Some(store::id(conn)?),
        statements: standing(conn)?.iter().map(statement).collect(),
        withdrawn: withdrawn(conn)?.max(0) as u64,
        machines,
        machines_not_read,
    })
}

/// `statements_outside_app` of the contract's `Status`: the statements that stand and are known
/// to have been made outside the app, the latest first, at most `shown`, with their total.
pub fn outside_app(
    standing: &[Standing],
    shown: usize,
) -> crate::contract::v1::StatementsOutsideApp {
    let mut outside: Vec<&Standing> = standing
        .iter()
        .filter(|s| s.word.via.outside_app())
        .collect();
    outside.sort_by(|a, b| {
        b.word
            .made_at
            .cmp(&a.word.made_at)
            .then_with(|| a.name().cmp(b.name()))
    });
    crate::contract::v1::StatementsOutsideApp {
        total: outside.len() as u64,
        items: outside.iter().take(shown).map(|s| statement(s)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::v1;
    use crate::store::{Gap, Reading, journal_note, put_coverage};

    #[test]
    fn the_list_of_machines_names_each_reading_that_finds_them_and_was_not_read_in_full_by_the_latest_run()
     {
        // "None known" rests on the readings that find machines: one not full, one older than
        // the latest run and one never taken each keep the list from being called whole.
        let scratch = crate::common::Scratch::new("owner-not-read");
        let mut conn = crate::store::open_or_make(&scratch.0.join("store.db")).unwrap();
        let (at, run_id) = (1_900_000_000, "1900000000-000000000");
        let tx = conn.transaction().unwrap();
        tx.execute_batch(
            "INSERT INTO meta (key, value) VALUES ('machine', 'machine:mac'), ('machine_name', 'mac')",
        )
        .unwrap();
        crate::store::put_entity(&tx, "machine:mac").unwrap();
        journal_note(&tx, at, run_id, "run_started", "").unwrap();
        let read = |reader, kind, observed_at, completeness, reason| {
            let r = Reading {
                reader,
                scope: "machine:mac",
                kind,
                run_id,
                at,
                observed_at,
            };
            let gap = match completeness {
                "full" => Gap::default(),
                _ => Gap::of(crate::store::Cause::Failed),
            };
            put_coverage(&tx, &r, completeness, reason, &gap).unwrap();
        };
        use crate::{known_hosts, ssh_config, tailnet};
        read(ssh_config::READER, ssh_config::KIND, at - 50, "full", None);
        read(ssh_config::READER, ssh_config::KIND, at, "full", None);
        read(
            known_hosts::READER,
            known_hosts::KIND,
            at - 100,
            "full",
            None,
        );
        journal_note(&tx, at + 1, run_id, "run_finished", "").unwrap();
        tx.commit().unwrap();
        let not_read = |conn: &rusqlite::Connection| {
            let m = super::statements(conn, at + 60).unwrap();
            (m.machines_not_read.iter())
                .map(|c| {
                    (
                        c.reader.clone(),
                        c.completeness,
                        c.observed_at,
                        c.last_full_at,
                    )
                })
                .collect::<Vec<_>>()
        };
        let none = v1::Completeness::None as i32;
        assert_eq!(
            not_read(&conn),
            [
                (
                    known_hosts::READER.to_string(),
                    v1::Completeness::Full as i32,
                    Some(at - 100),
                    Some(at - 100)
                ),
                (tailnet::READER.to_string(), none, None, None),
            ]
        );
        // A reading that failed after a full one says when that one was.
        let tx = conn.transaction().unwrap();
        journal_note(&tx, at + 2, "1900000002-000000000", "run_started", "").unwrap();
        let r = Reading {
            reader: ssh_config::READER,
            scope: "machine:mac",
            kind: ssh_config::KIND,
            run_id: "1900000002-000000000",
            at: at + 2,
            observed_at: at + 2,
        };
        put_coverage(
            &tx,
            &r,
            "none",
            Some("refused"),
            &Gap::of(crate::store::Cause::Failed),
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(
            not_read(&conn).contains(&(
                ssh_config::READER.to_string(),
                none,
                Some(at + 2),
                Some(at)
            )),
            "{:?}",
            not_read(&conn)
        );
    }

    #[test]
    fn a_full_reading_under_another_machines_id_neither_stands_for_this_macs_missing_one_nor_is_named_as_its_gap()
     {
        // A Mac whose name changed keeps readings under its former id: they say nothing of
        // whether this Mac's list of machines is whole.
        let scratch = crate::common::Scratch::new("owner-former-id");
        let mut conn = crate::store::open_or_make(&scratch.0.join("store.db")).unwrap();
        let (at, run_id) = (1_900_000_000, "1900000000-000000000");
        let tx = conn.transaction().unwrap();
        tx.execute_batch(
            "INSERT INTO meta (key, value) VALUES ('machine', 'machine:mac'), ('machine_name', 'mac')",
        )
        .unwrap();
        journal_note(&tx, at, run_id, "run_started", "").unwrap();
        use crate::{known_hosts, ssh_config, tailnet};
        for (reader, kind, scope, completeness) in [
            (ssh_config::READER, ssh_config::KIND, "machine:mac", "full"),
            (
                known_hosts::READER,
                known_hosts::KIND,
                "machine:mac",
                "full",
            ),
            (tailnet::READER, tailnet::KIND, "machine:old-mac", "full"),
            (
                known_hosts::READER,
                known_hosts::KIND,
                "machine:old-mac",
                "none",
            ),
        ] {
            crate::store::put_entity(&tx, scope).unwrap();
            let r = Reading {
                reader,
                scope,
                kind,
                run_id,
                at,
                observed_at: at,
            };
            let gap = match completeness {
                "full" => Gap::default(),
                _ => Gap::of(crate::store::Cause::Failed),
            };
            put_coverage(
                &tx,
                &r,
                completeness,
                (completeness != "full").then_some("refused"),
                &gap,
            )
            .unwrap();
        }
        journal_note(&tx, at + 1, run_id, "run_finished", "").unwrap();
        tx.commit().unwrap();
        let m = super::statements(&conn, at + 60).unwrap();
        let not_read: Vec<(&str, &str, Option<i64>)> = (m.machines_not_read.iter())
            .map(|c| (c.reader.as_str(), c.scope_text.as_str(), c.observed_at))
            .collect();
        assert_eq!(not_read, [(tailnet::READER, "machine:mac", None)]);
    }
}
