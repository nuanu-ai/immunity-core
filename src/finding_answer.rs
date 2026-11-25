//! `immunity findings` and `immunity finding <id>` as commands of the contract: the core's own
//! findings as the messages `Findings` and `Finding` (`contract/immunity/v1/findings.proto`). The
//! response layer reads a finding whole to give a verdict about it.
//!
//! It reads the store and nothing else, through the same `findings::all` and `findings::item`
//! that the status, the pages and the person's form of these commands read, so the words, the
//! state and the order are theirs. What a finding rests on is given as the store holds it: the
//! journal entries it rests on, and by its kind the evidence the core keeps beside them. Text
//! from the Mac or a source goes through `known::whole`, whole and escaped one to one.

use crate::contract::{v1, value_of};
use crate::events::{self, Evidence, FileEvent, ProcessStart};
use crate::findings::{self, Found, Item};
use crate::known::{self, Refused, whole};
use crate::secrets::Args;
use crate::{matches, sigma, status, store, verdict, vulnerabilities};
use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};

/// The version of the contract this build prints.
const FORMAT: u32 = 1;

/// Every finding the store holds, in every state, the most severe first.
pub fn list(conn: &Connection, now: i64) -> rusqlite::Result<v1::Findings> {
    let found = findings::all(conn, now)?;
    let mut items: Vec<Item> = found.iter().map(findings::item).collect();
    findings::order(&mut items);
    let store_id = Some(store::id(conn)?);
    let refs = refs(&items);
    let packages = packages(conn)?;
    Ok(v1::Findings {
        format: FORMAT,
        answered_at: now,
        latest_run_at: status::latest_finished(conn)?.and_then(|r| r.finished_at),
        findings: items
            .iter()
            .map(|i| listed(i, store_id.as_deref(), &refs, &packages))
            .collect(),
        store_id,
        answers_note: findings::ANSWERS_NOTE.to_string(),
        // Read in the same transaction as the findings, so it is of the state they show.
        journal_seq: findings::journal_seq(conn)?,
    })
}

/// One finding whole; a refusal when the store has no finding with this id. After an answer
/// given with `--with`, `with` are the other findings named, each as it stands now, in the order
/// given, and the other of the pair is `answered_with` too. Each of them was found by the
/// answer's own check (`findings::together`) in the same transaction, so each is read back.
pub fn one(
    conn: &Connection,
    id: &str,
    with: &[&str],
    pair: bool,
    now: i64,
) -> rusqlite::Result<Result<v1::Finding, Refused>> {
    let found = findings::all(conn, now)?;
    let mut one = of(conn, &found, id, now)?;
    if let Some(f) = one.as_mut() {
        let items: Vec<Item> = found.iter().map(findings::item).collect();
        let refs = refs(&items);
        f.answered_together = with.iter().filter_map(|w| refs.get(*w).cloned()).collect();
        f.answered_with = f.answered_together.first().cloned().filter(|_| pair);
    }
    Ok(one.ok_or(Refused {
        code: "unknown_finding",
        message: "the store has no finding with this id",
        example: "immunity findings --all lists every finding with its id; with --json, every one in every state",
        ids: Vec::new(),
    }))
}

/// One finding whole, as `one` gives it, out of every finding already read: the page of what
/// needs a look shows each finding's evidence by this same path. `None` when `found` has no
/// finding with this id.
pub fn of(
    conn: &Connection,
    found: &[Found],
    id: &str,
    now: i64,
) -> rusqlite::Result<Option<v1::Finding>> {
    let Some(f) = found.iter().find(|f| f.id == id) else {
        return Ok(None);
    };
    let i = findings::item(f);
    let rests_on = findings::basis(conn, id)?
        .into_iter()
        .map(|b| v1::JournalEntry {
            seq: b.seq,
            recorded_at: b.at,
            run_id: b.run_id,
            entry: b.entry,
            reader: b.reader,
            kind: b.kind,
            predicate: b.predicate,
            subject_text: b.subject.as_deref().map(whole),
            old_value_text: b.old_value.as_deref().map(whole),
            new_value_text: b.new_value.as_deref().map(whole),
        })
        .collect();
    let store_id = Some(store::id(conn)?);
    let items: Vec<Item> = found.iter().map(findings::item).collect();
    let refs = refs(&items);
    let verdicts = verdict::verdicts(
        verdict::of_finding(conn, id, &f.rule)?,
        store_id.as_deref(),
        &refs,
        i.verdicts.as_ref().and_then(|s| s.standing.as_ref()),
    );
    Ok(Some(v1::Finding {
        format: FORMAT,
        answered_at: now,
        store_id,
        verdicts,
        // Named by `one` after an answer given with `--with`; a read names none.
        answered_with: None,
        answered_together: Vec::new(),
        group: findings::group_key(&i),
        folder_text: findings::group_folder(&i).as_deref().map(whole),
        journal_seq: findings::journal_seq(conn)?,
        finding: Some(known::finding_ref(&i)),
        kind: i.kind.to_string(),
        title: i.words.title.to_string(),
        meaning: i.words.meaning.to_string(),
        advice: i.words.advice.to_string(),
        technique_text: i.technique.map(whole),
        where_text: whole(&f.place),
        first_seen_at: f.first_seen.0,
        last_seen_at: f.last_seen.0,
        answer: i.answer.as_ref().map(answer),
        evidence: evidence(conn, f)?.map(|body| v1::Evidence { body: Some(body) }),
        rests_on,
        answers_note: findings::ANSWERS_NOTE.to_string(),
        thing: i.thing.clone(),
        kind_title: findings::kind_title(i.kind).to_string(),
        short_title: i.words.short.to_string(),
    }))
}

/// Every finding by id, as an answer names one.
pub fn refs(items: &[Item]) -> BTreeMap<String, v1::FindingRef> {
    items
        .iter()
        .map(|i| (i.id.clone(), known::finding_ref(i)))
        .collect()
}

/// Every "affects me" answer, and what each finding about a package kept when it was cleared or
/// its package left, read once for a whole list.
pub struct Packages(
    Vec<vulnerabilities::Affecting>,
    BTreeMap<String, vulnerabilities::Kept>,
);

pub fn packages(conn: &Connection) -> rusqlite::Result<Packages> {
    Ok(Packages(
        vulnerabilities::affecting(conn)?,
        vulnerabilities::kept(conn)?,
    ))
}

impl Packages {
    /// The package a finding about the component `about` is about: its name and the releases
    /// of that component a record affects, as `package` gives them for one finding, each once.
    pub fn of(&self, about: &str) -> Option<(String, BTreeSet<String>)> {
        Self::in_list(&self.0, about)
    }

    /// The same for the finding `i`, from what it kept when it has kept something.
    fn of_finding(&self, i: &Item) -> Option<(String, BTreeSet<String>)> {
        match self.1.get(&i.id) {
            Some(k) => Self::in_list(&k.was, &i.about),
            None => self.of(&i.about),
        }
    }

    fn in_list(
        list: &[vulnerabilities::Affecting],
        about: &str,
    ) -> Option<(String, BTreeSet<String>)> {
        let mine: Vec<&vulnerabilities::Affecting> =
            list.iter().filter(|a| a.is_about(about)).collect();
        let releases = mine.iter().flat_map(|a| a.affected_of(about));
        let releases = releases.map(|(version, _)| version).collect();
        mine.first().map(|a| (a.package.clone(), releases))
    }
}

/// A published rule's own title, whole, for a finding of one; `None` for any other.
pub fn rule_title(rule: &str) -> Option<String> {
    findings::published(rule)
        .and_then(|l| l.meta.as_ref())
        .map(|m| whole(&m.title))
}

pub fn listed(
    i: &Item,
    store_id: Option<&str>,
    refs: &BTreeMap<String, v1::FindingRef>,
    packages: &Packages,
) -> v1::ListedFinding {
    let package = packages.of_finding(i);
    v1::ListedFinding {
        short_title: i.words.short.to_string(),
        rule_title_text: rule_title(&i.rule),
        package_text: package.as_ref().map(|(name, _)| whole(name)),
        releases_text: package
            .map(|(_, releases)| releases.iter().map(|r| whole(r)).collect())
            .unwrap_or_default(),
        // Counted, with only the verdict that raised a `verdict.suspicious` finding listed.
        verdicts: i.verdicts.as_ref().and_then(|s| {
            let opening = s.opening.iter().cloned().collect();
            verdict::verdicts(
                (s.total, s.suspicious, opening),
                store_id,
                refs,
                s.standing.as_ref(),
            )
        }),
        finding: Some(known::finding_ref(i)),
        group: findings::group_key(i),
        folder_text: findings::group_folder(i).as_deref().map(whole),
        change: place_change(&i.rule, i.change.as_deref()),
        kind: i.kind.to_string(),
        title: i.words.title.to_string(),
        where_text: whole(i.place.as_deref().unwrap_or_default()),
        // A finding's item always has both.
        first_seen_at: i.first_seen.unwrap_or_default(),
        last_seen_at: i.last_seen.unwrap_or_default(),
        answer: i.answer.as_ref().map(answer),
        thing: i.thing.clone(),
        kind_title: findings::kind_title(i.kind).to_string(),
    }
}

fn answer(a: &findings::Answered) -> v1::Answer {
    v1::Answer {
        given: value_of::<v1::AnswerKind>(a.given),
        via: value_of::<v1::Via>(a.via.literal()),
        given_at: a.at,
        reason_text: a.reason.as_ref().map(crate::secrets::Text::said),
        reason_cuts: a
            .reason
            .as_ref()
            .map(crate::answer::reason_cuts)
            .unwrap_or_default(),
        until_at: a.until,
        in_force: a.in_force,
    }
}

/// What a finding rests on, by the kind of its rule; `None` for a kind this build does not
/// shape.
pub fn evidence(conn: &Connection, f: &Found) -> rusqlite::Result<Option<v1::evidence::Body>> {
    use v1::evidence::Body;
    if let Some(l) = findings::published(&f.rule) {
        let (Some(meta), Some(kind)) = (&l.meta, l.kind) else {
            return Ok(None);
        };
        return Ok(Some(Body::PublishedRuleMatched(v1::PublishedRuleMatched {
            rule: Some(matches::rule(l.file, meta)),
            matches: rule_count(conn, &f.id)?,
            events: events::raised_first(rule_events(conn, &f.id, kind)?),
            source: meta.source.url.to_string(),
            licence: meta.source.licence.to_string(),
        })));
    }
    if let Some(subject) = f.rule.strip_prefix(verdict::PREFIX) {
        let events = match findings::published(subject).and_then(|l| l.kind) {
            Some(kind) => rule_events(conn, &f.id, kind)?,
            None => Vec::new(),
        };
        return Ok(Some(Body::VerdictGiven(v1::VerdictGiven {
            rule: subject.to_string(),
            events,
        })));
    }
    if let Some(change) = place_change(&f.rule, f.change.as_deref()) {
        return Ok(Some(Body::PlaceChanged(v1::PlaceChanged {
            change,
            presence_only: crate::watched::last_presence_only(conn, &f.about)?,
        })));
    }
    let became = || f.became.as_deref().map(whole);
    Ok(Some(
        match f.rule.split_once('.').map(|(family, _)| family) {
            Some("integrity") => Body::ChangedInPlace(v1::ChangedInPlace {
                became_text: became(),
                files: crate::integrity::files_changed(conn, &f.id)?,
            }),
            Some("indicator") => {
                let note = f.sampled.as_ref();
                Body::IndicatorMatched(v1::IndicatorMatched {
                    indicators_text: became(),
                    process: note.map(process),
                    port: note.and_then(|n| u32::try_from(n["port"].as_u64()?).ok()),
                    // The core's own word, as `processes::sampled` wrote it.
                    transport: note.and_then(|n| n["transport"].as_str().map(str::to_string)),
                })
            }
            Some("processes") => Body::DetachedProcess(process(
                f.sampled.as_ref().unwrap_or(&serde_json::Value::Null),
            )),
            Some("lockfiles") => {
                Body::VulnerablePackage(match vulnerabilities::kept(conn)?.remove(&f.id) {
                    // What it was about when it was cleared or its package left, and why.
                    Some(k) => v1::VulnerablePackage {
                        no_longer_found: Some(value_of::<v1::NoLongerFound>(&k.why)),
                        no_longer_found_at: Some(k.at),
                        ..package_in(conn, k.was, &f.about)?
                    },
                    None => package(conn, &f.about)?,
                })
            }
            _ => return Ok(None),
        },
    ))
}

/// What happened to the place a finding is about, for a rule whose evidence is a place that
/// changed (`watched.*` and `autorun.*`); `None` for every other rule. The one source of
/// `PlaceChanged.change` and `ListedFinding.change`, so a list and a finding never disagree.
pub fn place_change(rule: &str, word: Option<&str>) -> Option<i32> {
    matches!(
        rule.split_once('.').map(|(family, _)| family),
        Some("watched" | "autorun")
    )
    .then(|| change(word))
}

/// A change as the store words it, with spaces written as underscores in the contract.
fn change(word: Option<&str>) -> i32 {
    change_of(word.unwrap_or_default())
}

/// The same for a word that is there.
pub fn change_of(word: &str) -> i32 {
    value_of::<v1::Change>(&word.replace(' ', "_"))
}

/// How many events a published rule's finding counts since it was raised; `None` when the
/// store holds no count for it.
fn rule_count(conn: &Connection, finding: &str) -> rusqlite::Result<Option<u64>> {
    let n: Option<i64> = conn
        .query_row(
            "SELECT matches FROM rule_finding WHERE finding = ?1",
            [finding],
            |r| r.get(0),
        )
        .optional()?;
    Ok(n.map(|n| n as u64))
}

/// The events a published rule's finding keeps, newest first, as `immunity matches` gives an
/// event: the rows are made back into what the collector's reading made them from.
fn rule_events(
    conn: &Connection,
    finding: &str,
    kind: sigma::Kind,
) -> rusqlite::Result<Vec<v1::Event>> {
    // A row's arguments are read back cut, and cut again, so a set newer than the one that kept
    // them applies; the start made from the row holds none.
    let read: Vec<(Evidence, Args)> = match kind {
        sigma::Kind::Process => conn
            .prepare(
                "SELECT timestamp, executable, args, parent_executable, working_directory, pid,
                        parent_pid, user_id, signing_id, team_id, platform_binary
                 FROM rule_evidence WHERE finding = ?1 ORDER BY rowid DESC",
            )?
            .query_map([finding], |r| {
                let args: String = r.get(2)?;
                let args: Vec<String> = serde_json::from_str(&args).unwrap_or_default();
                let start = Evidence::Start(ProcessStart {
                    timestamp: r.get(0)?,
                    executable: r.get(1)?,
                    parent_executable: r.get(3)?,
                    working_directory: r.get(4)?,
                    pid: r.get(5)?,
                    parent_pid: r.get(6)?,
                    user_id: r.get(7)?,
                    signing_id: r.get(8)?,
                    team_id: r.get(9)?,
                    platform_binary: r.get(10)?,
                    ..ProcessStart::default()
                });
                Ok((start, Args::stored(&args)))
            })?
            .collect::<rusqlite::Result<_>>()?,
        sigma::Kind::File => conn
            .prepare(
                "SELECT timestamp, action, path, source, executable
                 FROM rule_file_evidence WHERE finding = ?1 ORDER BY rowid DESC",
            )?
            .query_map([finding], |r| {
                let action: String = r.get(1)?;
                let event = Evidence::File(FileEvent {
                    timestamp: r.get(0)?,
                    // A word the collector's reading does not write is no action: it prints
                    // as unspecified, which a reader cannot judge.
                    action: events::FILE_KINDS
                        .iter()
                        .find(|k| **k == action)
                        .copied()
                        .unwrap_or_default(),
                    path: r.get(2)?,
                    source: r.get(3)?,
                    executable: r.get(4)?,
                    ..FileEvent::default()
                });
                Ok((event, Args(Vec::new())))
            })?
            .collect::<rusqlite::Result<_>>()?,
    };
    Ok(read
        .iter()
        .map(|(e, args)| matches::event_cut(e, args))
        .collect())
}

/// The process the latest sample that raised or found again a finding saw, as the journal entry
/// `sampled` keeps it (`Found::sampled`): its pid and start, its command line, cut again as a
/// published rule's evidence is (`rule_events`), its folder, its parent and its leaders.
fn process(note: &serde_json::Value) -> v1::DetachedProcess {
    let args: Vec<String> = serde_json::from_value(note["args"].clone()).unwrap_or_default();
    let args = Args::stored(&args);
    let leader = |l: &serde_json::Value| {
        Some(v1::ProcessLeader {
            pid: l["pid"].as_i64()?,
            executable_text: whole(l["executable"].as_str()?),
            signed_by_text: l["signed_by"].as_str().map(whole),
        })
    };
    v1::DetachedProcess {
        pid: note["pid"].as_i64(),
        start_micros: note["start"].as_i64(),
        args_text: args.shown(whole),
        cuts: matches::cuts(&args),
        working_directory_text: note["working_directory"].as_str().map(whole),
        session_leader: leader(&note["session_leader"]),
        process_group_leader: leader(&note["process_group_leader"]),
        parent: leader(&note["parent"]),
    }
}

/// A package a project depends on, from the answers that stand now, as the report reads them
/// (`vulnerabilities::finding_detail`): every record that affects it, and every release it
/// affects with where it is declared.
pub fn package(conn: &Connection, about: &str) -> rusqlite::Result<v1::VulnerablePackage> {
    package_in(conn, vulnerabilities::affecting(conn)?, about)
}

/// The same from the answers in `list`.
fn package_in(
    conn: &Connection,
    list: Vec<vulnerabilities::Affecting>,
    about: &str,
) -> rusqlite::Result<v1::VulnerablePackage> {
    let mine: Vec<vulnerabilities::Affecting> =
        list.into_iter().filter(|a| a.is_about(about)).collect();
    let mut out = v1::VulnerablePackage::default();
    let Some(first) = mine.first() else {
        return Ok(out);
    };
    out.project_text = Some(whole(&first.checkout));
    out.ecosystem = Some(first.ecosystem.clone());
    out.package_text = Some(whole(&first.package));
    // A release two records affect is given once.
    let releases: BTreeSet<(String, String)> =
        mine.iter().flat_map(|a| a.affected_of(about)).collect();
    out.releases = releases
        .iter()
        .map(|(version, line)| v1::PackageRelease {
            version_text: whole(version),
            at_text: whole(&vulnerabilities::at_shown(line)),
        })
        .collect();
    let listed = crate::threats::last_good(conn).unwrap_or(None).is_some();
    for a in &mine {
        out.records.push(v1::PackageRecord {
            id_text: whole(&a.advisory),
            aliases_text: a.aliases.iter().map(|s| whole(s)).collect(),
            source: vulnerabilities::source_name(&a.advisory).to_string(),
            label: a.label.to_string(),
            exploited: vulnerabilities::exploited(a.exploited, listed),
            summary_text: a.summary.as_deref().map(whole),
            fixed_text: a.fixed.iter().map(|s| whole(s)).collect(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{change, v1};

    #[test]
    fn every_change_the_store_words_is_a_value_of_the_contract_and_never_unspecified() {
        // A reader takes an unspecified change for one it cannot judge.
        for (word, value) in [
            ("new", v1::Change::New),
            ("changed", v1::Change::Changed),
            ("gone", v1::Change::Gone),
            ("first read", v1::Change::FirstRead),
            (crate::findings::NOT_READ, v1::Change::NotRead),
        ] {
            assert_eq!(change(Some(word)), value as i32, "{word}");
        }
        assert_eq!(change(None), v1::Change::Unspecified as i32);
        assert_eq!(
            change(Some("unknown change")),
            v1::Change::Unspecified as i32
        );
    }
}
