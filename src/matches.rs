//! `immunity matches`: every match of the published rules over the collector's log, of every
//! level, each with the event it matched, printed as the contract's `Matches` message
//! (`contract/immunity/v1/matches.proto`). The response layer reads it to look into what the core
//! is not sure of.
//!
//! Nothing is written to the store and nothing is evaluated. The answer is the record the
//! evaluator keeps (`rule_line`, see `events::record`): a row for every match of every rule, by a
//! number never given twice, each with its line's place and the finding it went to. The event is
//! read again from the log at that place (`events::at_line`), and given only when it is the line
//! judged. The caller's place is the store's id, the number of the last row it was given and the
//! running totals of the counts its answer reached (`events::totals`), printed as an opaque token
//! (`Place`); a place from another store, or one this version cannot read, is refused with what to
//! do.
//!
//! No false calm. An answer with no matches says how far the evaluator has read and whether it
//! reads now (`Evaluated`), what the lines it counted after the caller's place held, what was
//! lost, unreadable or deleted before it was read, whether rows the caller had not been given went
//! with their files, the collector's state, and which rules judge nothing here and why. All of it
//! is read in one transaction, so the rows, the counts and how far the evaluator read are of one
//! moment. A store that is not there, or cannot be read, is a failure.

use crate::contract::{v1, value_of};
use crate::events::{self, Arrival, Arrivals, AtLine, Evidence, Lacked};
use crate::known::whole;
use crate::outcome::Outcome;
use crate::secrets::Args;
use crate::sigma::{Kind, Meta, Placement, Reason, Rules};
use crate::{answer, findings, known, store, verdict};
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The version of the contract this build prints.
const FORMAT: u32 = 1;
/// How many matches one answer holds unless `--limit` says otherwise. A match of a program
/// start is about a kilobyte of JSON and half that in binary, measured on invented logs, so the
/// default answer is about a megabyte; `BYTES` keeps one with very long command lines small too.
pub const LIMIT: usize = 1000;
/// The most bytes of matched lines one answer holds, each line counted once for every rule it
/// matched. An argument list is never cut and can be a megabyte, so the count of matches alone
/// does not keep an answer small.
pub const BYTES: usize = 4 << 20;
/// The version of a place's encoding, its first number. This build writes it and reads only it.
const PLACE_VERSION: u64 = 4;
/// How long the evaluator may be silent while a whole line waits past where the store says it
/// read, before it is taken as not advancing, in seconds. While it reads it writes at least once
/// a second (`evaluator::IDLE`), and the time of its write is kept to the second, so a healthy
/// evaluator is at most two seconds old by it; three leaves a second for a write that waits on
/// SQLite's lock.
const LATE: i64 = 3;

const AFTER: &str = "--after takes the place an answer of immunity matches printed in continue_after, whole and as printed; for a place this version cannot read, such as one an earlier version printed, run immunity matches without --after to start from the oldest match kept";
const OTHER_STORE: &str = "the place given with --after was printed for another store, or for this one before it was made again: run immunity matches without --after to start from the oldest match kept";

/// Why rules for file events judge nothing while the collector is not installed, and before the
/// store holds any reading of it.
const NOT_INSTALLED: &str = "the event level is not installed";
const NOT_READ: &str = "the store holds no reading of the event level yet";

/// `immunity matches`.
pub struct MatchesArgs {
    pub store: PathBuf,
    pub form: answer::Form,
    /// The place given with `--after`, as given, and as read.
    pub after: Option<(String, Place)>,
    pub limit: usize,
    /// `--limit` was given: the text for a person lists every match one row each.
    pub single: bool,
    /// The folder `/Library` is resolved under: `/` unless a test gives another.
    pub system_root: PathBuf,
}

/// Reads the arguments after `matches`.
pub fn parse(
    it: impl Iterator<Item = String>,
    options: &mut answer::Options,
) -> Result<MatchesArgs, String> {
    let (mut after, mut limit, mut root, mut single) = (None, LIMIT, None, false);
    options.read(it, |arg, it| {
        match arg.as_str() {
            "--system-root" => root = Some(crate::value(it, &arg)?.into()),
            "--after" => {
                let p = crate::value(it, &arg)?;
                let place = Place::parse(&p).ok_or(AFTER)?;
                after = Some((p, place));
            }
            "--limit" => {
                single = true;
                // More than the record can hold is all of it: the number is capped before any
                // arithmetic, so it never wraps.
                limit = crate::value(it, &arg)?
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("--limit takes a whole number of at least 1")?
                    .min(i64::MAX as u64 - 1) as usize;
            }
            _ => return Err(format!("unexpected argument: {arg}")),
        }
        Ok(())
    })?;
    Ok(MatchesArgs {
        store: options.store()?,
        form: options.form(),
        after,
        limit,
        single,
        system_root: root.unwrap_or_else(|| PathBuf::from("/")),
    })
}

/// A caller's place in the record: the store it was printed for, the number of the last row of
/// the record it was given, and the running totals of the counts its answer reached
/// (`events::totals`): the next answer gives the rows after the one and the totals now less these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    store: [u8; 16],
    seq: u64,
    totals: [u64; events::TOTALS],
}

/// A place is printed as lower-case hexadecimal of a run of unsigned varints in protobuf's
/// encoding, written and read by prost: the encoding's version, 4; the sixteen bytes of the
/// store's id, one varint each; the row of the record; and the totals, in the store's order.
/// Hexadecimal, because it passes through a shell and an argument parser untouched and is checked
/// character by character.
impl std::fmt::Display for Place {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let bytes = self.encode();
        bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl Place {
    /// The place in the store whose id is `store`, as `store::id` gives it.
    fn of(store: &str, seq: i64, totals: &[i64; events::TOTALS]) -> Option<Place> {
        let bytes: Vec<u8> = (store.as_bytes().chunks(2))
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect::<Option<_>>()?;
        let mut kept = [0; events::TOTALS];
        for (k, t) in kept.iter_mut().zip(totals) {
            *k = u64::try_from(*t).ok()?;
        }
        Some(Place {
            store: bytes.try_into().ok()?,
            seq: u64::try_from(seq).ok()?,
            totals: kept,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut put = |n: u64| prost::encoding::encode_varint(n, &mut bytes);
        put(PLACE_VERSION);
        self.store.iter().for_each(|b| put(u64::from(*b)));
        put(self.seq);
        self.totals.iter().for_each(|t| put(*t));
        bytes
    }

    /// A place as `immunity matches` prints it; `None` for any other text, a place of another
    /// version of the encoding among them. The text must be exactly what this build prints for
    /// the place it reads: lower case, nothing left over, and no two texts one place.
    pub fn parse(text: &str) -> Option<Place> {
        let bytes: Vec<u8> = (text.as_bytes().chunks(2))
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect::<Option<_>>()?;
        let mut buf = bytes.as_slice();
        let mut next = || prost::encoding::decode_varint(&mut buf).ok();
        if next()? != PLACE_VERSION {
            return None;
        }
        let mut store = [0u8; 16];
        for b in &mut store {
            *b = u8::try_from(next()?).ok()?;
        }
        let seq = next()?;
        let mut totals = [0; events::TOTALS];
        for t in &mut totals {
            *t = next()?;
        }
        let place = Place { store, seq, totals };
        (place.to_string() == text).then_some(place)
    }
}

/// Why an answer could not be given.
enum Failure {
    Store(Outcome),
    Log(String),
    /// The place given was not printed for this store, or names rows it never gave.
    Place,
}

/// Answers `immunity matches` in the form asked, or fails as every command of the contract does,
/// with the exit codes the report commands use.
pub fn matches_cmd(args: &MatchesArgs) -> ExitCode {
    let (error, exit) = match read(args, crate::now_secs()) {
        Ok(m) => {
            return answer::print("matches", args.form, &m, |m| {
                crate::lists::matches(m, args.single, &crate::screen::Screen::of_stdout())
            });
        }
        Err(Failure::Store(o)) => (o.error("matches", "immunity matches --json"), o.exit()),
        Err(Failure::Log(why)) => (
            answer::error(
                "log_unreadable",
                "the event log could not be read, so the events of the matches cannot be read again",
                "immunity matches --json",
                &why,
            ),
            1,
        ),
        Err(Failure::Place) => (
            answer::error("usage", OTHER_STORE, "immunity matches --json", ""),
            crate::EXIT_USAGE,
        ),
    };
    answer::fail("matches", args.form, error, exit)
}

fn read(args: &MatchesArgs, now: i64) -> Result<v1::Matches, Failure> {
    read_with(Rules::shipped(), args, now)
}

/// `read`, naming in `unevaluated` these rules. What matched is what the record holds.
fn read_with(rules: &Rules, args: &MatchesArgs, now: i64) -> Result<v1::Matches, Failure> {
    if !args.store.is_file() {
        return Err(Failure::Store(crate::store::absent(&args.store)));
    }
    store::read(&args.store, |tx| answered(rules, args, now, tx)).map_err(Failure::Store)?
}

/// The answer, read in `tx`, one read of the store: the rows after the caller's place, the
/// counts after it, how far the evaluator read, and the lines of the rows read again from the
/// log.
fn answered(
    rules: &Rules,
    args: &MatchesArgs,
    now: i64,
    tx: &Connection,
) -> Result<Result<v1::Matches, Failure>, Box<dyn std::error::Error>> {
    let id = store::id(tx)?;
    let (given, removed) = events::marks(tx)?;
    let totals = events::totals(tx)?;
    let (seq, from) = match &args.after {
        None => (0, [0; events::TOTALS]),
        Some((_, p)) => {
            let ours = Place::of(&id, 0, &[0; events::TOTALS]).is_some_and(|o| o.store == p.store);
            // A number past any this store gave, or past what its totals reached, was never
            // printed by it; one that does not fit the store's numbers is no place at all.
            let seq = i64::try_from(p.seq).ok().filter(|s| *s <= given);
            let mut from = [0; events::TOTALS];
            let fits = from
                .iter_mut()
                .zip(&p.totals)
                .zip(&totals)
                .all(|((f, p), now)| {
                    i64::try_from(*p).is_ok_and(|p| {
                        *f = p;
                        p <= *now
                    })
                });
            match seq {
                Some(seq) if ours && fits => (seq, from),
                _ => return Ok(Err(Failure::Place)),
            }
        }
    };
    let home = crate::home(&args.store);
    let lock = crate::watch::Lock::read(&home);
    let failed = crate::watch::failures(tx, &lock)?;
    let level = events::served(tx, &failed, now)?;
    let refs = finding_refs(tx, now)?;
    let mut answer = v1::Matches {
        format: FORMAT,
        answered_at: now,
        after: args.after.as_ref().map(|(text, _)| text.clone()),
        store_id: Some(id.clone()),
        ..Default::default()
    };
    // The rows after the place, one more than asked to tell whether more are left.
    let rows = events::recorded_after(tx, seq, args.limit + 1)?;
    let mut last = seq;
    let mut bytes = 0;
    let mut gone = removed > seq;
    for row in &rows {
        if answer.matches.len() == args.limit || bytes >= BYTES {
            answer.more = true;
            break;
        }
        let event = match events::at_line(&args.system_root, &row.at, row.inode, &row.line) {
            Ok(AtLine::Event(e, len)) => {
                bytes += len;
                Some(e)
            }
            // The line judged went from the log a moment ago, or another line is in its place:
            // the match is given, and that its event is gone said.
            Ok(AtLine::Gone | AtLine::NoLine) => {
                gone = true;
                None
            }
            Err(why) => return Ok(Err(Failure::Log(why))),
        };
        let loaded = Rules::shipped().by_name(&row.rule);
        let (rule, (raised, mut findings)) =
            match loaded.and_then(|l| Some((l.file, l.meta.as_ref()?))) {
                Some((file, meta)) => (
                    rule(file, meta),
                    raised(meta, row.finding.as_deref(), &refs),
                ),
                // A rule this build no longer ships, recorded by an earlier build of the same format:
                // given by its name, never left out, and what it raised left to the reader.
                None => (
                    v1::Rule {
                        name: row.rule.clone(),
                        ..Default::default()
                    },
                    (v1::Raised::Unspecified, Vec::new()),
                ),
            };
        let position = row.at.to_string();
        // The response layer's verdicts about the match, read by the match; the finding its
        // latest suspicious one went to is named after the core's.
        let said = verdict::listed(tx, "position = ?1 AND rule = ?2", &[&position, &row.rule])?;
        if let Some(f) = said.2.iter().rev().find_map(|v| v.finding.as_ref())
            && let Some(r) = refs.get(f)
        {
            findings.push(r.clone());
        }
        answer.matches.push(v1::RuleMatch {
            verdicts: verdict::verdicts(said, Some(&id), &refs, None),
            position,
            rule: Some(rule),
            event: event.as_deref().map(self::event),
            raised: raised as i32,
            findings,
        });
        last = row.seq;
    }
    // With nothing left, the next answer starts after every number given so far: a row is given a
    // number larger than any before it, so none can come before it later.
    if !answer.more {
        last = last.max(given);
    }
    // The counts are the totals now less the place's.
    let (tally, file_tally, lacked) = events::counted_between(&from, &totals);
    // The source as its own files say now, never as the last conclusion left it.
    let source = events::source_now(tx, &args.system_root, now)?;
    let waiting = match &source {
        events::Source::Failed(why) => Err(why),
        events::Source::Read(s) => Ok(s.waiting),
        events::Source::NotInstalled => Ok(false),
    };
    let state = evaluator(tx, &home, &lock, level.as_ref(), waiting, now)?;
    let n = |v: i64| v.max(0) as u64;
    let evaluated = v1::Evaluated {
        state: state.0 as i32,
        behind: state.1 as i32,
        reason_text: state.2.map(|r| whole(&r)),
        read_until_at: events::evaluated_at(tx)?,
        program_starts: n(tally.starts),
        file_events: n(file_tally.files),
        other: n(tally.other),
        unreadable_lines: n(tally.unreadable),
        unreadable_file_events: n(file_tally.unreadable),
        program_starts_lost: n(tally.lost),
        program_starts_unknown_losses: n(tally.unknown_gaps),
        file_events_lost: n(file_tally.lost),
        file_events_unknown_losses: n(file_tally.unknown_gaps),
        files_removed_unread: n(tally.removed_unread),
        gone,
    };
    answer.collector = Some(collector(level.as_ref(), &evaluated, &source));
    // Not installed as the source says now, whatever the last conclusion said.
    answer.unevaluated = match &level {
        _ if matches!(source, events::Source::NotInstalled) => {
            unevaluated(rules, &Err(NOT_INSTALLED.to_string()), None, None)
        }
        Some(l) => {
            use rusqlite::OptionalExtension;
            // Why file events are not collected, with what the system said when the record of
            // what the collector records could not be read: as the files' coverage keeps it.
            let collects = match l.files.collected {
                true => Ok(()),
                false => Err(tx
                    .query_row(
                        "SELECT reason FROM coverage WHERE reader = ?1 AND kind = ?2
                         AND cause = 'failed' ORDER BY id DESC LIMIT 1",
                        rusqlite::params![events::READER, events::KIND_FILES],
                        |r| r.get::<_, Option<String>>(0),
                    )
                    .optional()?
                    .flatten()
                    .or_else(|| l.files.why.clone())
                    .unwrap_or_default()),
            };
            unevaluated(rules, &collects, Some(&l.arrivals), Some(&lacked))
        }
        // Before any reading of the level, nothing is known of what it records.
        None => unevaluated(
            rules,
            &Err(NOT_READ.to_string()),
            Some(&Arrivals::default()),
            None,
        ),
    };
    answer.evaluated = Some(evaluated);
    answer.continue_after = Place::of(&id, last, &totals).map(|p| p.to_string());
    Ok(Ok(answer))
}

/// Whether the evaluator has read the log up to about now, why not, and what failed, from the
/// evaluator's own writes and never from the times of the log's files. Failed when the level is
/// served failed, or when the log folder or a file in it cannot be read (`waiting`, with why).
/// Current only when a live watcher holds its lock, the evaluator that wrote last is the one its
/// lock file names, it has read every whole line it listed since its start, and either no whole
/// line waits past where the store says it read (`waiting`) or it wrote within `LATE` seconds of
/// now, either way. Else behind: no watcher; another evaluator wrote last, or this one has not
/// caught up since its start; or it has been silent while a line waits, because a full check holds
/// the store or because it stalled.
fn evaluator(
    tx: &Connection,
    home: &Path,
    lock: &crate::watch::Lock,
    level: Option<&events::Level>,
    waiting: Result<bool, &String>,
    now: i64,
) -> rusqlite::Result<(v1::EvaluatorState, v1::BehindReason, Option<String>)> {
    use v1::{BehindReason as Why, EvaluatorState as State};
    if let Some(l) = level.filter(|l| l.state == events::FAILED) {
        return Ok((State::Failed, Why::Unspecified, l.reason.clone()));
    }
    let waiting = match waiting {
        Ok(waiting) => waiting,
        Err(why) => return Ok((State::Failed, Why::Unspecified, Some(why.clone()))),
    };
    let behind = |why| Ok((State::Behind, why, None));
    if !lock.watcher_alive() {
        return behind(Why::NoWatcher);
    }
    let Some((id, caught_up, at)) = events::evaluator(tx)? else {
        return behind(Why::CatchingUp);
    };
    if lock.evaluator() != Some(id) || !caught_up {
        return behind(Why::CatchingUp);
    }
    if waiting && (now - at).abs() > LATE {
        return match crate::check_running(tx, home)? {
            true => behind(Why::StoreHeld),
            false => behind(Why::NotAdvancing),
        };
    }
    Ok((State::Current, Why::Unspecified, None))
}

/// What became of a match among the findings, and the findings it went to: what the evaluator
/// recorded with the match, `finding`.
fn raised(
    meta: &Meta,
    finding: Option<&str>,
    refs: &BTreeMap<String, v1::FindingRef>,
) -> (v1::Raised, Vec<v1::FindingRef>) {
    // A rule raises by its level; one whose set states none has a value of its own, so that
    // `below_high` keeps the meaning it had.
    if meta.level.is_none() {
        return (v1::Raised::LevelNotStated, Vec::new());
    }
    if !meta.raises() {
        return (v1::Raised::BelowHigh, Vec::new());
    }
    match finding {
        Some(id) => {
            // Every finding of a shipped rule is among them; the id alone stands for one that is
            // not.
            let finding = refs.get(id).cloned().unwrap_or(v1::FindingRef {
                id: id.to_string(),
                ..Default::default()
            });
            (v1::Raised::Finding, vec![finding])
        }
        None => (v1::Raised::NoFinding, Vec::new()),
    }
}

/// Every finding in the store, by id, as `immunity project` and the others name one.
fn finding_refs(conn: &Connection, now: i64) -> rusqlite::Result<BTreeMap<String, v1::FindingRef>> {
    let found = findings::all(conn, now)?;
    Ok(found
        .iter()
        .map(findings::item)
        .map(|i| (i.id.clone(), known::finding_ref(&i)))
        .collect())
}

/// When an event happened, as seconds and nanoseconds.
fn happened(e: &Evidence) -> Option<(i64, u32)> {
    events::instant(match e {
        Evidence::Start(s) => &s.timestamp,
        Evidence::File(f) => &f.timestamp,
    })
}

/// A rule's level as the contract gives it: `not_stated` for a rule whose set states none.
/// A reader built before that value was added reads it as one it does not know, so as the
/// highest level; whether the match raised a finding is `raised`'s to say, never the level's.
fn level(m: &Meta) -> i32 {
    m.level_name()
        .map_or(v1::Level::NotStated as i32, value_of::<v1::Level>)
}

pub fn rule(file: &str, m: &Meta) -> v1::Rule {
    v1::Rule {
        name: m.name.clone(),
        file: file.to_string(),
        id_text: whole(&m.id),
        title_text: whole(&m.title),
        level: level(m),
        techniques_text: m.techniques.iter().map(|t| whole(t)).collect(),
        author_text: m.author.as_deref().map(whole),
        source: m.source.name.to_string(),
        set: m.source.set.to_string(),
    }
}

/// A process the log gives the program of, and who it is as far as the log says.
fn program(executable: &str, who: &events::Identity) -> v1::Process {
    let started = who.started.as_deref().and_then(events::instant);
    v1::Process {
        executable_text: whole(executable),
        pid: who.pid,
        pid_version: who.pid_version,
        started_at: started.map(|s| s.0),
        started_nanos: started.map(|s| s.1),
        user_id: who.user_id,
        real_user_id: who.users.real_user_id,
        group_id: who.users.group_id,
        real_group_id: who.users.real_group_id,
        ..Default::default()
    }
}

/// A process the log gives the pid of, without its program, as the contract gives it: absent
/// when the log does not give its pid.
fn identity(who: &events::Identity) -> Option<v1::Identity> {
    who.pid.map(|pid| v1::Identity {
        pid: Some(pid),
        pid_version: who.pid_version,
    })
}

/// Code-signing flags as the contract gives them: the kernel's 32 bits, or absent.
fn flags(f: Option<i64>) -> Option<u32> {
    f.and_then(|f| u32::try_from(f).ok())
}

/// An event as the contract gives it: every field the log holds, each whole, but for the
/// secrets cut out of the arguments.
pub fn event(e: &Evidence) -> v1::Event {
    let args = match e {
        Evidence::Start(s) => Args::raw(&s.args),
        Evidence::File(_) => Args(Vec::new()),
    };
    event_cut(e, &args)
}

/// The same, with a program start's arguments as given, already cut: a stored row's are read
/// back from the store (`finding_answer`). The start's own `args` are not read.
pub fn event_cut(e: &Evidence, args: &Args) -> v1::Event {
    use v1::event::Body;
    let when = happened(e);
    let (happened_at, happened_nanos) = (when.map(|w| w.0), when.map(|w| w.1));
    v1::Event {
        body: Some(match e {
            Evidence::Start(s) => Body::ProgramStart(v1::ProgramStart {
                happened_at,
                happened_nanos,
                process: Some(v1::Process {
                    signing_id_text: s.signing_id.as_deref().map(whole),
                    team_id_text: s.team_id.as_deref().map(whole),
                    platform_binary: s.platform_binary,
                    codesigning_flags: flags(s.who.codesigning_flags),
                    ..program(
                        &s.executable,
                        &events::Identity {
                            pid: Some(s.pid),
                            pid_version: s.who.pid_version,
                            started: s.who.started.clone(),
                            user_id: s.user_id,
                            users: s.who.users.clone(),
                        },
                    )
                }),
                instigator: s.parent_executable.as_deref().map(|p| v1::Process {
                    signing_id_text: s.who.instigator_signing_id.as_deref().map(whole),
                    team_id_text: s.who.instigator_team_id.as_deref().map(whole),
                    platform_binary: s.who.instigator_platform_binary,
                    codesigning_flags: flags(s.who.instigator_codesigning_flags),
                    ..program(p, &s.who.instigator)
                }),
                parent_pid: s.parent_pid,
                args_text: args.shown(whole),
                cuts: cuts(args),
                working_directory_text: s.working_directory.as_deref().map(whole),
                parent: identity(&s.who.parent),
                script_text: s.who.script.as_deref().map(whole),
                responsible: identity(&s.who.responsible),
                process_group_id: s.who.process_group,
            }),
            Evidence::File(f) => Body::FileEvent(v1::FileEvent {
                happened_at,
                happened_nanos,
                action: value_of::<v1::FileAction>(f.action),
                path_text: whole(&f.path),
                source_text: f.source.as_deref().map(whole),
                instigator: Some(v1::Process {
                    signing_id_text: f.signing_id.as_deref().map(whole),
                    team_id_text: f.team_id.as_deref().map(whole),
                    platform_binary: f.platform_binary,
                    codesigning_flags: flags(f.codesigning_flags),
                    ..program(&f.executable, &f.instigator)
                }),
            }),
        }),
    }
}

/// What was cut out of arguments, as the contract lists it beside them.
pub fn cuts(args: &Args) -> Vec<v1::Cut> {
    args.cuts()
        .into_iter()
        .map(|c| v1::Cut {
            argument: c.argument as u32,
            kind: c.kind,
            length: c.length as u64,
        })
        .collect()
}

/// The collector as its own files say at the answer (`source`), as a reading judges it: not
/// installed, refused, failing or silent as they say, and failed when its log cannot be read. Its
/// state is `running` only while the answer can be quiet by what `evaluated` holds: else `failed`
/// or `behind`, so that a reader built before `evaluated` never takes the answer for quiet. What
/// arrives is the evaluator's latest conclusion's (`level`), as of `status_read_at`.
fn collector(
    level: Option<&events::Level>,
    e: &v1::Evaluated,
    source: &events::Source,
) -> v1::Collector {
    let looked = match source {
        events::Source::Read(s) => Some(s.as_ref()),
        _ => None,
    };
    let whole = e.unreadable_lines
        + e.unreadable_file_events
        + e.program_starts_lost
        + e.program_starts_unknown_losses
        + e.file_events_lost
        + e.file_events_unknown_losses
        + e.files_removed_unread
        == 0
        && !e.gone;
    use v1::CollectorState as C;
    let state = match (source, e.state()) {
        (_, v1::EvaluatorState::Failed) | (events::Source::Failed(_), _) => C::Failed as i32,
        (events::Source::NotInstalled, _) => C::NotInstalled as i32,
        (events::Source::Read(s), state) if s.state == events::RUNNING => {
            match state == v1::EvaluatorState::Current && whole {
                true => C::Running as i32,
                false => C::Behind as i32,
            }
        }
        (events::Source::Read(s), _) => value_of::<C>(s.state),
    };
    let none = Arrivals::default();
    let arrivals = level.map_or(&none, |l| &l.arrivals);
    v1::Collector {
        state,
        said_by: looked
            .and_then(|s| s.said.as_ref())
            .map(|(by, _)| by.to_string()),
        said_text: looked
            .and_then(|s| s.said.as_ref())
            .map(|(_, said)| said.said()),
        written_at: looked.and_then(|s| s.written),
        file_events_collected: looked.is_some_and(|s| s.collects),
        status_state: level.map(|l| value_of::<C>(&l.state)),
        status_read_at: level.map(|l| l.read_at),
        foreign_files: looked.map_or(0, |s| s.foreign),
        not_kept: named(arrivals, Arrival::NotKept),
        kept_never_filled: named(arrivals, Arrival::Kept(None)),
        not_yet_known: named(arrivals, Arrival::Unknown),
        arriving: arrivals
            .arriving()
            .into_iter()
            .map(|(name, since)| v1::Arriving {
                name: name.to_string(),
                since,
            })
            .collect(),
        no_longer_arriving: arrivals
            .no_longer()
            .into_iter()
            .map(|(name, since)| v1::NoLongerArriving {
                name: name.to_string(),
                since,
            })
            .collect(),
    }
}

/// The names of what a collector may keep that the lines say this of.
fn named(arrivals: &Arrivals, state: Arrival) -> Vec<String> {
    arrivals
        .named(|a| a == state)
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The rules that judge nothing here, or only in part, each with why, in the order they are
/// shipped. `collects` is whether file events are collected here, or why not; `arrivals` what
/// the core's latest reading says of what a collector may keep, so that a rule that reads one
/// that does not arrive judges nothing; `lacked` what the lines this answer judged did not give,
/// so that a rule that was not asked about some of them, or was asked without what it reads, is
/// named whatever the store says. Both `None` when no collector is installed.
///
/// What this list says rests on the lines read: the store can only add to it. A reading older
/// than the lines, as after a downgrade with the app closed, never makes a stretch whose lines
/// lack a field look judged.
fn unevaluated(
    rules: &Rules,
    collects: &Result<(), String>,
    arrivals: Option<&Arrivals>,
    lacked: Option<&Lacked>,
) -> Vec<v1::Unevaluated> {
    let not_arriving = arrivals.map_or(0, Arrivals::not_arriving);
    let lacked_of = |kind: Option<Kind>| kind.zip(lacked).map_or(0, |(k, l)| l.of(k));
    use v1::UnevaluatedReason as Why;
    let not_collected = collects.as_ref().err();
    let texts = |items: &[String]| items.iter().map(|s| whole(s)).collect();
    rules
        .rules
        .iter()
        .filter_map(|l| {
            // For a rule a translated set did not take, what the translation said of it.
            let said = l.detail.map(str::to_string);
            let (why, fields, detail): (Why, Vec<String>, Option<String>) =
                match (&l.placement, not_collected) {
                    (Placement::NotEvaluated(r), _) => match r {
                        Reason::NeedsEvents(c) => (Why::NeedsEvents, Vec::new(), Some(c.clone())),
                        Reason::NeedsFields(f) => (Why::NeedsFields, texts(f), said),
                        Reason::KeywordSearch => (Why::KeywordSearch, Vec::new(), None),
                        Reason::NotParsed(s) => (Why::NotParsed, Vec::new(), Some(s.clone())),
                        Reason::Sequence => (Why::Sequence, Vec::new(), said),
                        Reason::NotEql => (Why::NotEql, Vec::new(), said),
                        Reason::BackslashInWildcard => (Why::BackslashInWildcard, Vec::new(), said),
                        Reason::SpansKinds => (Why::SpansKinds, Vec::new(), said),
                        Reason::NeverTrue => (Why::NeverTrue, Vec::new(), said),
                        Reason::Regex => (Why::Regex, Vec::new(), said),
                        Reason::Unsupported => (Why::Unsupported, Vec::new(), said),
                        Reason::Function => (Why::Function, Vec::new(), said),
                    },
                    (_, Some(why)) if l.kind == Some(Kind::File) => {
                        (Why::NotCollected, Vec::new(), Some(why.clone()))
                    }
                    _ if l.silenced_by(not_arriving) => (
                        Why::NotCollected,
                        texts(&l.needs_fields),
                        arrivals
                            .and_then(|a| a.worst(l.needs & not_arriving).why())
                            .map(str::to_string),
                    ),
                    _ if l.silenced_by(lacked_of(l.kind)) => (
                        Why::NotCollected,
                        texts(&l.needs_fields),
                        Some(events::NOT_IN_LINES.to_string()),
                    ),
                    (Placement::InPart(branches), _) => {
                        let mut fields: Vec<String> =
                            branches.iter().flat_map(|b| b.fields.clone()).collect();
                        fields.sort();
                        fields.dedup();
                        // What a translation left out that is not a missing field, such as a
                        // pattern it could not carry, as it wrote it.
                        let left: Vec<&str> = branches
                            .iter()
                            .filter(|b| b.fields.is_empty())
                            .filter_map(|b| b.said.as_deref())
                            .collect();
                        let detail = (!left.is_empty()).then(|| left.join("; "));
                        (Why::InPart, texts(&fields), detail)
                    }
                    (Placement::Evaluated, _) => return None,
                };
            let meta = l.meta.as_ref();
            Some(v1::Unevaluated {
                file: l.file.to_string(),
                name: meta.map(|m| m.name.clone()),
                id_text: meta.map(|m| whole(&m.id)),
                title_text: meta.map(|m| whole(&m.title)),
                level: meta.map(level),
                reason: why as i32,
                fields_text: fields,
                detail_text: detail.map(|d| whole(&d)),
                source: l.source.name.to_string(),
                set: l.source.set.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{NEVER_FILLED, NO_LONGER, NOT_KEPT, NOT_YET_KNOWN};

    const NOW: i64 = 1_791_090_000;

    /// A reading of the log under `root` by the core, as `immunity run` makes one, into `store`.
    fn core_reads(store: &std::path::Path, root: &std::path::Path) {
        core_reads_at(store, root, NOW);
    }

    /// The evaluator the watcher of these tests runs, by which `core_reads` reads.
    const EVALUATOR: i64 = 7;

    /// A watcher that holds the store in `dir`, ready, running `EVALUATOR`, started before every
    /// reading of these tests: the lock is this process's, as a watcher's is its own.
    fn watching(dir: &std::path::Path) -> std::fs::File {
        let lock = store::lock_watch(dir).unwrap().unwrap();
        let text = format!("1791000000\nheartbeat {EVALUATOR}\nready");
        std::fs::write(dir.join(store::WATCH_LOCK), text).unwrap();
        lock
    }

    /// A start of `dd if=/dev/zero bs=1 count=1`, which "Binary Padding - MacOS", marked high,
    /// matches: as a collector that keeps who each process is writes it, with its start time
    /// given or null, or as an earlier collector wrote it.
    fn dd(seq: u64, form: &str) -> String {
        let kept = format!(
            r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/sh"}},"audit_token":{{"pid":401,"pidversion":9401}},"start_time":"2026-10-04T00:00:01.900000Z","codesigning_flags":570522385}},"event":{{"exec":{{"args":["dd","if=/dev/zero","bs=1","count=1"],"cwd":{{"path":"/Users/example"}},"script":{{"path":"/Users/example/run.sh"}},"target":{{"executable":{{"path":"/bin/dd"}},"audit_token":{{"pid":402,"euid":501,"pidversion":9402}},"start_time":"2026-10-04T00:00:01.900000Z","parent_audit_token":{{"pid":401,"pidversion":9300}},"ppid":401,"signing_id":"com.apple.dd","team_id":null,"is_platform_binary":true,"codesigning_flags":570522304}}}}}}}}"#
        );
        let line = match form {
            "kept" => kept,
            "null" => kept.replace(
                r#""start_time":"2026-10-04T00:00:01.900000Z","parent_audit_token""#,
                r#""start_time":null,"parent_audit_token""#,
            ),
            _ => format!(
                r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/sh"}}}},"event":{{"exec":{{"args":["dd","if=/dev/zero","bs=1","count=1"],"cwd":{{"path":"/Users/example"}},"target":{{"executable":{{"path":"/bin/dd"}},"audit_token":{{"pid":402,"euid":501}},"ppid":401,"signing_id":"com.apple.dd","team_id":null,"is_platform_binary":true}}}}}}}}"#
            ),
        };
        line + "\n"
    }

    /// A file created by `curl`, as a collector that keeps who acted and its signer writes it,
    /// or as an earlier collector wrote it.
    fn created(form: &str) -> String {
        let who = match form {
            "old" => "",
            _ => {
                r#","audit_token":{"pid":403,"pidversion":9403},"start_time":"2026-10-04T00:00:01.900000Z","signing_id":"com.example.tool","codesigning_flags":570522385"#
            }
        };
        format!(
            r#"{{"schema_version":1,"seq_num":1,"time":"2026-10-04T00:00:03.000003Z","process":{{"executable":{{"path":"/usr/bin/curl"}}{who}}},"event":{{"create":{{"destination":"/Users/example/a"}}}}}}"#
        ) + "\n"
    }

    /// Writes `text` as the log file `name` under `root`, last written `ago` seconds before
    /// `NOW`.
    fn log_file(root: &std::path::Path, name: &str, text: &str, ago: u64) {
        let path = root.join(events::LOG).join(name);
        std::fs::write(&path, text).unwrap();
        let f = std::fs::File::options().append(true).open(&path).unwrap();
        let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(NOW as u64 - ago);
        f.set_modified(at).unwrap();
    }

    #[test]
    fn paging_tells_what_arrives_as_the_core_s_latest_reading_stored_it() {
        // No false calm. Pages of the record stop at their limit anywhere, so a file no longer
        // written can hold the last match a page gives: after a downgrade, the later collector's
        // file, which sorts after the earlier one's; after a clock set back, the file written
        // with the clock ahead. What `collector` and `unevaluated` say arrives is the core's
        // latest reading, on every page.
        let rules = crate::sigma::testing::process_kept();
        for (tag, files, said) in [
            (
                "downgrade",
                [
                    ("exec-20261004T000013-20261004T000000.jsonl", "kept", 200),
                    ("exec-20261004T00.jsonl", "old", 100),
                ],
                (
                    vec!["identity".to_string(), "script".into(), "signature".into()],
                    vec![],
                    1,
                ),
            ),
            (
                "clock",
                [
                    ("exec-20261004T000013-20261004T050000.jsonl", "kept", 200),
                    ("exec-20261004T000013-20261004T010000.jsonl", "null", 100),
                ],
                (vec![], vec!["identity"], 0),
            ),
        ] {
            let (dir, root) = installed_root(&format!("page-{tag}"));
            std::fs::remove_file(root.join(events::COLLECTS)).unwrap();
            for (n, (name, form, ago)) in files.iter().enumerate() {
                let seq = 10 * n as u64;
                // The file being written: who the program started is arrived, then stopped.
                let first = if *form == "null" { "kept" } else { form };
                let text =
                    dd(seq + 1, first) + &dd(seq + 2, form) + &dd(seq + 3, form) + &created(form);
                log_file(&root, name, &text, *ago);
            }
            let store = dir.join("store.db");
            core_reads(&store, &root);
            let mut after = None;
            let mut pages = 0;
            loop {
                let args = MatchesArgs {
                    store: store.clone(),
                    form: answer::Form::Json,
                    after: after.take(),
                    limit: 1,
                    single: true,
                    system_root: root.clone(),
                };
                let answer = read_with(&rules, &args, NOW).ok().unwrap();
                pages += 1;
                let c = answer.collector.as_ref().unwrap();
                let stopped: Vec<&str> = c
                    .no_longer_arriving
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect();
                assert_eq!(
                    (&c.not_kept, stopped),
                    (&said.0, said.1.clone()),
                    "{tag} page {pages}"
                );
                assert!(
                    c.arriving.iter().all(|a| a.name != "identity"),
                    "{tag} page {pages}: {:?}",
                    c.arriving
                );
                assert_eq!(answer.unevaluated.len(), said.2, "{tag} page {pages}");
                if !answer.more {
                    break;
                }
                let place = answer.continue_after.unwrap();
                after = Some((place.clone(), Place::parse(&place).unwrap()));
            }
            assert_eq!(pages, 6, "{tag}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A system root with the collector installed and established to record file events.
    fn installed_root(tag: &str) -> (crate::common::Scratch, std::path::PathBuf) {
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immunity-matches-{tag}-{}", std::process::id())),
        );
        let root = dir.join("root");
        std::fs::create_dir_all(root.join(events::LOG)).unwrap();
        let plist = root.join(events::PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let collects = r#"["/usr/bin/eslogger","exec","create","rename"]"#;
        std::fs::write(root.join(events::COLLECTS), collects).unwrap();
        (dir, root)
    }

    fn ask(
        rules: &Rules,
        store: &std::path::Path,
        root: &std::path::Path,
        after: Option<&str>,
    ) -> v1::Matches {
        let args = MatchesArgs {
            store: store.to_path_buf(),
            form: answer::Form::Json,
            after: after.map(|p| (p.to_string(), Place::parse(p).unwrap())),
            limit: LIMIT,
            single: false,
            system_root: root.to_path_buf(),
        };
        read_with(rules, &args, NOW).ok().unwrap()
    }

    /// `git status`, which no shipped rule matches, in the forms `dd` writes.
    fn git(seq: u64, form: &str) -> String {
        dd(seq, form)
            .replace(
                r#""args":["dd","if=/dev/zero","bs=1","count=1"]"#,
                r#""args":["git","status"]"#,
            )
            .replace(r#""path":"/bin/dd""#, r#""path":"/usr/bin/git""#)
    }

    /// Quiet as `matches.proto` defines it: nothing matched, and nothing says what was not seen.
    fn quiet(a: &v1::Matches) -> bool {
        let c = a.collector.as_ref().unwrap();
        let s = a.evaluated.as_ref().unwrap();
        a.matches.is_empty()
            && s.state == v1::EvaluatorState::Current as i32
            && c.state == v1::CollectorState::Running as i32
            && c.file_events_collected
            && s.program_starts > 0
            && s.program_starts_lost == 0
            && s.program_starts_unknown_losses == 0
            && s.file_events_lost == 0
            && s.file_events_unknown_losses == 0
            && s.unreadable_lines == 0
            && s.unreadable_file_events == 0
            && s.files_removed_unread == 0
            && !s.gone
            && a.unevaluated.is_empty()
    }

    /// The rule of `process_kept`, which reads the script, as `unevaluated` names it: why, and
    /// in which words.
    fn named(a: &v1::Matches) -> Vec<(i32, Option<&str>)> {
        a.unevaluated
            .iter()
            .map(|u| (u.reason, u.detail_text.as_deref()))
            .collect()
    }

    #[test]
    fn a_quiet_answer_rests_on_the_lines_counted_after_the_place_and_not_on_an_older_reading() {
        // No false calm. The core read while the later collector wrote, so the store says the
        // script arrives. Then lines of the earlier collector come into a file that sorts before
        // the file being written, which goes on: an answer whose counts hold them names the rule
        // that reads the script, since that rule was asked about none of them, while
        // `collector` goes on giving what the file being written says arrives. The same for a
        // file event without its signer and a rule that reads the signer. An answer over lines
        // that give it is quiet again: what is named is of the lines counted after the place.
        let rules = crate::sigma::testing::process_kept();
        let (dir, root) = installed_root("stale");
        let _watcher = watching(&dir);
        let later = "exec-20261004T000013-20261004T010000.jsonl";
        let text = git(1, "kept") + &git(2, "kept") + &created("kept");
        log_file(&root, later, &text, 300);
        let store = dir.join("store.db");
        core_reads(&store, &root);
        let first = ask(&rules, &store, &root, None);
        assert!(quiet(&first), "{first:?}");
        assert!(ask(&signer(), &store, &root, None).unevaluated.is_empty());
        let earlier = git(3, "old") + &git(4, "old") + &created("old");
        log_file(
            &root,
            "exec-20261004T000013-20261004T000000.jsonl",
            &earlier,
            400,
        );
        let text = text + &git(5, "kept");
        log_file(&root, later, &text, 60);
        let place = first.continue_after.clone().unwrap();
        // Lines the core has not read are in no answer, and the answer is not quiet over them.
        let unread = ask(&rules, &store, &root, Some(&place));
        assert!(!quiet(&unread));
        core_reads(&store, &root);
        let not_in_lines = [(
            v1::UnevaluatedReason::NotCollected as i32,
            Some(events::NOT_IN_LINES),
        )];
        let next = ask(&rules, &store, &root, Some(&place));
        let c = next.collector.as_ref().unwrap();
        let arriving: Vec<&str> = c.arriving.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(arriving, ["identity", "script", "signature"]);
        assert_eq!(c.status_read_at, Some(NOW));
        assert!(!quiet(&next));
        assert_eq!(named(&next), not_in_lines);
        let files = ask(&signer(), &store, &root, Some(&place));
        assert_eq!(named(&files), not_in_lines);
        // Each row of counts is given in one answer, so the earlier lines are behind a place once
        // an answer gave their row.
        let text = text + &git(6, "kept");
        log_file(&root, later, &text, 50);
        core_reads_at(&store, &root, NOW + 10);
        let place = ask(&rules, &store, &root, Some(&place))
            .continue_after
            .unwrap();
        let text = text + &git(7, "kept") + &git(8, "kept");
        log_file(&root, later, &text, 40);
        core_reads_at(&store, &root, NOW + 30);
        let after = ask(&rules, &store, &root, Some(&place));
        assert_eq!(after.evaluated.as_ref().unwrap().program_starts, 2);
        assert!(quiet(&after), "{:?}", after.unevaluated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `core_reads` at `at`: a reading of every whole line and a conclusion, as the evaluator
    /// `EVALUATOR` writes one.
    fn core_reads_at(store: &std::path::Path, root: &std::path::Path, at: i64) {
        let mut conn = crate::store::open_or_make(store).unwrap();
        let tx = conn.transaction().unwrap();
        crate::store::put_entity(&tx, "machine:mac").unwrap();
        let mut r = events::Reader::load(&tx, root).unwrap();
        r.by_evaluator(EVALUATOR);
        r.relist(at, u64::MAX, |_, _| {});
        r.write(&tx, "events-1", "machine:mac", at, true)
            .unwrap()
            .unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn a_group_filled_on_some_lines_by_nature_is_judged_by_the_core_s_latest_reading_alone() {
        // The limit as it stands, pinned so that a change that closes it has a test to turn
        // round. One start without a script cannot tell no script by nature from a field the
        // collector stopped filling, so only the evaluator's conclusion, counting its bound,
        // tells the second. Until it has counted 1,000 such starts of the file being written,
        // an answer is quiet over them; once it has, the rule that reads the script is named as
        // no longer watching. No shipped rule reads such a group
        // (`events::tests::every_kept_field_a_shipped_rule_reads_is_...`); the test set ties the
        // script to the working directory.
        let rules = crate::sigma::testing::process_kept();
        let (dir, root) = installed_root("script-null");
        let _watcher = watching(&dir);
        let text = git(1, "kept") + &git(2, "kept");
        let first = "exec-20261004T000013-20261004T000000.jsonl";
        log_file(&root, first, &text, 300);
        let store = dir.join("store.db");
        core_reads(&store, &root);
        let place = ask(&rules, &store, &root, None).continue_after.unwrap();
        let null = |seq: u64| {
            git(seq, "kept")
                .replace(
                    r#""script":{"path":"/Users/example/run.sh"}"#,
                    r#""script":null"#,
                )
                .replace(
                    r#""cwd":{"path":"/Users/example"}"#,
                    r#""cwd":{"path":"/tmp"}"#,
                )
        };
        assert!(null(3).contains(r#""script":null"#) && null(3).contains(r#""path":"/tmp""#));
        let second = "exec-20261004T000013-20261004T010000.jsonl";
        log_file(&root, second, &(3..503).map(null).collect::<String>(), 100);
        core_reads_at(&store, &root, NOW + 10);
        let before = ask(&rules, &store, &root, Some(&place));
        assert_eq!(before.evaluated.as_ref().unwrap().program_starts, 500);
        assert!(quiet(&before), "{:?}", before.unevaluated);
        log_file(&root, second, &(3..1503).map(null).collect::<String>(), 50);
        core_reads_at(&store, &root, NOW + 30);
        let after = ask(&rules, &store, &root, Some(&place));
        let stopped = &after.collector.as_ref().unwrap().no_longer_arriving;
        assert_eq!(
            stopped.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["script"]
        );
        assert_eq!(
            named(&after),
            [(v1::UnevaluatedReason::NotCollected as i32, Some(NO_LONGER))]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_event_whose_signer_is_null_or_absent_names_the_rule_that_reads_it_whatever_the_store_says()
     {
        // The signer of file events is filled on every line, so one line without it, null or
        // without its key, names the rule that reads it while the store says it arrives.
        let rules = signer();
        let signed = r#""signing_id":"com.example.tool""#;
        let null = created("kept").replace(signed, r#""signing_id":null"#);
        let absent = created("kept").replace(&format!(",{signed}"), "");
        for (what, line, why) in [("null", null, NO_LONGER), ("absent", absent, NOT_KEPT)] {
            let (dir, root) = installed_root(&format!("signer-{what}"));
            let text = git(1, "kept") + &created("kept");
            let name = "exec-20261004T000013-20261004T000000.jsonl";
            log_file(&root, name, &text, 300);
            let store = dir.join("store.db");
            core_reads(&store, &root);
            let first = ask(&rules, &store, &root, None);
            assert!(first.unevaluated.is_empty(), "{:?}", first.unevaluated);
            let place = first.continue_after.unwrap();
            assert!(!line.contains(signed), "{what}");
            log_file(&root, name, &(text + &git(3, "kept") + &line), 100);
            core_reads_at(&store, &root, NOW + 10);
            let a = ask(&rules, &store, &root, Some(&place));
            assert_eq!(a.evaluated.as_ref().unwrap().file_events, 1, "{what}");
            // The latest line, read by the core, says the signer no longer arrives, or is not
            // kept by the collector that wrote it.
            assert_eq!(
                named(&a),
                [(v1::UnevaluatedReason::NotCollected as i32, Some(why))],
                "{what}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    use crate::sigma::ELASTIC;

    /// One rule of Elastic's, about file events, that reads the signer of the program that acted.
    fn signer() -> Rules {
        let text = format!(
            "title: Invented\nid: 00000000-0000-4000-8000-000000000001\nstatus: test\n\
             level: high\nlogsource: {{\"product\": \"macos\", \"category\": \"file_event\"}}\n\
             detection:\n  s1: {{\"process.code_signature.signing_id|cased\": [\"com.example\"]}}\n  condition: s1\n{}",
            crate::sigma::testing::record_of(&ELASTIC, "\"high\"", "")
        );
        Rules::load_as(
            &ELASTIC,
            &[("signer.yml", Box::leak(text.into_boxed_str()))],
        )
    }

    #[test]
    fn a_rule_that_reads_what_does_not_arrive_is_handed_over_as_judging_nothing_with_which() {
        // The response layer reads a quiet queue as calm only for the rules that judge: a rule
        // that reads what no line gives a value for is listed, with the field and which of the
        // three it is, and is not once values arrive.
        let rules = signer();
        let on = Arrival::Kept(Some(1));
        let sig = |a| Arrivals::from([on, on, a, on, a]);
        for (state, why) in [
            (Arrival::NotKept, NOT_KEPT),
            (Arrival::Kept(None), NEVER_FILLED),
            (Arrival::Unknown, NOT_YET_KNOWN),
            (Arrival::NoLonger(1), NO_LONGER),
        ] {
            let listed = unevaluated(&rules, &Ok(()), Some(&sig(state)), None);
            assert_eq!(listed.len(), 1);
            assert_eq!(
                (
                    listed[0].reason,
                    listed[0].fields_text.clone(),
                    listed[0].detail_text.as_deref()
                ),
                (
                    v1::UnevaluatedReason::NotCollected as i32,
                    vec!["process.code_signature.signing_id".to_string()],
                    Some(why)
                )
            );
        }
        let identity = Arrivals::from([Arrival::NotKept, on, on, Arrival::NotKept, on]);
        assert!(unevaluated(&rules, &Ok(()), Some(&identity), None).is_empty());
        assert!(unevaluated(&rules, &Ok(()), Some(&sig(on)), None).is_empty());
    }

    #[test]
    fn the_queue_hands_over_a_rule_that_reads_what_its_lines_do_not_give_as_judging_nothing() {
        // The answer itself, not only its part: whether a rule judges is decided by what the
        // lines the core's reading read carry, never by a record. Before the core has read,
        // nothing is known; a log an earlier collector wrote lacks the field, a later
        // collector's carries it empty, and only a line that gives it a value lets the rule
        // judge; each is said in the collector's lists.
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immunity-matches-arrival-{}", std::process::id())),
        );
        let root = dir.join("root");
        std::fs::create_dir_all(root.join(events::LOG)).unwrap();
        let plist = root.join(events::PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let start = |seq: u64, extra: &str| {
            format!(
                r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/zsh"}}}},"event":{{"exec":{{"args":["git","status"],"cwd":{{"path":"/Users/example/dev/site"}},{extra}"target":{{"executable":{{"path":"/usr/bin/git"}},"audit_token":{{"pid":402,"euid":501}},"ppid":401,"signing_id":"com.apple.git","team_id":null,"is_platform_binary":true}}}}}}}}
"#
            )
        };
        let log = root.join(events::LOG).join("exec-20261004T00.jsonl");
        // A program start as an earlier collector wrote it: no script, no start time.
        std::fs::write(&log, start(1, "")).unwrap();
        drop(crate::store::open_or_make(&dir.join("store.db")).unwrap());
        let core = || core_reads(&dir.join("store.db"), &root);
        let args = MatchesArgs {
            store: dir.join("store.db"),
            form: answer::Form::Json,
            after: None,
            limit: LIMIT,
            single: false,
            system_root: root.clone(),
        };
        let rules = crate::sigma::testing::process_kept();
        let unevaluated_why = |answer: &v1::Matches| {
            assert_eq!(answer.unevaluated.len(), 1, "{:?}", answer.unevaluated);
            let u = &answer.unevaluated[0];
            assert_eq!(
                (u.reason, u.fields_text.clone()),
                (
                    v1::UnevaluatedReason::NotCollected as i32,
                    vec!["process.working_directory".to_string()],
                )
            );
            u.detail_text.clone()
        };
        let answer = read_with(&rules, &args, NOW).ok().unwrap();
        let c = answer.collector.as_ref().unwrap();
        assert_eq!(c.not_yet_known, ["identity", "script", "signature"]);
        assert!(c.not_kept.is_empty() && c.arriving.is_empty());
        assert_eq!(unevaluated_why(&answer).as_deref(), Some(NOT_YET_KNOWN));
        core();
        let answer = read_with(&rules, &args, NOW).ok().unwrap();
        let c = answer.collector.as_ref().unwrap();
        assert_eq!(c.not_kept, ["identity", "script", "signature"]);
        assert!(c.kept_never_filled.is_empty() && c.arriving.is_empty());
        assert_eq!(unevaluated_why(&answer).as_deref(), Some(NOT_KEPT));
        // A later collector's line that carries the script empty: kept, never filled.
        std::fs::write(&log, start(1, "") + &start(2, r#""script":null,"#)).unwrap();
        core();
        let answer = read_with(&rules, &args, NOW).ok().unwrap();
        assert_eq!(
            answer.collector.as_ref().unwrap().kept_never_filled,
            ["script"]
        );
        assert_eq!(unevaluated_why(&answer).as_deref(), Some(NEVER_FILLED));
        // A line that gives it a value: it arrives, since that line, and the rule judges.
        std::fs::write(
            &log,
            start(1, "")
                + &start(2, r#""script":null,"#)
                + &start(3, r#""script":{"path":"/Users/example/x.sh"},"#),
        )
        .unwrap();
        core();
        let answer = read_with(&rules, &args, NOW).ok().unwrap();
        assert_eq!(
            answer.collector.as_ref().unwrap().arriving,
            [v1::Arriving {
                name: "script".into(),
                since: 1_791_072_002
            }]
        );
        // The counts of this answer hold the earlier collector's start too, which the rule was
        // not asked about, and it says so.
        assert_eq!(
            unevaluated_why(&answer).as_deref(),
            Some(events::NOT_IN_LINES)
        );
        // With no collector the state says nothing is judged, and no rule about program
        // starts is put down to what a collector that is not there keeps.
        std::fs::remove_file(&plist).unwrap();
        core();
        let answer = read_with(&rules, &args, NOW).ok().unwrap();
        assert_eq!(
            answer.collector.as_ref().unwrap().state,
            v1::CollectorState::NotInstalled as i32
        );
        assert!(answer.unevaluated.is_empty(), "{:?}", answer.unevaluated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store holding the core's reading of one line under a root installed for `tag`, and
    /// what `immunity matches` is asked of it.
    fn one_line(tag: &str) -> (crate::common::Scratch, MatchesArgs) {
        let (dir, root) = installed_root(tag);
        log_file(
            &root,
            "exec-20261004T00.jsonl",
            &(dd(1, "kept") + &git(2, "kept")),
            10,
        );
        let store = dir.join("store.db");
        core_reads(&store, &root);
        let args = MatchesArgs {
            store,
            form: answer::Form::Json,
            after: None,
            limit: LIMIT,
            single: false,
            system_root: root,
        };
        (dir, args)
    }

    /// A reading of program starts the watcher failed is named among the readings that failed in
    /// `not_covered`, and `immunity matches` gives the state of the event level `immunity status`
    /// gives for the same store and lock file: failed then, running before.
    #[test]
    fn a_failed_reading_of_program_starts_by_the_watcher_is_named_and_matches_gives_the_status_state()
     {
        let (dir, args) = one_line("watcher-failed");
        let now = 1_791_090_010;
        let lock = store::lock_watch(&dir).unwrap().unwrap();
        let text = format!("1791000000\nheartbeat {EVALUATOR}\nready");
        std::fs::write(dir.join(store::WATCH_LOCK), text).unwrap();
        let said = || {
            let state = read_with(Rules::shipped(), &args, now);
            let state = state.ok().unwrap().collector.unwrap().status_state;
            let status = store::read(&args.store, |tx| {
                let st = crate::status::state(tx, &dir, now)?;
                crate::status::message(Some(tx), Some(&st), false, &args.store, now)
            });
            let status = status.unwrap();
            let failed = status.not_covered.iter().find(|u| {
                u.id == crate::covered::READING_FAILED.id
                    && u.examples
                        .iter()
                        .any(|e| e.reason_text.as_deref() == Some("invented"))
            });
            (
                state,
                Some(status.event_level.unwrap().state),
                failed.is_some(),
            )
        };
        let running = Some(v1::CollectorState::Running as i32);
        assert_eq!(said(), (running, running, false));
        store::open(&args.store)
            .unwrap()
            .execute(
                "INSERT INTO watcher_failed (what, at, detail) VALUES ('events', ?1, 'invented')",
                [now - 5],
            )
            .unwrap();
        let failed = Some(v1::CollectorState::Failed as i32);
        assert_eq!(said(), (failed, failed, true));
        drop(lock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The watcher's failed reading makes failed only a level the store says runs: a level that
    /// records nothing keeps its own state and words. A failed reading, the watcher's or the
    /// store's own, is named once among the readings that failed, in place of this Mac's row of
    /// program starts or with none there. File events not collected stay named, by what the
    /// store says of the level and since its reading, beside the failure.
    #[test]
    fn a_level_is_served_failed_only_over_running_and_its_failure_is_named_once_with_or_without_a_row()
     {
        let dir = crate::common::Scratch::new("matches-served");
        let conn = store::open_or_make(&dir.join("store.db")).unwrap();
        let watcher = [crate::watch::Failure {
            what: crate::watch::EVENTS.to_string(),
            at: 5,
            detail: "invented".to_string(),
        }];
        let put = |state: &str| {
            let sql = "INSERT OR REPLACE INTO event_level (id, read_at, state) VALUES (1, 1, ?1)";
            conn.execute(sql, [state]).unwrap();
            events::served(&conn, &watcher, 10).unwrap().unwrap()
        };
        assert_eq!(put(events::SILENT).state, events::SILENT);
        let own = put(events::FAILED);
        let failed = put(events::RUNNING);
        assert_eq!((failed.state.as_str(), failed.read_at), (events::FAILED, 5));
        let row = |scope: &str, completeness: &str| crate::covered::Latest {
            reader: events::READER.to_string(),
            scope: scope.to_string(),
            kind: events::KIND.to_string(),
            completeness: completeness.to_string(),
            reason: None,
            cause: None,
            at: 1,
            last_full: Some(1),
            ..Default::default()
        };
        let this = Some("machine:mac");
        // Each row as (scope, completeness, at).
        let served = |level: &events::Level, rows: &[crate::covered::Latest]| {
            let rows = events::served_readings(Some(level), rows, this);
            let told = rows
                .iter()
                .map(|r| (r.scope.clone(), r.completeness.clone(), r.at));
            told.collect::<Vec<_>>()
        };
        let other = || row("machine:other", "full");
        let failure = ("machine:mac".to_string(), "none".to_string(), 5);
        let kept = ("machine:other".to_string(), "full".to_string(), 1);
        let mine = [other(), row("machine:mac", "full")];
        assert_eq!(served(&failed, &mine), [kept.clone(), failure.clone()]);
        assert_eq!(served(&failed, &[other()]), [kept.clone(), failure]);
        // A level whose own reading failed is named once too, with its row or without.
        let failed_row = [row("machine:mac", "none")];
        let own_failure = ("machine:mac".to_string(), "none".to_string(), 1);
        assert_eq!(
            served(&own, &failed_row),
            std::slice::from_ref(&own_failure)
        );
        assert_eq!(served(&own, &[]), std::slice::from_ref(&own_failure));
        // A row that failed already says it with its own reason and is kept, the watcher's
        // failure not put in its place.
        let mut said = row("machine:mac", "none");
        said.cause = Some(crate::store::Cause::Failed.literal().to_string());
        assert_eq!(served(&failed, &[said]), std::slice::from_ref(&own_failure));
        // With no row at all in a store that does not know its Mac yet, there is no scope to
        // name the failure under, so it is not filed under another machine: the level and the
        // headline say it. File events not collected are listed.
        let p = crate::status::problems(&conn, &[]).unwrap();
        let items = crate::covered::not_covered(&conn, &[], &p, None, Some(&failed)).unwrap();
        let ids: Vec<&str> = items.iter().map(|u| u.cause.id).collect();
        assert!(!ids.contains(&crate::covered::READING_FAILED.id), "{ids:?}");
        let files = items
            .iter()
            .find(|u| u.cause.id == crate::covered::FILES_NOT_COLLECTED.id);
        // Since the store's reading, not the watcher's failure.
        assert_eq!(files.map(|u| u.since), Some(Some(1)), "{ids:?}");
    }

    /// A log file of one run of the collector.
    const NAME: &str = "exec-20261004T000013-20261004T000000.jsonl";

    /// `sw_vers -productVersion`, which a rule marked medium matches, in the forms `dd` writes.
    fn sw_vers(seq: u64) -> String {
        git(seq, "kept")
            .replace(
                r#""args":["git","status"]"#,
                r#""args":["sw_vers","-productVersion"]"#,
            )
            .replace(r#""path":"/usr/bin/git""#, r#""path":"/usr/bin/sw_vers""#)
    }

    /// A store in which the core read a log of a match of a high rule, a match of a medium one and
    /// a start nothing matches, under a collector that records file events, with a watcher
    /// started before that reading.
    fn scene(tag: &str) -> (crate::common::Scratch, std::path::PathBuf, std::fs::File) {
        let (dir, root) = installed_root(tag);
        let watcher = watching(&dir);
        let text = dd(1, "kept") + &sw_vers(2) + &git(3, "kept") + &created("kept");
        log_file(&root, NAME, &text, 300);
        core_reads(&dir.join("store.db"), &root);
        (dir, root, watcher)
    }

    fn asked(
        dir: &std::path::Path,
        root: &std::path::Path,
        after: Option<&str>,
        limit: usize,
        now: i64,
    ) -> v1::Matches {
        let args = MatchesArgs {
            store: dir.join("store.db"),
            form: answer::Form::Json,
            after: after.map(|p| (p.to_string(), Place::parse(p).unwrap())),
            limit,
            single: false,
            system_root: root.to_path_buf(),
        };
        read(&args, now).ok().unwrap()
    }

    fn evaluator_of(a: &v1::Matches) -> (v1::EvaluatorState, v1::BehindReason) {
        let e = a.evaluated.as_ref().unwrap();
        (e.state(), e.behind())
    }

    #[test]
    fn a_place_is_taken_back_only_as_this_build_printed_it() {
        // `--after` comes from a caller. Only the text the core printed is taken: anything else,
        // a place of an earlier encoding among it, is refused as a misuse.
        let id = "0123456789abcdef0123456789abcdef";
        let place = Place::of(id, 4_000_000, &[17; events::TOTALS]).unwrap();
        let text = place.to_string();
        assert_eq!(Place::parse(&text), Some(place));
        assert!(text.len() < 128, "{text}");
        let hex = |numbers: &[u64]| -> String {
            let mut bytes = Vec::new();
            numbers
                .iter()
                .for_each(|n| prost::encoding::encode_varint(*n, &mut bytes));
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        };
        let mut numbers = vec![PLACE_VERSION];
        numbers.extend([0u64; 16]);
        numbers.push(5);
        numbers.extend([7; events::TOTALS]);
        assert!(Place::parse(&hex(&numbers)).is_some());
        let mut version_3 = numbers.clone();
        version_3[0] = 3;
        let mut wide = numbers.clone();
        wide[1] = 256;
        for bad in [
            String::new(),
            text.to_uppercase(),
            format!("{text}00"),
            text[..text.len() - 2].to_string(),
            format!(" {text}"),
            hex(&version_3),
            hex(&wide),
            hex(&numbers[..18]),
            // The same numbers in a longer varint: one place, one text.
            format!("84{}", &hex(&numbers)[2..]).replacen("84", "8400", 1),
            "0".repeat(20_000),
        ] {
            assert_eq!(Place::parse(&bad), None, "{bad}");
        }
    }

    #[test]
    fn a_place_from_another_store_or_past_what_this_store_gave_is_refused() {
        // A place printed for another store, or for this one before it was made again, would
        // read on from a number that means nothing here: refused, never an empty answer. So is
        // one whose totals are past the store's, or whose numbers do not fit the store's.
        let (dir, root, _w) = scene("place-other");
        let first = asked(&dir, &root, None, LIMIT, NOW);
        let id = first.store_id.clone().unwrap();
        let totals = events::totals(&store::open(&dir.join("store.db")).unwrap()).unwrap();
        let mut past = totals;
        past[3] += 1;
        let mut wrapped = Place::of(&id, 2, &totals).unwrap();
        wrapped.seq = u64::MAX;
        let mut wrapped_total = Place::of(&id, 2, &totals).unwrap();
        wrapped_total.totals[0] = u64::MAX;
        let other = "f".repeat(32);
        let args = |p: Place| MatchesArgs {
            store: dir.join("store.db"),
            form: answer::Form::Json,
            after: Some((p.to_string(), p)),
            limit: LIMIT,
            single: false,
            system_root: root.clone(),
        };
        for p in [
            Place::of(&other, 0, &totals).unwrap(),
            Place::of(&id, 99, &totals).unwrap(),
            Place::of(&id, 0, &past).unwrap(),
            wrapped,
            wrapped_total,
        ] {
            assert!(matches!(read(&args(p), NOW), Err(Failure::Place)), "{p:?}");
        }
        assert!(read(&args(Place::of(&id, 2, &totals).unwrap()), NOW).is_ok());
    }

    #[test]
    fn a_limit_past_what_the_record_can_hold_gives_every_match_and_never_wraps() {
        // `--limit` is the caller's: the largest number it takes is capped before any sum, so an
        // answer never skips the record as one of no matches.
        let (dir, root, _w) = scene("limit-wraps");
        let mut options = answer::Options::default();
        let given = ["--limit", "18446744073709551615", "--system-root"].map(String::from);
        let it = given.into_iter().chain([root.display().to_string()]);
        let mut args = parse(it, &mut options).unwrap();
        args.store = dir.join("store.db");
        let a = read(&args, NOW).ok().unwrap();
        assert_eq!((a.matches.len(), a.more), (2, false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_match_of_every_level_is_given_once_in_the_order_recorded_and_pages_miss_none() {
        // The record holds a row for every match of every rule, high or not; an answer gives
        // them in the order they were recorded, each once, however it is paged, and says what
        // each raised.
        let (dir, root, _w) = scene("every-level");
        let whole = asked(&dir, &root, None, LIMIT, NOW);
        let said = |a: &v1::Matches| -> Vec<(String, String, i32)> {
            let rule = |m: &v1::RuleMatch| m.rule.as_ref().unwrap().name.clone();
            a.matches
                .iter()
                .map(|m| (m.position.clone(), rule(m), m.raised))
                .collect()
        };
        let all = said(&whole);
        assert_eq!(all.len(), 2, "{all:?}");
        assert_eq!(all[0].2, v1::Raised::Finding as i32);
        assert_eq!(all[1].2, v1::Raised::BelowHigh as i32);
        assert!(
            whole.matches[0].findings.len() == 1 && whole.matches.iter().all(|m| m.event.is_some())
        );
        assert!(!whole.more);
        let (mut paged, mut after) = (Vec::new(), None::<String>);
        for _ in 0..10 {
            let page = asked(&dir, &root, after.as_deref(), 1, NOW);
            paged.extend(said(&page));
            after = page.continue_after.clone();
            if !page.more {
                break;
            }
        }
        assert_eq!(paged, all);
        // Read on from the last place: nothing new, and nothing again.
        assert!(
            asked(&dir, &root, after.as_deref(), LIMIT, NOW)
                .matches
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_a_watcher_current_and_nothing_lost_an_answer_with_no_match_is_quiet() {
        // The other side of every case below: quiet is reachable, so its tests test something.
        let (dir, root, _w) = scene("quiet");
        let place = asked(&dir, &root, None, LIMIT, NOW).continue_after;
        let text =
            dd(1, "kept") + &sw_vers(2) + &git(3, "kept") + &created("kept") + &git(4, "kept");
        log_file(&root, NAME, &text, 200);
        core_reads_at(&dir.join("store.db"), &root, NOW + 10);
        let place = asked(&dir, &root, place.as_deref(), LIMIT, NOW + 10).continue_after;
        log_file(&root, NAME, &(text + &git(5, "kept")), 100);
        core_reads_at(&dir.join("store.db"), &root, NOW + 20);
        // Over rules that all judge here, so that `unevaluated` is empty.
        let args = MatchesArgs {
            store: dir.join("store.db"),
            form: answer::Form::Json,
            after: place
                .as_deref()
                .map(|p| (p.to_string(), Place::parse(p).unwrap())),
            limit: LIMIT,
            single: false,
            system_root: root.clone(),
        };
        let rules = crate::sigma::testing::process_kept();
        let a = read_with(&rules, &args, NOW + 20).ok().unwrap();
        assert_eq!(evaluator_of(&a).0, v1::EvaluatorState::Current);
        assert!(quiet(&a), "{a:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_no_watcher_an_answer_is_behind_and_never_quiet() {
        // No watcher reads the log, so lines written since the latest full check are read by
        // none: an answer says so, and a reader built before `evaluated` sees the collector not
        // running.
        let (dir, root, w) = scene("no-watcher");
        drop(w);
        let a = asked(&dir, &root, None, LIMIT, NOW);
        assert_eq!(
            evaluator_of(&a),
            (v1::EvaluatorState::Behind, v1::BehindReason::NoWatcher)
        );
        assert_eq!(
            a.collector.unwrap().state,
            v1::CollectorState::Behind as i32
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_watcher_whose_evaluator_did_not_write_last_or_left_lines_to_read_is_catching_up() {
        // Current rests on the evaluator's own writes: another evaluator wrote last, as after a
        // restart of the watcher in the same second, or of the evaluator's thread under an old
        // start time; or its last write left lines to read. Either way, behind.
        let (dir, root, w) = scene("catching-up");
        drop(w);
        let _lock = store::lock_watch(&dir).unwrap().unwrap();
        let lock = |evaluator: &str| {
            let text = format!("1791000000\nheartbeat{evaluator}\nready");
            std::fs::write(dir.join(store::WATCH_LOCK), text).unwrap();
        };
        let behind = (v1::EvaluatorState::Behind, v1::BehindReason::CatchingUp);
        for other in ["", " 8"] {
            lock(other);
            let a = asked(&dir, &root, None, LIMIT, NOW);
            assert_eq!(evaluator_of(&a), behind, "{other:?}");
            assert!(!quiet(&a));
        }
        lock(&format!(" {EVALUATOR}"));
        assert_eq!(
            evaluator_of(&asked(&dir, &root, None, LIMIT, NOW)).0,
            v1::EvaluatorState::Current
        );
        // A new evaluator whose write left lines to read is behind, and current once it wrote the
        // rest; then a backlog comes, and its first write is behind again, however fresh.
        lock(" 9");
        let mut conn = store::open(&dir.join("store.db")).unwrap();
        let mut r = events::Reader::load(&conn, &root).unwrap();
        r.by_evaluator(9);
        let more = [(1, behind.0), (u64::MAX, v1::EvaluatorState::Current)];
        let mut text = dd(1, "kept") + &sw_vers(2) + &git(3, "kept") + &created("kept");
        for (i, (budget, want)) in more.iter().chain(&more).copied().enumerate() {
            if i % 2 == 0 {
                text += &(sw_vers(4 + i as u64 * 2) + &sw_vers(5 + i as u64 * 2));
                log_file(&root, NAME, &text, 0);
            }
            r.relist(NOW, budget, |_, _| {});
            let tx = conn.transaction().unwrap();
            r.write(&tx, "events-1", "machine:mac", NOW, false)
                .unwrap()
                .unwrap();
            tx.commit().unwrap();
            r.wrote();
            let a = asked(&dir, &root, None, LIMIT, NOW);
            assert_eq!(evaluator_of(&a).0, want, "{budget}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_installed_collector_whose_log_folder_is_gone_or_cannot_be_listed_is_failed_at_the_answer()
    {
        use std::os::unix::fs::PermissionsExt;
        // The answer looks at the source itself, never only at the last conclusion: the launch
        // daemon is there and its log folder cannot be listed, or is not there at all, so the
        // collector failed, whatever the store says. Past every match, so that the answer reads no
        // line again.
        for gone in [false, true] {
            let (dir, root, _w) = scene(&format!("unlisted-{gone}"));
            let place = asked(&dir, &root, None, LIMIT, NOW).continue_after;
            let log = root.join(events::LOG);
            match gone {
                true => std::fs::remove_dir_all(&log).unwrap(),
                false => {
                    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o000)).unwrap()
                }
            }
            let a = asked(&dir, &root, place.as_deref(), LIMIT, NOW);
            if !gone {
                std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            assert_eq!(evaluator_of(&a).0, v1::EvaluatorState::Failed, "{gone}");
            assert!(a.evaluated.as_ref().unwrap().reason_text.is_some());
            assert_eq!(
                a.collector.as_ref().unwrap().state,
                v1::CollectorState::Failed as i32
            );
            assert!(!quiet(&a));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_collector_uninstalled_since_the_last_conclusion_is_not_installed_at_the_next_answer() {
        // Its launch daemon is gone: the answer says so at once, and the rules for file events
        // judge nothing, whatever the last conclusion said.
        let (dir, root, _w) = scene("uninstalled-since");
        std::fs::remove_file(root.join(events::PLIST)).unwrap();
        let a = asked(&dir, &root, None, LIMIT, NOW);
        assert_eq!(
            a.collector.as_ref().unwrap().state,
            v1::CollectorState::NotInstalled as i32
        );
        assert!(
            a.unevaluated
                .iter()
                .any(|u| u.detail_text.as_deref() == Some(NOT_INSTALLED))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_refusal_the_collector_wrote_since_the_last_conclusion_is_seen_at_the_next_answer() {
        // The collector's state is judged from its own files at every answer: eslogger refused
        // after the evaluator last concluded, and the answer says so at once with what it printed,
        // never running until the next conclusion.
        let (dir, root, _w) = scene("refused-since");
        let said = root.join(events::LOG).join(events::ESLOGGER_SAID);
        std::fs::write(&said, "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED\n").unwrap();
        let a = asked(&dir, &root, None, LIMIT, NOW);
        let c = a.collector.as_ref().unwrap();
        assert_eq!(
            (c.state, c.said_by.as_deref()),
            (v1::CollectorState::Refused as i32, Some("eslogger"))
        );
        assert!(!quiet(&a));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_line_waiting_past_the_evaluator_s_place_is_behind_once_it_was_silent_past_the_bound_however_fresh_the_files()
     {
        // No false calm. A whole line waits past where the evaluator read, and the evaluator has
        // not written since: a full check holds the store, or it stalled. The log's files can be
        // written a moment ago, again and again, by lines after it: what counts is how long the
        // evaluator has been silent, never when a file was last written.
        let (dir, root, _w) = scene("stalled");
        let text =
            dd(1, "kept") + &sw_vers(2) + &git(3, "kept") + &created("kept") + &dd(4, "kept");
        log_file(&root, NAME, &text, 0);
        let late = NOW + LATE + 1;
        let a = asked(&dir, &root, None, LIMIT, late);
        assert_eq!(
            evaluator_of(&a),
            (v1::EvaluatorState::Behind, v1::BehindReason::NotAdvancing)
        );
        // Silent for no more than the bound, it is current; a line not yet whole waits for none.
        assert_eq!(
            evaluator_of(&asked(&dir, &root, None, LIMIT, NOW + LATE)).0,
            v1::EvaluatorState::Current
        );
        log_file(&root, NAME, &(text.clone() + "{\"schema"), 0);
        core_reads_at(&dir.join("store.db"), &root, NOW);
        assert_eq!(
            evaluator_of(&asked(&dir, &root, None, LIMIT, late)).0,
            v1::EvaluatorState::Current
        );
        // A file put in place of the one read, shorter than where that was read to, holds its
        // lines from its start.
        std::fs::remove_file(root.join(events::LOG).join(NAME)).unwrap();
        log_file(&root, NAME, &dd(9, "kept"), 0);
        assert_eq!(
            evaluator_of(&asked(&dir, &root, None, LIMIT, late)),
            (v1::EvaluatorState::Behind, v1::BehindReason::NotAdvancing)
        );
        log_file(&root, NAME, &(text + &dd(5, "kept")), 0);
        std::fs::create_dir_all(dir.join(crate::osv::FOLDER)).unwrap();
        let _check = crate::osv::lock_check(&dir, "run-1").unwrap();
        let conn = store::open(&dir.join("store.db")).unwrap();
        store::journal_note(&conn, NOW, "run-1", "run_started", "").unwrap();
        let a = asked(&dir, &root, None, LIMIT, late);
        assert_eq!(
            evaluator_of(&a),
            (v1::EvaluatorState::Behind, v1::BehindReason::StoreHeld)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_reading_is_failed_with_its_reason_and_the_collector_failed() {
        let (dir, root, _w) = scene("failed");
        let conn = store::open(&dir.join("store.db")).unwrap();
        conn.execute(
            "INSERT INTO watcher_failed (what, at, detail) VALUES ('events', ?1, 'invented')",
            [NOW],
        )
        .unwrap();
        let a = asked(&dir, &root, None, LIMIT, NOW);
        assert_eq!(evaluator_of(&a).0, v1::EvaluatorState::Failed);
        assert_eq!(
            a.evaluated.as_ref().unwrap().reason_text.as_deref(),
            Some("invented")
        );
        assert_eq!(
            a.collector.unwrap().state,
            v1::CollectorState::Failed as i32
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rows_that_went_with_their_file_past_the_caller_s_place_are_told_gone() {
        // The caller's place is before two matches; their file leaves the log before it asks:
        // the answer gives nothing of them and says rows are gone, never a quiet empty answer.
        // The file was read to its end with its hour over, so a caller given them lost nothing.
        let (dir, root, _w) = scene("rows-gone");
        let conn = store::open(&dir.join("store.db")).unwrap();
        let id = store::id(&conn).unwrap();
        let totals = events::totals(&conn).unwrap();
        let before = Place::of(&id, 0, &totals).unwrap().to_string();
        let later = "exec-20261004T000013-20261004T010000.jsonl";
        log_file(&root, later, &git(5, "kept"), 100);
        core_reads_at(&dir.join("store.db"), &root, NOW + 5);
        let totals = events::totals(&conn).unwrap();
        std::fs::remove_file(root.join(events::LOG).join(NAME)).unwrap();
        core_reads_at(&dir.join("store.db"), &root, NOW + 10);
        let a = asked(&dir, &root, Some(&before), LIMIT, NOW + 10);
        assert!(a.matches.is_empty());
        assert!(a.evaluated.as_ref().unwrap().gone);
        assert!(!quiet(&a));
        assert_eq!(
            a.collector.unwrap().state,
            v1::CollectorState::Behind as i32
        );
        // A caller that had been given them is told nothing is gone.
        let given = Place::of(&id, 2, &totals).unwrap().to_string();
        assert!(
            !asked(&dir, &root, Some(&given), LIMIT, NOW + 10)
                .evaluated
                .unwrap()
                .gone
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_listed_match_whose_line_cannot_be_read_again_is_given_without_its_event_and_gone() {
        // The file left the log after the record was read and before its line: the match is
        // still given, by its position and rule, with no event, and the answer says so.
        let (dir, root, _w) = scene("line-gone");
        std::fs::write(root.join(events::LOG).join(NAME), "").unwrap();
        let a = asked(&dir, &root, None, LIMIT, NOW);
        assert_eq!(a.matches.len(), 2);
        assert!(a.matches.iter().all(|m| m.event.is_none()));
        assert!(a.evaluated.as_ref().unwrap().gone);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn counts_come_from_totals_that_only_grow_so_answers_read_on_add_up_whatever_the_rows_and_the_clock()
     {
        // Answers read on one from another add up to the lines read, none twice and none left
        // out. A row of counts aged out, or written under a clock set back, takes nothing from
        // what an answer gives: the totals only grow, and a place holds the totals it reached.
        let (dir, root, _w) = scene("totals");
        let store = dir.join("store.db");
        let starts = |a: &v1::Matches| a.evaluated.as_ref().unwrap().program_starts;
        let first = asked(&dir, &root, None, LIMIT, NOW);
        let text = dd(1, "kept") + &sw_vers(2) + &git(3, "kept") + &created("kept");
        // Read while the clock is ahead, then with it set back, a line that cannot be read.
        log_file(&root, NAME, &(text.clone() + &git(4, "kept")), 200);
        core_reads_at(&store, &root, NOW + 3600);
        log_file(&root, NAME, &(text + &git(4, "kept") + "not a line\n"), 100);
        core_reads_at(&store, &root, NOW);
        let conn = store::open(&store).unwrap();
        conn.execute("DELETE FROM event_count WHERE at < ?1", [NOW + 1])
            .unwrap();
        let second = asked(&dir, &root, first.continue_after.as_deref(), LIMIT, NOW);
        let e = second.evaluated.as_ref().unwrap();
        assert_eq!((e.program_starts, e.unreadable_lines), (1, 1));
        assert!(!e.gone);
        let third = asked(&dir, &root, second.continue_after.as_deref(), LIMIT, NOW);
        assert_eq!(starts(&third), 0);
        assert_eq!(starts(&first) + starts(&second), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
