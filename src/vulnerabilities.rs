//! Matching: what the projects' lockfiles declare against the open vulnerability data of their
//! ecosystem (`osv.rs`), with the four answers of docs/threats.md.
//!
//! A match is the OSV schema's own `IsVulnerable`, in the order of the ecosystem's versions
//! (SemVer for npm and crates.io, PEP 440 for PyPI), on an entry from the ecosystem's public
//! registry only. Versions are parsed strictly and never coerced. Whatever cannot be compared is
//! "don't know" with its reason from a closed list, never "not affected": an entry not from the
//! registry, a version or a range its ecosystem's scheme does not read, a release
//! above a record's `last_affected` with no fix, a lockfile reading that is partial or old, a
//! feed that is not current. "Affects me" wins over every reason.
//!
//! The answers are computed by every run and kept, each with what it rests on: the lockfile
//! and line, the record with its `modified`, the feed reading and its time. An answer that
//! changes between runs keeps the one before in `vulnerability_answer_past`, so the change can
//! be seen later; no event is made of it in this version.
//!
//! Text from a record is the feed's, partly written by anyone: it is returned only in `_text`
//! fields and escaped wherever it is shown, always with the record's id and its source.

use crate::contract::v1;
use crate::known::whole;
use crate::lockfiles::Source;
use crate::osv::{FEEDS, Feed};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// The tables of the answers, part of the store's schema (`store::schema`).
pub const SCHEMA: &str = "
-- One answer per advisory, checkout and package the checkout's lockfiles hold, as the latest
-- run gave it.
CREATE TABLE vulnerability_answer (
    checkout   TEXT NOT NULL,      -- the checkout's entity id
    ecosystem  TEXT NOT NULL,
    package    TEXT NOT NULL,      -- the package's name in the registry
    source     TEXT NOT NULL,      -- the feed, such as 'osv-npm'
    advisory   TEXT NOT NULL,
    modified   TEXT NOT NULL,      -- the record's `modified` the answer rests on
    answer     TEXT NOT NULL CHECK (answer IN ('affected', 'unknown', 'not_affected')),
    -- unknown: one of the closed list of reasons; not_affected: 'fixed' or 'not_in_range'
    reason     TEXT NOT NULL,
    detail     TEXT NOT NULL,      -- in the program's words
    entries    TEXT NOT NULL,      -- JSON: [{version, at, from, affected}], at as the lockfile's line
    fixed      TEXT NOT NULL,      -- JSON: the releases the record names as fixing it here
    reading    INTEGER,            -- the feed_reading the data rests on
    read_at    INTEGER,            -- when that reading was made, UTC seconds
    since_run  TEXT NOT NULL,      -- when this answer began
    since_at   INTEGER NOT NULL,
    run_id     TEXT NOT NULL,      -- the run that last gave it
    at         INTEGER NOT NULL,
    PRIMARY KEY (checkout, ecosystem, package, source, advisory)
);
-- An answer that changed or went, with when it stopped holding.
CREATE TABLE vulnerability_answer_past (
    checkout   TEXT NOT NULL,
    ecosystem  TEXT NOT NULL,
    package    TEXT NOT NULL,
    source     TEXT NOT NULL,
    advisory   TEXT NOT NULL,
    modified   TEXT NOT NULL,
    answer     TEXT NOT NULL,
    reason     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    entries    TEXT NOT NULL,
    fixed      TEXT NOT NULL,
    reading    INTEGER,
    read_at    INTEGER,
    since_run  TEXT NOT NULL,
    since_at   INTEGER NOT NULL,
    run_id     TEXT NOT NULL,
    at         INTEGER NOT NULL,
    until_run  TEXT NOT NULL,
    until_at   INTEGER NOT NULL
);
-- One row per checkout and matched ecosystem: whether the conditions for 'does not affect me,
-- known for certain' hold there, so the answer for any advisory is derived on demand.
CREATE TABLE vulnerability_place (
    checkout        TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    lockfiles       TEXT NOT NULL CHECK (lockfiles IN ('full', 'partial', 'not_read')),
    lockfiles_why   TEXT,
    feed            TEXT NOT NULL CHECK (feed IN ('current', 'not_current')),
    feed_why        TEXT,
    reading         INTEGER,
    read_at         INTEGER,
    run_id          TEXT NOT NULL,
    at              INTEGER NOT NULL,
    PRIMARY KEY (checkout, ecosystem)
);
-- The catalogue's exploited CVEs that records of the data are linked to through aliases.
CREATE TABLE vulnerability_linked (
    cve       TEXT NOT NULL,
    source    TEXT NOT NULL,
    advisory  TEXT NOT NULL,
    PRIMARY KEY (cve, source, advisory)
);
";

// ---- Why an answer is "don't know": a closed list. ----

/// The lockfile reading is missing, not from the latest check, or partial for this ecosystem.
pub const PLACE_NOT_READ: &str = "place_not_read";
/// The data set was not read whole within its limit, or its newest change is old.
pub const FEED_NOT_READ: &str = "feed_not_read";
/// An entry's version, or the record's range or versions, is not read by the ecosystem's scheme.
pub const NOT_COMPARABLE: &str = "version_cannot_be_compared";
/// Git, a path or a file, a link, or another registry.
pub const NOT_FROM_REGISTRY: &str = "not_from_registry";
/// The release is above the record's `last_affected`, and no fix is named.
pub const NOT_COVERED: &str = "data_does_not_cover_this_version";
/// The release was compared and the record does not hold it, but the lockfile does not record
/// which index the package comes from (`Source::UnrecordedIndex`).
pub const INDEX_NOT_RECORDED: &str = "index_not_recorded";
/// An ecosystem for which no data set is fetched.
pub const NO_MATCHER: &str = "no_matcher";

/// Every reason, in the order one answer takes the first that applies: what is wrong with the
/// entry before what is wrong with the place, and the feed last. Of the entry's reasons,
/// `index_not_recorded` is last: it is the only one given after the release was compared and
/// found outside the record, so a reason that left a release not compared at all says more of
/// what is missing and comes before it.
pub const REASONS: [&str; 7] = [
    NOT_FROM_REGISTRY,
    NOT_COMPARABLE,
    NOT_COVERED,
    INDEX_NOT_RECORDED,
    PLACE_NOT_READ,
    FEED_NOT_READ,
    NO_MATCHER,
];

/// How old the newest change of a data set may be for it to count as current.
const NEWEST_CHANGE: i64 = 7 * 86_400;

/// What "known for certain" speaks for, in its words.
pub const DECLARED: &str = "This speaks for what the project's lockfiles declare. What is installed in its node_modules, or what was built and deployed from it, can differ.";

// ---- Ordering versions. ----

/// How the versions of an ecosystem are read and ordered. A string the scheme does not read is
/// not a version and is never coerced.
pub trait Scheme: Sized {
    /// The scheme's name, in what is said.
    const NAME: &'static str;
    /// The kinds of OSV range ordered by it.
    const KINDS: &'static [&'static str];
    fn read(s: &str) -> Option<Self>;
    fn order(&self, other: &Self) -> Ordering;
    /// Whether the version has a local label, which only a build outside the registry carries.
    fn local(&self) -> bool;
}

/// SemVer 2.0, strictly: three numbers, no leading `v`, no `=`, no spaces. The parser is the
/// `semver` crate's; precedence disregards build metadata (semver.org, item 11).
impl Scheme for semver::Version {
    const NAME: &'static str = "SemVer";
    const KINDS: &'static [&'static str] = &["SEMVER", "ECOSYSTEM"];
    fn read(s: &str) -> Option<Self> {
        semver::Version::parse(s).ok()
    }
    fn order(&self, other: &Self) -> Ordering {
        self.cmp_precedence(other)
    }
    fn local(&self) -> bool {
        false
    }
}

/// The "Version specifiers" specification (PEP 440), as `pep440_rs` reads and orders it: its
/// normalisation of case, a leading `v`, separators, spellings and padding is the
/// specification's own. A range of kind `SEMVER` says nothing in this order.
impl Scheme for pep440_rs::Version {
    const NAME: &'static str = "PEP 440";
    const KINDS: &'static [&'static str] = &["ECOSYSTEM"];
    fn read(s: &str) -> Option<Self> {
        s.parse().ok()
    }
    fn order(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
    fn local(&self) -> bool {
        self.is_local()
    }
}

/// A release, in the scheme of its ecosystem.
pub enum Release {
    SemVer(semver::Version),
    Pep440(pep440_rs::Version),
}

impl Release {
    /// `judge` in the release's own scheme.
    pub fn judge(&self, ranges: &Value, versions: &Value) -> Verdict {
        match self {
            Release::SemVer(v) => judge(v, ranges, versions),
            Release::Pep440(v) => judge(v, ranges, versions),
        }
    }
}

/// A release of a package of `ecosystem`, read by the scheme of its versions: SemVer for npm and
/// crates.io, PEP 440 for PyPI. `Err` says in the program's words why there is none; for an
/// ecosystem with no scheme here, there is never one, so its answer is "don't know".
pub fn version(ecosystem: &str, s: &str) -> Result<Release, String> {
    fn read<R: Scheme>(s: &str) -> Result<R, String> {
        R::read(s).ok_or_else(|| format!("is not a {} version", R::NAME))
    }
    match ecosystem {
        "npm" | "crates.io" => read(s).map(Release::SemVer),
        "PyPI" => read(s).map(Release::Pep440),
        _ => Err(format!(
            "cannot be ordered: no order of {ecosystem} versions is known"
        )),
    }
}

/// The order of the scheme.
pub fn compare<R: Scheme>(a: &R, b: &R) -> Ordering {
    a.order(b)
}

/// An event's value: `"0"` for `introduced` is before every version.
#[derive(Clone)]
enum Bound<R> {
    Zero,
    At(R),
}

impl<R: Scheme> Bound<R> {
    fn cmp_to(&self, v: &R) -> Ordering {
        match self {
            Bound::Zero => Ordering::Less,
            Bound::At(b) => compare(b, v),
        }
    }

    fn order(a: &Self, b: &Self) -> Ordering {
        match (a, b) {
            (Bound::Zero, Bound::Zero) => Ordering::Equal,
            (Bound::Zero, _) => Ordering::Less,
            (_, Bound::Zero) => Ordering::Greater,
            (Bound::At(x), Bound::At(y)) => compare(x, y),
        }
    }
}

/// What one record says of one release.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Affected,
    /// Not affected; `fixed` when the release is at or above a fix.
    NotAffected {
        fixed: bool,
    },
    /// The reason, from the closed list, and the detail in the program's words.
    Unknown(&'static str, String),
}

/// The OSV schema's `IsVulnerable` for one release and one affected entry of a record:
/// `ranges` and `versions` as `advisory_affects` keeps them. A range of a kind the release's
/// scheme orders is walked over its sorted events, each read by that scheme; a range of commits,
/// or of a kind not known, cannot be compared here. A release with a local label is not one the
/// registry serves, and a record's version with one cannot be compared: PyPI takes no local
/// version, and the order and the specifiers disagree about them.
pub fn judge<R: Scheme>(v: &R, ranges: &Value, versions: &Value) -> Verdict {
    if v.local() {
        return Verdict::Unknown(
            NOT_FROM_REGISTRY,
            "a release with a local label is not one the registry serves".to_string(),
        );
    }
    let version = |s: &str| R::read(s).filter(|x| !x.local());
    let mut uncomparable: Option<String> = None;
    let mut uncovered: Option<String> = None;
    let mut fixed = false;
    let listed: Vec<&str> = versions
        .as_array()
        .map(|l| l.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for s in &listed {
        match version(s) {
            Some(x) if compare(&x, v) == Ordering::Equal => return Verdict::Affected,
            Some(_) => {}
            None => {
                uncomparable.get_or_insert(format!("the record lists the release {s}"));
            }
        }
    }
    let ranges = ranges.as_array().cloned().unwrap_or_default();
    if ranges.is_empty() && listed.is_empty() {
        return Verdict::Unknown(
            NOT_COMPARABLE,
            "the record names no range and no release".to_string(),
        );
    }
    for range in &ranges {
        let kind = range["type"].as_str().unwrap_or_default();
        if !R::KINDS.contains(&kind) {
            // OSV's `versions` enumerates what a range of commits covers, so with releases
            // listed such a range says no more. A range of any other kind may hold the release.
            if kind != "GIT" || listed.is_empty() {
                uncomparable.get_or_insert(format!("the record gives a range of kind {kind}"));
            }
            continue;
        }
        let mut events: Vec<(&str, Bound<R>)> = Vec::new();
        let mut limits: Vec<Option<R>> = Vec::new();
        let mut bad = None;
        for e in range["events"].as_array().into_iter().flatten() {
            let Some((key, value)) = e
                .as_object()
                .and_then(|o| o.iter().next())
                .and_then(|(k, v)| v.as_str().map(|v| (k.as_str(), v)))
            else {
                bad = Some("an event out of shape".to_string());
                continue;
            };
            match (key, value) {
                ("introduced", "0") => events.push(("introduced", Bound::Zero)),
                ("limit", "*") => limits.push(None),
                (key, value) => match version(value) {
                    Some(x) if key == "limit" => limits.push(Some(x)),
                    Some(x) => events.push((
                        match key {
                            "introduced" => "introduced",
                            "fixed" => "fixed",
                            _ => "last_affected",
                        },
                        Bound::At(x),
                    )),
                    None => bad = Some(format!("the record's range has {key} {value}")),
                },
            }
        }
        if let Some(why) = bad {
            uncomparable.get_or_insert(why);
            continue;
        }
        // At one version, a `fixed` ends the interval before an `introduced` begins the next,
        // and a `last_affected`, which ends its interval after its version, comes last. An
        // `introduced` and a `fixed` at one version so read as affected from there on: loud.
        let at = |key: &str| match key {
            "fixed" => 0,
            "introduced" => 1,
            _ => 2,
        };
        events.sort_by(|a, b| Bound::order(&a.1, &b.1).then(at(a.0).cmp(&at(b.0))));
        let mut vulnerable = false;
        let mut off_by_fix = false;
        for (key, bound) in &events {
            let c = bound.cmp_to(v);
            match *key {
                "introduced" if c != Ordering::Greater => vulnerable = true,
                "fixed" if c != Ordering::Greater => {
                    vulnerable = false;
                    off_by_fix = true;
                }
                "last_affected" if c == Ordering::Less => {
                    vulnerable = false;
                    off_by_fix = false;
                }
                _ => {}
            }
        }
        let before_limits = limits.is_empty()
            || limits
                .iter()
                .any(|l| l.as_ref().is_none_or(|l| compare(v, l) == Ordering::Less));
        if vulnerable && before_limits {
            return Verdict::Affected;
        }
        fixed |= off_by_fix;
        // Past the last release named as affected, with no fix anywhere in the range: the
        // record does not say whether this release is affected.
        let has_fix = events.iter().any(|(k, _)| *k == "fixed");
        let above_last = events
            .iter()
            .any(|(k, b)| *k == "last_affected" && b.cmp_to(v) == Ordering::Less);
        let after_start = events
            .iter()
            .any(|(k, b)| *k == "introduced" && b.cmp_to(v) != Ordering::Greater);
        if !has_fix && above_last && after_start {
            uncovered.get_or_insert(
                "the release is above the last one the record names as affected, and no fix is named"
                    .to_string(),
            );
        }
    }
    if let Some(why) = uncomparable {
        return Verdict::Unknown(NOT_COMPARABLE, why);
    }
    if let Some(why) = uncovered {
        return Verdict::Unknown(NOT_COVERED, why);
    }
    Verdict::NotAffected { fixed }
}

/// The releases a record names as fixing it, for one affected entry.
fn fixes(ranges: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for range in ranges.as_array().into_iter().flatten() {
        for e in range["events"].as_array().into_iter().flatten() {
            if let Some(f) = e["fixed"].as_str() {
                out.push(f.to_string());
            }
        }
    }
    out
}

/// The source of a record by its id, named as docs/threats.md names it wherever a record's
/// text is shown.
pub fn source_name(id: &str) -> &'static str {
    if id.starts_with("GHSA-") {
        "GitHub Advisory Database"
    } else if id.starts_with("RUSTSEC-") {
        "RustSec"
    } else if id.starts_with("MAL-") {
        "OpenSSF malicious packages"
    } else if id.starts_with("PYSEC-") {
        "Python Packaging Advisory Database"
    } else {
        "OSV.dev"
    }
}

// ---- The conditions of a place. ----

/// Whether a feed's data counts as current at `now`, and the reading it rests on.
pub struct Fresh {
    pub feed: &'static Feed,
    /// The latest reading that read the feed or found it unchanged: its id and time.
    pub reading: Option<(i64, i64)>,
    /// `None` when current; else why not, in the program's words.
    pub not_current: Option<String>,
}

/// The feeds whose ecosystem is matched: this build has a feed for it and reads some kind of
/// lockfile of it (`lockfiles::has_reader`). Only these give a place, an answer, a count or a
/// word that says packages were compared. Any other feed is downloaded, read, counted and shown
/// as a feed, and nothing else.
pub fn matched_feeds() -> impl Iterator<Item = &'static Feed> {
    matched_of(&FEEDS, crate::lockfiles::has_reader)
}

/// The feeds of `feeds` whose ecosystem `read` says some kind of lockfile is read for.
fn matched_of(feeds: &[Feed], read: fn(&str) -> bool) -> impl Iterator<Item = &Feed> {
    feeds.iter().filter(move |f| read(f.ecosystem))
}

/// Each feed as a feed: whether it was read whole within its limit and its newest change is
/// recent.
pub fn freshness(conn: &Connection, now: i64) -> rusqlite::Result<Vec<Fresh>> {
    let feeds: &'static [Feed] = &FEEDS;
    freshness_of(conn, now, feeds.iter())
}

/// The same for each matched feed (`matched_feeds`): what answers rest on.
pub fn matched_freshness(conn: &Connection, now: i64) -> rusqlite::Result<Vec<Fresh>> {
    freshness_of(conn, now, matched_feeds())
}

fn freshness_of(
    conn: &Connection,
    now: i64,
    feeds: impl Iterator<Item = &'static Feed>,
) -> rusqlite::Result<Vec<Fresh>> {
    let mut out = Vec::new();
    for feed in feeds {
        let reading = crate::osv::last_good_at(conn, feed.source)?;
        let newest: Option<String> = conn.query_row(
            "SELECT MAX(modified) FROM advisory WHERE source = ?1 AND gone_at IS NULL",
            [feed.source],
            |r| r.get(0),
        )?;
        // The newest change is the source's time, compared as text in the same form and said as
        // every time in the core's words is.
        let ahead = crate::view::iso(now + crate::store::AHEAD_ALLOWED);
        let changed = |t: &str| match record_time(t) {
            Some(at) => crate::view::utc(at),
            None => "at a time this version cannot read as a date".to_string(),
        };
        let read = reading.map(|r| r.1);
        let not_current = read_not_current(read, now, feed.current_for).or_else(|| match newest {
            Some(t) if t.as_str() > ahead.as_str() => Some(format!(
                "its newest record changed {}, and {}",
                changed(&t),
                crate::store::AHEAD
            )),
            Some(t) if t.as_str() >= crate::view::iso(now - NEWEST_CHANGE).as_str() => None,
            Some(t) => Some(format!(
                "its newest record changed {}, more than 7 days before this check",
                changed(&t)
            )),
            None => Some("it holds no record".to_string()),
        });
        out.push(Fresh {
            feed,
            reading,
            not_current,
        });
    }
    Ok(out)
}

/// Why data whose latest good reading was at `read_at` is not current at `now` by its
/// `current_for`, or `None` while it is: never read, read at a time ahead of the clock, or read
/// longer ago than `current_for`. A feed is current when this is `None` and its newest record is
/// recent (`freshness`); the catalogue has no records with such times and is current when this
/// is `None` with `threats::CURRENT_FOR`.
///
/// It is also the one rule for a download that failed: a failed download is silent while the
/// data it would have refreshed is current, and it is a fault from the moment that data is not
/// current, or when nothing of it was ever read. That is the moment answers resting on it turn
/// to "don't know" (`stale_at`). The catalogue's cause in `covered::not_covered` and the line
/// of downloads in `overview::downloads_failed` both read it, the latter through the status's
/// `FeedFreshness.current`.
pub fn read_not_current(read_at: Option<i64>, now: i64, current_for: i64) -> Option<String> {
    match read_at.map(|at| (at, crate::store::age(at, now))) {
        None => Some("it has never been read".to_string()),
        Some((at, None)) => Some(format!(
            "it was last read {}, and {}",
            crate::view::utc(at),
            crate::store::AHEAD
        )),
        Some((at, Some(age))) if age > current_for => Some(format!(
            "it was last read {}, more than {} hours before this check",
            crate::view::utc(at),
            current_for / 3600
        )),
        _ => None,
    }
}

/// A record's time as OSV writes it (`osv::parse`), in UTC seconds; `None` when it is no date,
/// such as one of a thirteenth month. The C library reads it (`events::instant`), and it is
/// taken only when the time it gives is said with the same date, hour and minute, since
/// `timegm` carries a 31 February into March. The fraction of a second is never said.
fn record_time(t: &str) -> Option<i64> {
    let (secs, _) = crate::events::instant(&format!("{}Z", t.get(..19)?))?;
    (crate::view::utc(secs).get(..16)? == t.get(..16)?.replace('T', " ")).then_some(secs)
}

/// A checkout's lockfiles reading: its scope, completeness, reason, run, the names of what it
/// says it did not read (`coverage_lack`), `None` for one without a name, the ecosystems of the
/// lockfiles found in it, read or not (`lockfiles::HAS_LOCKFILE`), and the rows of what it did not
/// read (`store::unread_of`).
type LockfileReading = (
    String,
    String,
    Option<String>,
    String,
    Vec<Option<String>>,
    HashSet<&'static str>,
    Vec<crate::store::Unread>,
);

/// The lockfiles reader's latest reading of each checkout that is still there.
fn lockfile_readings(conn: &Connection) -> rusqlite::Result<Vec<LockfileReading>> {
    let readings: Vec<(i64, String, String, Option<String>, String)> = conn
        .prepare(&format!(
            "SELECT c.id, c.scope, c.completeness, c.reason, c.run_id FROM coverage c
             WHERE c.reader = ?1
               AND c.id = (SELECT MAX(l.id) FROM coverage l WHERE l.reader = c.reader AND l.scope = c.scope)
               AND NOT {}
             ORDER BY c.scope",
            crate::store::gone_entity("c.scope")
        ))?
        .query_map([crate::lockfiles::READER], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut lacks = conn.prepare("SELECT name FROM coverage_lack WHERE coverage = ?1")?;
    let mut found = conn.prepare(
        "SELECT object FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND scope = ?2 AND subject = ?2 AND predicate = ?3",
    )?;
    readings
        .into_iter()
        .map(|(id, scope, completeness, reason, run)| {
            let names = lacks
                .query_map([id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let paths: Vec<String> = found
                .query_map(
                    params![
                        crate::lockfiles::READER,
                        scope,
                        crate::lockfiles::HAS_LOCKFILE
                    ],
                    |r| r.get(0),
                )?
                .collect::<rusqlite::Result<_>>()?;
            let of = (paths.iter())
                .filter_map(|p| crate::lockfiles::ecosystem_of_file(p))
                .collect();
            let rows = crate::store::unread_of(conn, &[id])?.concat();
            Ok((scope, completeness, reason, run, names, of, rows))
        })
        .collect()
}

/// How the lockfiles of a checkout were read for one ecosystem: `full`, `partial` or
/// `not_read`, and why, from what the reading did not read (`lockfiles::partial_for`).
fn lockfiles_for(
    completeness: &str,
    reason: Option<&str>,
    rows: &[crate::store::Unread],
    lacks: &[Option<String>],
    reading_run: &str,
    run_id: &str,
    ecosystem: &str,
) -> (&'static str, Option<String>) {
    if reading_run != run_id {
        return (
            "not_read",
            Some("its lockfiles were not read in the latest check".to_string()),
        );
    }
    match completeness {
        "full" => ("full", None),
        "partial" if !crate::lockfiles::partial_for(rows, lacks, ecosystem) => ("full", None),
        "partial" => ("partial", reason.map(str::to_string)),
        _ => ("not_read", reason.map(str::to_string)),
    }
}

// ---- Matching, in the run. ----

/// One entry of a package in a checkout: its component, where it comes from, its version and
/// where in the lockfile it is.
struct Entry {
    component: String,
    source: Source,
    version: Option<String>,
    at: String,
}

/// The packages of the lockfiles: checkout, ecosystem and name, with their entries.
type Packages = BTreeMap<(String, &'static str, String), Vec<Entry>>;

/// Every package the lockfiles hold now, grouped by checkout, ecosystem and name.
fn held_packages(conn: &Connection) -> rusqlite::Result<Packages> {
    let mut packages: Packages = BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT subject, predicate, object, source_ref, scope FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate IN ('has_version', 'part_of')
             ORDER BY subject, predicate",
        )?;
        let rows = stmt.query_map([crate::lockfiles::READER], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut versioned: HashSet<String> = HashSet::new();
        for row in rows {
            let (subject, predicate, object, at, scope) = row?;
            let Some(rest) = subject.strip_prefix(&format!("component:{scope}/")) else {
                continue;
            };
            let Some((eco, name)) = rest.split_once('/') else {
                continue;
            };
            // No component of an ecosystem with no feed exists: every ecosystem a lockfile is
            // read for has one, which a test in `lockfiles` holds
            // (`every_ecosystem_a_lockfile_is_read_for_has_a_feed`).
            let Some(eco) = FEEDS.iter().map(|f| f.ecosystem).find(|e| *e == eco) else {
                continue;
            };
            let (package, source) = crate::lockfiles::split_name(name);
            let version = if predicate == "has_version" {
                versioned.insert(subject.clone());
                Some(object)
            } else if versioned.contains(&subject) {
                // Its versions were taken; `part_of` alone says nothing more.
                continue;
            } else {
                None
            };
            packages
                .entry((scope.clone(), eco, package.to_string()))
                .or_default()
                .push(Entry {
                    component: subject,
                    source,
                    version,
                    at,
                });
        }
    }
    Ok(packages)
}

/// One answer as computed.
struct Computed {
    checkout: String,
    ecosystem: &'static str,
    package: String,
    source: &'static str,
    advisory: String,
    modified: String,
    kind: String,
    answer: &'static str,
    reason: &'static str,
    detail: String,
    entries: Value,
    /// Whether each entry's own verdict is "don't know", in the order of `entries`. Not kept.
    untold: Vec<bool>,
    fixed: Value,
    reading: Option<(i64, i64)>,
}

/// One advisory's rows for a package.
struct Named {
    source: &'static str,
    advisory: String,
    modified: String,
    kind: String,
    affects: Vec<(Value, Value)>,
}

/// What a run's matching found, for the findings.
pub struct Matched {
    /// Per component with an affected entry, by the id it is read under: its affecting records
    /// of each kind, with the versions they affect.
    pub affected: BTreeMap<String, Vec<(String, String, Vec<String>)>>,
    /// The checkouts and ecosystems whose lockfiles this run read in full (`lockfiles_for`).
    read: HashSet<(String, &'static str)>,
    /// The components those lockfiles hold for which this run has an answer `unknown` or data
    /// that is not current.
    untold: HashSet<String>,
}

impl Matched {
    /// Whether this run tells for certain what affects the component `about` names, so that a
    /// finding about it that the run did not hold again is over: its checkout is gone, or its
    /// checkout's lockfiles of its ecosystem were read in full in this run and either no longer
    /// hold the package, or hold it and every answer for it is known, on current data.
    pub fn known(&self, conn: &Connection, about: &str) -> rusqlite::Result<bool> {
        // Every checkout whose lockfiles the reader read a component of this id in, kept after
        // it went. A package name may hold `/`, so one id can name packages of two checkouts,
        // one inside the other; the thing is known only when it is known in each. A thing the
        // store holds no such fact of has no checkout, so nothing is known of it.
        let checkouts: Vec<(String, bool)> = conn
            .prepare(&format!(
                "SELECT DISTINCT a.scope, {} FROM assertion a WHERE a.subject = ?1 AND a.reader = ?2",
                crate::store::gone_entity("a.scope")
            ))?
            .query_map(params![about, crate::lockfiles::READER], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let known_in = |(checkout, gone): &(String, bool)| {
            let read = about
                .strip_prefix(&format!("component:{checkout}/"))
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(eco, _)| self.read.iter().any(|(c, e)| c == checkout && *e == eco));
            *gone || (read && !self.untold.contains(about))
        };
        Ok(!checkouts.is_empty() && checkouts.iter().all(known_in))
    }
}

/// Matches every package the checkouts' lockfiles hold against the data, writes the answers
/// and the conditions of each place, and links records to the catalogue. Run in the run's
/// transaction after the feeds are read.
pub fn match_all(tx: &Transaction, run_id: &str, at: i64) -> rusqlite::Result<Matched> {
    // A place for each checkout and each matched ecosystem alone (`matched_feeds`).
    let fresh = matched_freshness(tx, at)?;
    let fresh_of = |eco: &str| fresh.iter().find(|f| f.feed.ecosystem == eco);
    // The conditions of each place.
    let readings = lockfile_readings(tx)?;
    tx.execute("DELETE FROM vulnerability_place", [])?;
    let mut places: HashMap<(String, &'static str), (&'static str, Option<String>)> =
        HashMap::new();
    let mut read = HashSet::new();
    for (scope, completeness, reason, reading_run, lacks, found, rows) in &readings {
        for f in &fresh {
            let eco = f.feed.ecosystem;
            let (lockfiles, why) = lockfiles_for(
                completeness,
                reason.as_deref(),
                rows,
                lacks,
                reading_run,
                run_id,
                eco,
            );
            // Read in full with no lockfile of the ecosystem left, the checkout holds none of its
            // packages for certain, so a finding about one it held is over (`Matched::known`).
            if lockfiles == "full" {
                read.insert((scope.clone(), eco));
            }
            // A place only where there is something to say of the ecosystem: a lockfile of it
            // was found, read or not, or the reading may hide one, as folders not looked through
            // or a reading not of the latest check (`lockfiles_for`). A checkout with no lockfile
            // of it is never a place that would read as compared; one in which the reading found
            // no lockfile at all is one counted item (`unread_places`).
            let none = reason.as_deref() == Some(crate::lockfiles::NONE_FOUND_NOTE);
            if !found.contains(eco) && (lockfiles == "full" || none) {
                continue;
            }
            tx.execute(
                "INSERT INTO vulnerability_place (checkout, ecosystem, lockfiles, lockfiles_why,
                     feed, feed_why, reading, read_at, run_id, at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    scope,
                    eco,
                    lockfiles,
                    why,
                    if f.not_current.is_none() {
                        "current"
                    } else {
                        "not_current"
                    },
                    f.not_current,
                    f.reading.map(|r| r.0),
                    f.reading.map(|r| r.1),
                    run_id,
                    at
                ],
            )?;
            places.insert((scope.clone(), eco), (lockfiles, why));
        }
    }

    let packages = held_packages(tx)?;

    // What the data says of each package, once per ecosystem and name.
    let mut computed: Vec<Computed> = Vec::new();
    {
        let mut lookup = tx.prepare(
            "SELECT f.source, f.advisory, f.ranges, f.versions, a.kind, a.modified
             FROM advisory_affects f JOIN advisory a ON a.source = f.source AND a.id = f.advisory
             WHERE f.ecosystem = ?1 AND f.normalized = ?2
               AND a.withdrawn IS NULL AND a.gone_at IS NULL AND a.kind != 'informational'
             ORDER BY f.source, f.advisory",
        )?;
        let mut cache: HashMap<(&'static str, String), Vec<Named>> = HashMap::new();
        for ((checkout, eco, package), entries) in &packages {
            let key = (*eco, crate::osv::normalized(eco, package));
            if !cache.contains_key(&key) {
                let mut named: Vec<Named> = Vec::new();
                let rows = lookup.query_map(params![key.0, key.1], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                    ))
                })?;
                for row in rows {
                    let (source, advisory, ranges, versions, kind, modified) = row?;
                    let Some(source) = FEEDS.iter().map(|f| f.source).find(|s| *s == source) else {
                        continue;
                    };
                    let ranges = serde_json::from_str(&ranges).unwrap_or(Value::Null);
                    let versions = serde_json::from_str(&versions).unwrap_or(Value::Null);
                    match named.last_mut() {
                        Some(n) if n.source == source && n.advisory == advisory => {
                            n.affects.push((ranges, versions));
                        }
                        _ => named.push(Named {
                            source,
                            advisory,
                            modified,
                            kind,
                            affects: vec![(ranges, versions)],
                        }),
                    }
                }
                cache.insert(key.clone(), named);
            }
            let place = places.get(&(checkout.clone(), *eco));
            let feed = fresh_of(eco);
            for n in &cache[&key] {
                computed.push(answer_one(checkout, eco, package, entries, n, place, feed));
            }
        }
    }

    write_answers(tx, &computed, run_id, at)?;
    link_catalogue(tx)?;

    // A package that cannot be told is so under its plain name and under each component its
    // entries are read as, such as one whose index the lockfile does not record.
    let unknown: HashSet<(&str, &str, &str)> = (computed.iter())
        .filter(|c| c.answer == "unknown")
        .map(|c| (c.checkout.as_str(), c.ecosystem, c.package.as_str()))
        .collect();
    let mut untold: HashSet<String> = packages
        .iter()
        .filter(|((checkout, eco, package), _)| {
            fresh_of(eco).is_none_or(|f| f.not_current.is_some())
                || unknown.contains(&(checkout.as_str(), *eco, package.as_str()))
        })
        .flat_map(|((checkout, eco, package), entries)| {
            std::iter::once(format!("component:{checkout}/{eco}/{package}"))
                .chain(entries.iter().map(|e| e.component.clone()))
        })
        .collect();

    // What the findings rest on: each component with an affected entry, by record kind. A
    // component follows its own entries, whatever the package's answer: with one that cannot be
    // told it is untold, even when another is affected, so a finding of another rule about it
    // stands.
    let mut affected: BTreeMap<String, Vec<(String, String, Vec<String>)>> = BTreeMap::new();
    for c in &computed {
        let entries = &packages[&(c.checkout.clone(), c.ecosystem, c.package.clone())];
        // `answer_one` gives the entries in their order.
        let mut of: BTreeMap<&str, (Vec<String>, bool)> = BTreeMap::new();
        let shown = c.entries.as_array().into_iter().flatten();
        for ((e, shown), untold) in entries.iter().zip(shown).zip(&c.untold) {
            let (versions, unknown) = of.entry(&e.component).or_default();
            if let (true, Some(v)) = (shown["affected"] == true, &e.version) {
                versions.push(v.clone());
            }
            *unknown |= untold;
        }
        for (component, (versions, unknown)) in of {
            if !versions.is_empty() {
                affected.entry(component.to_string()).or_default().push((
                    c.advisory.clone(),
                    c.kind.clone(),
                    versions,
                ));
            }
            if unknown {
                untold.insert(component.to_string());
            }
        }
    }
    Ok(Matched {
        affected,
        read,
        untold,
    })
}

/// The answer for one advisory and one package in one checkout.
fn answer_one(
    checkout: &str,
    eco: &'static str,
    package: &str,
    entries: &[Entry],
    n: &Named,
    place: Option<&(&'static str, Option<String>)>,
    feed: Option<&Fresh>,
) -> Computed {
    let mut reasons: Vec<(&'static str, String)> = Vec::new();
    let mut shown: Vec<Value> = Vec::new();
    let mut untold = Vec::new();
    let mut any_affected = false;
    let mut all_fixed = true;
    for e in entries {
        let compared = matches!(e.source, Source::Registry | Source::UnrecordedIndex);
        let verdict = match (compared, e.version.as_deref()) {
            (false, _) => Verdict::Unknown(
                NOT_FROM_REGISTRY,
                format!("{package} comes from {} at {}", e.source.said(), e.at),
            ),
            (true, None) => Verdict::Unknown(
                NOT_COMPARABLE,
                format!("the lockfile gives no version at {}", e.at),
            ),
            (true, Some(v)) => match version(eco, v) {
                Err(why) => {
                    Verdict::Unknown(NOT_COMPARABLE, format!("the release {v} at {} {why}", e.at))
                }
                Ok(parsed) => {
                    let verdicts: Vec<Verdict> = n
                        .affects
                        .iter()
                        .map(|(ranges, versions)| parsed.judge(ranges, versions))
                        .collect();
                    if verdicts.contains(&Verdict::Affected) {
                        Verdict::Affected
                    } else if let Some(Verdict::Unknown(r, d)) =
                        verdicts.iter().find(|v| matches!(v, Verdict::Unknown(..)))
                    {
                        Verdict::Unknown(r, format!("{d}, for {v} at {}", e.at))
                    } else if e.source == Source::UnrecordedIndex {
                        // Outside the record, but it may not be the registry's release.
                        Verdict::Unknown(
                            INDEX_NOT_RECORDED,
                            format!(
                                "the lockfile does not record which index {package} {v} comes \
                                 from, at {}",
                                e.at
                            ),
                        )
                    } else {
                        Verdict::NotAffected {
                            fixed: verdicts
                                .iter()
                                .all(|v| matches!(v, Verdict::NotAffected { fixed: true })),
                        }
                    }
                }
            },
        };
        let affected = verdict == Verdict::Affected;
        any_affected |= affected;
        untold.push(matches!(verdict, Verdict::Unknown(..)));
        match verdict {
            Verdict::Unknown(r, d) => reasons.push((r, d)),
            Verdict::NotAffected { fixed } => all_fixed &= fixed,
            Verdict::Affected => {}
        }
        shown.push(json!({
            "version": e.version,
            "at": e.at,
            "from": e.source.said(),
            "affected": affected,
        }));
    }
    match place {
        Some(("full", _)) => {}
        Some((_, why)) => reasons.push((
            PLACE_NOT_READ,
            why.clone()
                .unwrap_or_else(|| "its lockfiles were not read".to_string()),
        )),
        None => reasons.push((PLACE_NOT_READ, "its lockfiles have no reading".to_string())),
    }
    if let Some(why) = feed.and_then(|f| f.not_current.as_ref()) {
        reasons.push((
            FEED_NOT_READ,
            format!("the {eco} data is not current: {why}"),
        ));
    }
    let fixed: Vec<String> = n.affects.iter().flat_map(|(r, _)| fixes(r)).collect();
    let (answer, reason, detail) = if any_affected {
        (
            "affected",
            "affected",
            format!("{} affects {package} here", n.advisory),
        )
    } else if let Some((r, d)) = REASONS
        .iter()
        .find_map(|code| reasons.iter().find(|(r, _)| r == code))
    {
        ("unknown", *r, d.clone())
    } else if all_fixed {
        (
            "not_affected",
            "fixed",
            "every release here is at or above a fix".to_string(),
        )
    } else {
        (
            "not_affected",
            "not_in_range",
            "no release here is in the record's ranges or list".to_string(),
        )
    };
    Computed {
        checkout: checkout.to_string(),
        ecosystem: eco,
        package: package.to_string(),
        source: n.source,
        advisory: n.advisory.clone(),
        modified: n.modified.clone(),
        kind: n.kind.clone(),
        answer,
        reason,
        detail,
        entries: Value::Array(shown),
        untold,
        fixed: json!(fixed),
        reading: feed.and_then(|f| f.reading),
    }
}

/// Writes the answers: an answer that stays keeps when it began; one that changed or went is
/// kept in the past table with when it stopped.
fn write_answers(
    tx: &Transaction,
    computed: &[Computed],
    run_id: &str,
    at: i64,
) -> rusqlite::Result<()> {
    type Key = (String, String, String, String, String);
    let held: HashMap<Key, (String, String)> = tx
        .prepare(
            "SELECT checkout, ecosystem, package, source, advisory, answer, reason
             FROM vulnerability_answer",
        )?
        .query_map([], |r| {
            Ok((
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?),
                (r.get(5)?, r.get(6)?),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut keep_past = tx.prepare(
        "INSERT INTO vulnerability_answer_past
         SELECT checkout, ecosystem, package, source, advisory, modified, answer, reason, detail,
                entries, fixed, reading, read_at, since_run, since_at, run_id, at, ?6, ?7
         FROM vulnerability_answer
         WHERE checkout = ?1 AND ecosystem = ?2 AND package = ?3 AND source = ?4 AND advisory = ?5",
    )?;
    let mut put = tx.prepare(
        "INSERT INTO vulnerability_answer (checkout, ecosystem, package, source, advisory,
             modified, answer, reason, detail, entries, fixed, reading, read_at, since_run,
             since_at, run_id, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?14, ?15)
         ON CONFLICT (checkout, ecosystem, package, source, advisory) DO UPDATE SET
             modified = excluded.modified, answer = excluded.answer, reason = excluded.reason,
             detail = excluded.detail, entries = excluded.entries, fixed = excluded.fixed,
             reading = excluded.reading, read_at = excluded.read_at,
             since_run = CASE WHEN ?16 THEN excluded.since_run ELSE since_run END,
             since_at = CASE WHEN ?16 THEN excluded.since_at ELSE since_at END,
             run_id = excluded.run_id, at = excluded.at",
    )?;
    let mut seen: HashSet<Key> = HashSet::new();
    for c in computed {
        let key: Key = (
            c.checkout.clone(),
            c.ecosystem.to_string(),
            c.package.clone(),
            c.source.to_string(),
            c.advisory.clone(),
        );
        let changed = match held.get(&key) {
            Some((answer, reason)) if answer == c.answer && reason == c.reason => false,
            Some(_) => {
                keep_past.execute(params![key.0, key.1, key.2, key.3, key.4, run_id, at])?;
                true
            }
            None => true,
        };
        put.execute(params![
            c.checkout,
            c.ecosystem,
            c.package,
            c.source,
            c.advisory,
            c.modified,
            c.answer,
            c.reason,
            c.detail,
            c.entries.to_string(),
            c.fixed.to_string(),
            c.reading.map(|r| r.0),
            c.reading.map(|r| r.1),
            run_id,
            at,
            changed
        ])?;
        seen.insert(key);
    }
    let mut gone = tx.prepare(
        "DELETE FROM vulnerability_answer
         WHERE checkout = ?1 AND ecosystem = ?2 AND package = ?3 AND source = ?4 AND advisory = ?5",
    )?;
    for key in held.keys().filter(|k| !seen.contains(*k)) {
        keep_past.execute(params![key.0, key.1, key.2, key.3, key.4, run_id, at])?;
        gone.execute(params![key.0, key.1, key.2, key.3, key.4])?;
    }
    Ok(())
}

/// Links records to the catalogue's exploited CVEs through their aliases, and through the
/// aliases of a record they name, as a RustSec record names a GitHub one.
fn link_catalogue(tx: &Transaction) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM vulnerability_linked", [])?;
    let catalogue: HashSet<String> = tx
        .prepare("SELECT id FROM threat WHERE gone_at IS NULL")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if catalogue.is_empty() {
        return Ok(());
    }
    let records: Vec<(String, String, Vec<String>)> = tx
        .prepare(
            "SELECT source, id, aliases FROM advisory
             WHERE gone_at IS NULL AND withdrawn IS NULL AND aliases != '[]'",
        )?
        .query_map([], |r| {
            let aliases: String = r.get(2)?;
            Ok((
                r.get(0)?,
                r.get(1)?,
                serde_json::from_str(&aliases).unwrap_or_default(),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let by_id: HashMap<&str, &Vec<String>> =
        records.iter().map(|(_, id, a)| (id.as_str(), a)).collect();
    let mut put = tx.prepare(
        "INSERT OR IGNORE INTO vulnerability_linked (cve, source, advisory) VALUES (?1, ?2, ?3)",
    )?;
    for (source, id, aliases) in &records {
        let mut names: BTreeSet<&str> = aliases.iter().map(String::as_str).collect();
        for a in aliases {
            if let Some(more) = by_id.get(a.as_str()) {
                names.extend(more.iter().map(String::as_str));
            }
        }
        names.insert(id);
        for cve in names.into_iter().filter(|n| catalogue.contains(*n)) {
            put.execute(params![cve, source, id])?;
        }
    }
    Ok(())
}

// ---- What is told. ----

/// The order of labels, most severe first; a malicious package before every label.
const LABELS: [&str; 6] = ["malicious", "critical", "high", "moderate", "low", "none"];

/// The label an affecting record is listed under: malicious, or the source's own label.
fn label_of(kind: &str, severity: Option<&str>) -> &'static str {
    if kind == "malicious" {
        return "malicious";
    }
    match severity.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => "critical",
        Some("high") => "high",
        Some("moderate" | "medium") => "moderate",
        Some("low") => "low",
        _ => "none",
    }
}

/// One "affects me" answer, as it is listed.
pub struct Affecting {
    pub checkout: String,
    pub ecosystem: String,
    pub package: String,
    pub source: String,
    pub advisory: String,
    pub modified: String,
    pub kind: String,
    pub label: &'static str,
    pub summary: Option<String>,
    pub aliases: Vec<String>,
    pub exploited: bool,
    pub entries: Value,
    pub fixed: Vec<String>,
    pub read_at: Option<i64>,
    pub since_at: i64,
}

impl Affecting {
    /// Whether a finding about the component `about` rests on this answer: it affects an entry
    /// of that component (`affected_of`).
    pub fn is_about(&self, about: &str) -> bool {
        !self.affected_of(about).is_empty()
    }

    /// The releases of the component `about` the record affects, with where each is. An answer
    /// is kept under the package's plain name; a component's id may carry its source, and only
    /// the entries from that source are its own.
    pub fn affected_of(&self, about: &str) -> Vec<(String, String)> {
        let id = format!(
            "component:{}/{}/{}",
            self.checkout, self.ecosystem, self.package
        );
        match crate::lockfiles::split_name(about) {
            (plain, source) if plain == id => self.affected_from(Some(source.said())),
            _ => Vec::new(),
        }
    }

    /// The answer as a finding keeps it in the journal (`ended`), as it reads back (`of_kept`).
    fn kept(&self) -> Value {
        json!({
            "checkout": self.checkout, "ecosystem": self.ecosystem, "package": self.package,
            "source": self.source, "advisory": self.advisory, "kind": self.kind,
            "label": self.label, "summary": self.summary, "aliases": self.aliases,
            "exploited": self.exploited, "entries": self.entries, "fixed": self.fixed,
        })
    }

    fn of_kept(v: &Value) -> Affecting {
        let text = |k: &str| v[k].as_str().unwrap_or_default().to_string();
        let texts = |k: &str| {
            let all = v[k].as_array().into_iter().flatten();
            all.filter_map(Value::as_str).map(str::to_string).collect()
        };
        let kind = text("kind");
        Affecting {
            checkout: text("checkout"),
            ecosystem: text("ecosystem"),
            package: text("package"),
            source: text("source"),
            advisory: text("advisory"),
            modified: String::new(),
            label: label_of(&kind, v["label"].as_str()),
            kind,
            summary: v["summary"].as_str().map(str::to_string),
            aliases: texts("aliases"),
            exploited: v["exploited"] == true,
            entries: v["entries"].clone(),
            fixed: texts("fixed"),
            read_at: None,
            since_at: 0,
        }
    }

    /// The releases here the record affects, with where each is.
    pub fn affected(&self) -> Vec<(String, String)> {
        self.affected_from(None)
    }

    /// The releases the record affects of the entries from `from`, or of every entry.
    fn affected_from(&self, from: Option<&str>) -> Vec<(String, String)> {
        self.entries
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| e["affected"] == true && from.is_none_or(|f| e["from"] == f))
            .map(|e| {
                (
                    e["version"].as_str().unwrap_or_default().to_string(),
                    e["at"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }
}

/// The ecosystems whose lockfile packages the latest check compared with current data, in
/// the order of `FEEDS`. Through the records linked to it, this is all of the catalogue that
/// is compared with the estate: an ecosystem counts only where some checkout's lockfiles were
/// read in that check and its data was current then, so only a matched one (`matched_feeds`),
/// the only kind with places. Empty: the catalogue is compared with nothing.
pub fn catalogue_compared(conn: &Connection) -> rusqlite::Result<Vec<&'static str>> {
    let mut out = Vec::new();
    for feed in &FEEDS {
        let compared: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM vulnerability_place
             WHERE ecosystem = ?1 AND feed = 'current' AND lockfiles != 'not_read')",
            [feed.ecosystem],
            |r| r.get(0),
        )?;
        if compared {
            out.push(feed.ecosystem);
        }
    }
    Ok(out)
}

/// What is said of the catalogue's entries against this estate, after "they are": what they
/// are compared with, from `catalogue_compared`, and that for everything else whether any
/// affects the estate is unknown. It never reads as "none affects me".
pub fn catalogue_said(compared: &[&str]) -> String {
    if compared.is_empty() {
        return "not compared with anything in this estate, so whether any of them affects it is unknown".to_string();
    }
    format!(
        "compared, through the vulnerability records linked to them, only with the {} packages in the projects' lockfiles, so whether any of them affects anything else in this estate is unknown",
        crate::covered::listed(compared)
    )
}

/// Every "affects me" answer, most severe first by the source's label, then by project.
pub fn affecting(conn: &Connection) -> rusqlite::Result<Vec<Affecting>> {
    affecting_in(conn, "vulnerability_answer", "1", &[])
}

/// The "affects me" answers of `table`, `vulnerability_answer` or `vulnerability_answer_past`,
/// as `v`, that meet `condition`, ordered as `affecting` orders them.
fn affecting_in(
    conn: &Connection,
    table: &str,
    condition: &str,
    values: &[&dyn rusqlite::ToSql],
) -> rusqlite::Result<Vec<Affecting>> {
    let mut list: Vec<Affecting> = conn
        .prepare(&format!(
            "SELECT v.checkout, v.ecosystem, v.package, v.source, v.advisory, v.modified,
                    a.kind, a.severity, a.summary, a.aliases, v.entries, v.fixed, v.read_at,
                    v.since_at, k.advisory IS NOT NULL
             FROM {table} v
             JOIN advisory a ON a.source = v.source AND a.id = v.advisory
             -- Each linked record once, though several CVEs may link it.
             LEFT JOIN (SELECT DISTINCT source, advisory FROM vulnerability_linked) k
                    ON k.source = v.source AND k.advisory = v.advisory
             WHERE v.answer = 'affected' AND {condition}"
        ))?
        .query_map(values, |r| {
            let kind: String = r.get(6)?;
            let severity: Option<String> = r.get(7)?;
            let aliases: String = r.get(9)?;
            let entries: String = r.get(10)?;
            let fixed: String = r.get(11)?;
            Ok(Affecting {
                checkout: r.get(0)?,
                ecosystem: r.get(1)?,
                package: r.get(2)?,
                source: r.get(3)?,
                advisory: r.get(4)?,
                modified: r.get(5)?,
                label: label_of(&kind, severity.as_deref()),
                kind,
                summary: r.get(8)?,
                aliases: serde_json::from_str(&aliases).unwrap_or_default(),
                entries: serde_json::from_str(&entries).unwrap_or(Value::Null),
                fixed: serde_json::from_str(&fixed).unwrap_or_default(),
                read_at: r.get(12)?,
                since_at: r.get(13)?,
                exploited: r.get(14)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let rank = |a: &Affecting| {
        (
            a.kind != "malicious" && !a.exploited,
            LABELS.iter().position(|l| *l == a.label),
        )
    };
    list.sort_by(|a, b| {
        rank(a)
            .cmp(&rank(b))
            .then_with(|| a.checkout.cmp(&b.checkout))
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.advisory.cmp(&b.advisory))
    });
    Ok(list)
}

/// Why a finding about a package is no longer found, in the words of the journal and of the
/// contract (`NoLongerFound`): its project is gone; its project's lockfiles no longer declare a
/// release it was about; or they still declare it and its rule no longer finds it, as when a
/// record was withdrawn. It describes and decides nothing (`findings::hold`).
pub const NOT_DECLARED: &str = "not_declared";
pub const PROJECT_GONE: &str = "project_gone";
pub const NOT_NAMED: &str = "not_named";

/// Why the finding of `rule` about the component `about`, last found by the run `since`, is no
/// longer found, and what it was about then: the answers about its package in its checkout that
/// stood at that run, live or archived, and that the rule fires on (`fires`). An answer stood at
/// a run when it began at or before it and, archived, ended after it; runs are ordered by the
/// journal, not by their times, which two runs can share. The finding keeps them as what it was
/// about then (`findings::hold`); they are never read as what the lockfiles hold now. When none
/// is left, as when its answer was written over, it keeps nothing and the reason is told from its
/// checkout alone.
pub fn ended(
    conn: &Connection,
    rule: &str,
    about: &str,
    since: &str,
) -> rusqlite::Result<(&'static str, Value)> {
    // A run is placed by its `run_started` entry, one look-up on `journal_run`: every run these
    // ids name is a full check, and a check writes that entry before anything else of its id.
    let run = |of: &str| {
        format!("(SELECT seq FROM journal WHERE run_id = {of} AND entry = 'run_started')")
    };
    let began = format!("{} <= {}", run("v.since_run"), run("?1"));
    let stood = format!("{began} AND {} > {}", run("v.until_run"), run("?1"));
    let mut was = affecting_in(conn, "vulnerability_answer", &began, &[&since])?;
    was.extend(affecting_in(
        conn,
        "vulnerability_answer_past",
        &stood,
        &[&since],
    )?);
    was.retain(|a| a.is_about(about) && fires(rule, a, about));
    // Its own checkout: that of what it was about, else each whose lockfiles held it.
    let mut checkouts: BTreeSet<String> = was.iter().map(|a| a.checkout.clone()).collect();
    if checkouts.is_empty() {
        checkouts = conn
            .prepare("SELECT DISTINCT scope FROM assertion WHERE subject = ?1 AND reader = ?2")?
            .query_map(params![about, crate::lockfiles::READER], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
    }
    // A release declared now in that checkout's lockfiles: one it was about, or any when it
    // kept none.
    let declared = |checkout: &str, release: Option<&str>| {
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM assertion WHERE layer = 'live' AND reader = ?1
                            AND subject = ?2 AND scope = ?3 AND predicate = 'has_version'
                            AND (?4 IS NULL OR object = ?4))",
            params![crate::lockfiles::READER, about, checkout, release],
            |r| r.get::<_, bool>(0),
        )
    };
    let (mut gone, mut still) = (true, false);
    let query = format!("SELECT {}", crate::store::gone_entity("?1"));
    for c in &checkouts {
        gone &= conn.query_row(&query, [c], |r| r.get::<_, bool>(0))?;
        if was.is_empty() {
            still |= declared(c, None)?;
        }
    }
    for a in &was {
        for (release, _) in a.affected_of(about) {
            still |= declared(&a.checkout, Some(&release))?;
        }
    }
    let why = match (gone, still) {
        (true, _) => PROJECT_GONE,
        (_, true) => NOT_NAMED,
        _ => NOT_DECLARED,
    };
    Ok((why, was.iter().map(Affecting::kept).collect()))
}

/// Whether the finding of `rule` about `about` rests on the answer `a`, as a run raises it
/// (`match_dependencies`): a malicious record, naming only npm's placeholder for a removed name
/// or not; or, for an exploited vulnerability, a record linked to the catalogue.
fn fires(rule: &str, a: &Affecting, about: &str) -> bool {
    let placeholder = (a.affected_of(about).iter()).all(|(v, _)| v == "0.0.1-security");
    match rule {
        crate::findings::MALICIOUS_PACKAGE => a.kind == "malicious" && !placeholder,
        crate::findings::MALICIOUS_NAME_REMOVED => a.kind == "malicious" && placeholder,
        _ => a.exploited,
    }
}

/// What a finding about a package ended with, as the journal entry it rests on keeps it.
pub struct Kept {
    /// `NOT_DECLARED`, `PROJECT_GONE` or `NOT_NAMED`, as the entry says it.
    pub why: String,
    pub at: i64,
    pub was: Vec<Affecting>,
}

/// Every finding about a package that the core cleared, or whose package left, by its id, with
/// the latest entry it rests on that says why (`findings::hold`). A finding cleared by a build
/// that kept nothing is not here.
pub fn kept(conn: &Connection) -> rusqlite::Result<BTreeMap<String, Kept>> {
    let mut out = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT b.finding, j.at, j.text FROM finding_basis b
         JOIN journal j ON j.seq = b.journal JOIN finding f ON f.id = b.finding
         WHERE j.entry IN ('finding_cleared', 'finding_raised')
           AND (f.state = 'cleared' OR f.change = 'gone')
         ORDER BY j.seq",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    for row in rows {
        let (id, at, text): (String, i64, Option<String>) = row?;
        let v: Value = text
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        if let Some(why) = v["why"].as_str() {
            let was = v["was"].as_array().into_iter().flatten();
            let was = was.map(Affecting::of_kept).collect();
            let why = why.to_string();
            out.insert(id, Kept { why, at, was });
        }
    }
    Ok(out)
}

/// The totals of the answers the store holds. A record that affects several projects is one
/// answer in each, so every number a person reads counts records, not answers.
#[derive(Default)]
pub struct Totals {
    pub affected: usize,
    pub unknown: usize,
    pub not_affected: usize,
    /// Catalogue CVEs no record of the data names: "does not affect me, no signs" for
    /// every lockfile. `None` when the catalogue was never read.
    pub no_signs: Option<usize>,
    /// Affecting answers by label, in the order of `LABELS`.
    pub by_label: Vec<(&'static str, usize)>,
    /// What a person calls a known vulnerability: a record that affects something, counted
    /// once however many projects it affects; with the packages and projects it is in.
    pub records: usize,
    pub packages: usize,
    pub projects: usize,
    /// Affecting records by label, each counted once, in the order of `LABELS`.
    pub records_by_label: Vec<(&'static str, usize)>,
    /// "Don't know" answers by reason, in the order of `REASONS`.
    pub by_reason: Vec<(&'static str, usize)>,
    /// Packages with a "don't know" answer, each counted once, under the first of its reasons.
    /// A package in a place whose data is not current is one, whether or not a record held
    /// names it.
    pub packages_unknown: usize,
    pub packages_by_reason: Vec<(&'static str, usize)>,
    /// Those packages, as checkout, ecosystem and name, each with that first reason, in order.
    pub unknown_packages: Vec<(String, String, String, &'static str)>,
    /// The places whose lockfiles were not all read, as checkout, ecosystem, `partial`,
    /// `not_read` or `no_reader`, and why, in order: what they declare is not all known, whether
    /// or not a package was read there, so no answer about them is "not affected".
    pub unread_places: Vec<UnreadPlace>,
    /// Informational advisories held, which this version does not answer.
    pub informational: usize,
    /// Whether matching ever ran on this store.
    pub matched: bool,
    /// Projects with a place read in full and compared with current data, none of their places
    /// not wholly read: without one, nothing was compared and nothing is calm.
    pub projects_compared: usize,
    /// What the catalogue is compared with: `catalogue_compared`.
    pub catalogue_compared: Vec<&'static str>,
}

/// The feeds whose data is not current at `now`, each with why: an answer of "not affected"
/// that rests on one is "don't know" when it is asked, whatever the check that wrote it found.
pub fn stale_at(conn: &Connection, now: i64) -> rusqlite::Result<HashMap<&'static str, String>> {
    Ok(freshness(conn, now)?
        .into_iter()
        .filter_map(|f| f.not_current.map(|why| (f.feed.source, why)))
        .collect())
}

/// An answer as it stands when asked for a project with a place not wholly read
/// (`unread_places`): "not affected" becomes "don't know", as `immunity vulnerability` gives it.
fn untold_now<'a>(answer: &'a str, reason: &'a str, untold: bool) -> (&'a str, &'a str) {
    if answer == "not_affected" && untold {
        ("unknown", PLACE_NOT_READ)
    } else {
        (answer, reason)
    }
}

/// An answer as it stands when asked: "not affected" whose feed is not current at that time
/// becomes "don't know" because of the data (`stale_at`).
fn judged_now<'a>(answer: &'a str, reason: &'a str, stale: bool) -> (&'a str, &'a str) {
    if answer == "not_affected" && stale {
        ("unknown", FEED_NOT_READ)
    } else {
        (answer, reason)
    }
}

/// The totals as they stand at `now`: the answers the last check wrote, with "not affected"
/// counted as "don't know" where its data is not current at `now`.
pub fn totals(conn: &Connection, now: i64) -> rusqlite::Result<Totals> {
    let mut t = Totals {
        matched: conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM vulnerability_place)",
            [],
            |r| r.get(0),
        )?,
        catalogue_compared: catalogue_compared(conn)?,
        ..Totals::default()
    };
    let stale = stale_at(conn, now)?;
    let stale_eco: HashSet<&str> = FEEDS
        .iter()
        .filter(|f| stale.contains_key(f.source))
        .map(|f| f.ecosystem)
        .collect();
    // What cannot be told of each project, as every answer gives it.
    let unread = unread_places(conn)?;
    let untold: HashSet<String> = unread.iter().map(|p| p.0.clone()).collect();
    let mut counts: Vec<(String, String, i64)> = Vec::new();
    let rows: Vec<(String, String, String, String, i64)> = conn
        .prepare(
            "SELECT checkout, answer, reason, source, COUNT(*) FROM vulnerability_answer
             GROUP BY checkout, answer, reason, source",
        )?
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (checkout, answer, reason, source, n) in &rows {
        let (answer, reason) = judged_now(answer, reason, stale.contains_key(source.as_str()));
        let (answer, reason) = untold_now(answer, reason, untold.contains(checkout));
        match counts
            .iter_mut()
            .find(|(a, r, _)| a == answer && r == reason)
        {
            Some(c) => c.2 += n,
            None => counts.push((answer.to_string(), reason.to_string(), *n)),
        }
    }
    for (answer, _, n) in &counts {
        let n = *n as usize;
        match answer.as_str() {
            "affected" => t.affected += n,
            "unknown" => t.unknown += n,
            _ => t.not_affected += n,
        }
    }
    let mut labels: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut records: BTreeMap<(String, String), &'static str> = BTreeMap::new();
    let mut packages: BTreeSet<(String, String)> = BTreeSet::new();
    let mut projects: BTreeSet<String> = BTreeSet::new();
    for a in affecting(conn)? {
        *labels.entry(a.label).or_default() += 1;
        records.insert((a.source, a.advisory), a.label);
        packages.insert((a.ecosystem, a.package));
        projects.insert(a.checkout);
    }
    let in_order = |of: &BTreeMap<&'static str, usize>| -> Vec<(&'static str, usize)> {
        LABELS
            .iter()
            .filter_map(|l| of.get(l).map(|n| (*l, *n)))
            .collect()
    };
    t.by_label = in_order(&labels);
    let mut record_labels: BTreeMap<&'static str, usize> = BTreeMap::new();
    for label in records.values() {
        *record_labels.entry(label).or_default() += 1;
    }
    t.records_by_label = in_order(&record_labels);
    (t.records, t.packages, t.projects) = (records.len(), packages.len(), projects.len());
    // A package counts once, under the first reason of its "don't know" answers.
    let unknown: Vec<(String, String, String, String)> = conn
        .prepare(
            "SELECT checkout, ecosystem, package, answer, reason, source FROM vulnerability_answer
             WHERE answer != 'affected'",
        )?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|(c, e, p, answer, reason, source)| {
            let (answer, reason) =
                judged_now(&answer, &reason, stale.contains_key(source.as_str()));
            let (answer, reason) = untold_now(answer, reason, untold.contains(&c));
            (answer == "unknown").then(|| (c, e, p, reason.to_string()))
        })
        .collect();
    let rank_of = |reason: &str| {
        REASONS
            .iter()
            .position(|r| *r == reason)
            .unwrap_or(REASONS.len())
    };
    let mut first: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (c, e, p, reason) in unknown {
        let rank = rank_of(&reason);
        let slot = first.entry((c, e, p)).or_insert(rank);
        *slot = (*slot).min(rank);
    }
    // Data that is not current, or was never read, may lack the record that names a package,
    // so every package of such a place is "don't know" with the feed's reason. One that no
    // record held names has no answer of its own and is one more "don't know" answer here,
    // standing for the records the data lacks.
    let stale_places: HashSet<(String, String)> = conn
        .prepare("SELECT checkout, ecosystem, feed FROM vulnerability_place")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter(|(_, e, feed)| feed == "not_current" || stale_eco.contains(e.as_str()))
        .map(|(c, e, _)| (c, e))
        .collect();
    let mut unanswered = 0;
    for (c, e, p) in held_packages(conn)?.into_keys() {
        if !stale_places.contains(&(c.clone(), e.to_string())) {
            continue;
        }
        if let std::collections::btree_map::Entry::Vacant(slot) = first.entry((c, e.to_string(), p))
        {
            slot.insert(rank_of(FEED_NOT_READ));
            unanswered += 1;
        }
    }
    t.unknown += unanswered;
    t.by_reason = REASONS
        .iter()
        .map(|code| {
            let mut n: usize = counts
                .iter()
                .filter(|(a, r, _)| a == "unknown" && r == code)
                .map(|(_, _, n)| *n as usize)
                .sum();
            if *code == FEED_NOT_READ {
                n += unanswered;
            }
            (*code, n)
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    t.packages_unknown = first.len();
    t.packages_by_reason = REASONS
        .iter()
        .enumerate()
        .map(|(i, code)| (*code, first.values().filter(|r| **r == i).count()))
        .filter(|(_, n)| *n > 0)
        .collect();
    // Every reason an answer is written with is one of `REASONS`.
    t.unknown_packages = first
        .into_iter()
        .map(|((c, e, p), r)| (c, e, p, REASONS.get(r).copied().unwrap_or_default()))
        .collect();
    // A project counts as compared where a place of it was read in full against data current
    // at the check and now, it has no place not wholly read, and none of its packages is
    // "don't know", whatever the reason: one such package and it was not compared in full.
    let untold_package: HashSet<&str> = t.unknown_packages.iter().map(|u| u.0.as_str()).collect();
    let mut compared: BTreeMap<String, bool> = BTreeMap::new();
    for (c, e, lockfiles, feed) in conn
        .prepare("SELECT checkout, ecosystem, lockfiles, feed FROM vulnerability_place")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    {
        let whole = lockfiles == "full" && feed == "current" && !stale_eco.contains(e.as_str());
        *compared.entry(c).or_insert(false) |= whole;
    }
    t.projects_compared = compared
        .into_iter()
        .filter(|(c, whole)| *whole && !untold.contains(c) && !untold_package.contains(c.as_str()))
        .count();
    t.unread_places = unread;
    t.informational = conn.query_row(
        "SELECT COUNT(*) FROM advisory
         WHERE kind = 'informational' AND withdrawn IS NULL AND gone_at IS NULL",
        [],
        |r| r.get::<_, i64>(0),
    )? as usize;
    let read: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM feed_reading WHERE source = ?1 AND outcome != 'failed')",
        [crate::threats::SOURCE],
        |r| r.get(0),
    )?;
    let catalogue: i64 = conn.query_row(
        "SELECT COUNT(*) FROM threat t WHERE t.gone_at IS NULL
           AND NOT EXISTS (SELECT 1 FROM vulnerability_linked l WHERE l.cve = t.id)",
        [],
        |r| r.get(0),
    )?;
    t.no_signs = read.then_some(catalogue as usize);
    Ok(t)
}

/// What one reason of "don't know" says of packages, for one and for many.
pub fn reason_words(code: &str) -> (&'static str, &'static str) {
    match code {
        NOT_FROM_REGISTRY => (
            "1 does not come from the public registry",
            "{n} do not come from the public registry",
        ),
        NOT_COMPARABLE => (
            "1 has a version that cannot be compared with a record's",
            "{n} have a version that cannot be compared with a record's",
        ),
        NOT_COVERED => (
            "1 is newer than the last release a record names as affected, and no fix is named",
            "{n} are newer than the last release a record names as affected, and no fix is named",
        ),
        INDEX_NOT_RECORDED => (
            "1 comes from an index its lockfile does not record",
            "{n} come from an index their lockfiles do not record",
        ),
        PLACE_NOT_READ => (
            "1 is in a project whose lockfiles were not all read, such as one with a bun.lockb or a uv.lock",
            "{n} are in a project whose lockfiles were not all read, such as one with a bun.lockb or a uv.lock",
        ),
        FEED_NOT_READ => (
            "1 is in an ecosystem whose list of known vulnerabilities was never read or is not current",
            "{n} are in an ecosystem whose list of known vulnerabilities was never read or is not current",
        ),
        _ => (
            "1 is in an ecosystem this version has no data for",
            "{n} are in an ecosystem this version has no data for",
        ),
    }
}

/// `{n}` packages for one reason, in words.
pub fn reason_said(code: &str, n: usize) -> String {
    let (one, many) = reason_words(code);
    if n == 1 {
        one.to_string()
    } else {
        many.replace("{n}", &n.to_string())
    }
}

/// The oldest time a matched feed that is not current was last read, and whether any is not
/// current.
pub fn stale(conn: &Connection, now: i64) -> rusqlite::Result<Option<Option<i64>>> {
    let fresh = matched_freshness(conn, now)?;
    let old: Vec<&Fresh> = fresh.iter().filter(|f| f.not_current.is_some()).collect();
    if old.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        old.iter().filter_map(|f| f.reading.map(|r| r.1)).min(),
    ))
}

// ---- The machine-readable forms. ----

/// Where a lockfile line is, as a person finds it: under the home folder unless it starts at
/// the root.
pub fn at_shown(at: &str) -> String {
    if at.starts_with('/') {
        at.to_string()
    } else {
        format!("~/{at}")
    }
}

/// The totals as the contract gives them, with each feed and whether it is current now: the
/// status's part about known vulnerabilities, and the totals of `immunity vulnerabilities`.
/// Absent when matching never ran on this store: nothing was counted, so nothing reads as 0.
pub fn totals_message(
    conn: &Connection,
    now: i64,
) -> rusqlite::Result<Option<v1::VulnerabilityTotals>> {
    // Matching runs in every check that finishes.
    if crate::status::latest_finished(conn)?.is_none() {
        return Ok(None);
    }
    let t = totals(conn, now)?;
    totals_of(conn, now, &t).map(Some)
}

/// The totals `t` as the contract gives them.
fn totals_of(conn: &Connection, now: i64, t: &Totals) -> rusqlite::Result<v1::VulnerabilityTotals> {
    let n = |x: usize| x as u64;
    let by = |list: &[(&'static str, usize)]| -> Vec<v1::Count> {
        list.iter()
            .map(|(name, count)| v1::Count {
                name: name.to_string(),
                count: n(*count),
            })
            .collect()
    };
    Ok(v1::VulnerabilityTotals {
        affected: n(t.affected),
        unknown: n(t.unknown),
        not_affected_known: n(t.not_affected),
        not_affected_no_signs: t.no_signs.map(n),
        affected_by_label: by(&t.by_label),
        affected_records: n(t.records),
        affected_packages: n(t.packages),
        affected_projects: n(t.projects),
        affected_records_by_label: by(&t.records_by_label),
        unknown_by_reason: by(&t.by_reason),
        unknown_packages: n(t.packages_unknown),
        unknown_packages_by_reason: by(&t.packages_by_reason),
        matched_this_store: t.matched,
        feeds: freshness(conn, now)?
            .iter()
            .map(|f| v1::FeedFreshness {
                source: f.feed.source.to_string(),
                ecosystem: f.feed.ecosystem.to_string(),
                matched: crate::lockfiles::has_reader(f.feed.ecosystem),
                read_at: f.reading.map(|r| r.1),
                current: f.not_current.is_none(),
                not_current_why: f.not_current.clone(),
            })
            .collect(),
        informational_records: n(t.informational),
        places_not_read: n(t.unread_places.iter().filter(|p| p.2 != NONE_FOUND).count()),
        projects_not_read: n(project_counts(&t.unread_places).1),
        projects_without_lockfile: n(project_counts(&t.unread_places).0),
        projects_compared: n(t.projects_compared),
        projects_found: Some(projects_found(conn)?),
        affected_exploited: n((affecting(conn)?.iter())
            .filter(|a| a.exploited)
            .map(|a| a.advisory.as_str())
            .collect::<HashSet<&str>>()
            .len()),
    })
}

/// Whether every project on this Mac was found (`covered::projects_found`): every answer here
/// that speaks of the projects as a whole, in the totals, for one id and on the page, speaks
/// only for the projects found while not.
pub fn projects_found(conn: &Connection) -> rusqlite::Result<v1::ProjectsFound> {
    let latest = crate::view::latest_coverage(conn)?;
    let this = crate::covered::this_machine(conn)?;
    Ok(crate::covered::projects_found(&latest, this.as_deref()))
}

/// Why the totals and the "affects" answers are absent from a store that has them not.
pub const NEVER_MATCHED: &str = "the projects' lockfiles have never been matched against vulnerability data in this store; the next check does";

/// The most "affects me" answers `immunity vulnerabilities` lists; the total is always given.
pub const SHOWN: usize = 200;

/// A record the data holds, as `immunity vulnerability` reads it.
struct Held {
    source: String,
    id: String,
    modified: String,
    kind: String,
    withdrawn: Option<String>,
    gone: bool,
    summary: Option<String>,
    aliases: Vec<String>,
}

fn held_records(conn: &Connection, id: &str) -> rusqlite::Result<Vec<Held>> {
    // A record by its own id, or by an alias such as a CVE id. The alias is matched as the
    // whole quoted string inside the JSON array, never as a part of one.
    let quoted = serde_json::to_string(id).unwrap_or_default();
    let found: Vec<Held> = conn
        .prepare(
            "SELECT source, id, modified, kind, withdrawn, gone_at IS NOT NULL, summary, aliases
             FROM advisory WHERE id = ?1 OR instr(aliases, ?2) > 0 ORDER BY source, id",
        )?
        .query_map(params![id, quoted], |r| {
            let aliases: String = r.get(7)?;
            Ok(Held {
                source: r.get(0)?,
                id: r.get(1)?,
                modified: r.get(2)?,
                kind: r.get(3)?,
                withdrawn: r.get(4)?,
                gone: r.get(5)?,
                summary: r.get(6)?,
                aliases: serde_json::from_str(&aliases).unwrap_or_default(),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(found
        .into_iter()
        .filter(|h| h.id == id || h.aliases.iter().any(|a| a == id))
        .collect())
}

/// A place whose lockfiles were not all read: checkout, ecosystem, how they were read and why.
pub type UnreadPlace = (String, String, String, Option<String>);

/// How the lockfiles of a place were read when this version has no reader for their kind.
pub const NO_READER: &str = "no_reader";
/// How the lockfiles of a project were read when none this version knows was found in it.
pub const NONE_FOUND: &str = "none_found";
/// How the lockfiles of a project were read when the reading of lockfiles did not open it.
pub const NOT_READ: &str = "not_read";

/// The places whose lockfiles were not all read, in order: what cannot be told about every
/// project, built here alone, so the list, the totals and the answer for one record, held or
/// not, say the same. A place is a project's lockfiles of one ecosystem, read in part or not in
/// the latest check (`vulnerability_place`), of a kind this version has no reader for
/// (`no_reader_places`), a project in which the latest check found no lockfile at all, and one
/// the reading of lockfiles did not open in the latest check, which no other table holds. The
/// last two stand for every ecosystem, `any`. What they declare is not known, so none is ever
/// "not affected".
pub fn unread_places(conn: &Connection) -> rusqlite::Result<Vec<UnreadPlace>> {
    let rows: Vec<UnreadPlace> = conn
        .prepare(
            "SELECT checkout, ecosystem, lockfiles, lockfiles_why FROM vulnerability_place
             ORDER BY checkout, ecosystem",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    // The places the latest matching judged. Any other place the latest reading of lockfiles
    // found is not read, whatever feeds this build has: the store may have been written by a
    // build with other feeds.
    let rowed: HashSet<(String, String)> =
        rows.iter().map(|p| (p.0.clone(), p.1.clone())).collect();
    let mut out: Vec<UnreadPlace> = rows.into_iter().filter(|p| p.2 != "full").collect();
    out.extend(
        no_reader_places(conn, &rowed)?
            .into_iter()
            .map(|(c, e, names)| (c, e, NO_READER.to_string(), Some(no_reader_said(&names)))),
    );
    // Each project the store holds, with its latest reading of lockfiles, if any: none found
    // only where that reading opened it in the latest check and found nothing; not read where
    // no reading opened it then.
    // The latest check that looked for projects: the reading of lockfiles opens what it found
    // in that same check, so a note from an earlier one is not of the latest check.
    let latest_run: Option<String> = conn
        .query_row(
            "SELECT run_id FROM coverage WHERE reader IN (?1, ?2) ORDER BY id DESC LIMIT 1",
            [crate::lockfiles::READER, crate::checkouts::READER],
            |r| r.get(0),
        )
        .optional()?;
    let projects: Vec<(String, Option<String>, Option<String>)> = conn
        .prepare(&format!(
            "SELECT e.id, c.reason, c.run_id FROM entity e
             LEFT JOIN coverage c ON c.id = (SELECT MAX(l.id) FROM coverage l
                                             WHERE l.reader = ?2 AND l.scope = e.id)
             WHERE e.type = ?1 AND NOT {}
               AND EXISTS (SELECT 1 FROM assertion a WHERE a.layer = 'live' AND a.subject = e.id)
             ORDER BY e.id",
            crate::store::gone_entity("e.id")
        ))?
        .query_map([crate::checkouts::TYPE, crate::lockfiles::READER], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (checkout, reason, run) in projects {
        let none = reason.as_deref() == Some(crate::lockfiles::NONE_FOUND_NOTE);
        let (lockfiles, why) = match run {
            None => (NOT_READ, NEVER_OPENED),
            Some(run) if none && Some(&run) == latest_run.as_ref() => (NONE_FOUND, NONE_FOUND_SAID),
            Some(_) if none => (NOT_READ, NOT_OPENED_LATEST),
            // A reading that found lockfiles has its places in `vulnerability_place`.
            Some(_) => continue,
        };
        out.push((
            checkout,
            ANY_ECOSYSTEM.to_string(),
            lockfiles.to_string(),
            Some(why.to_string()),
        ));
    }
    out.sort();
    Ok(out)
}

/// Why a project the reading of lockfiles never opened is not compared.
const NEVER_OPENED: &str = "the reading of lockfiles never opened it";
/// Why a project it did not open in the latest check is not compared.
const NOT_OPENED_LATEST: &str = "its lockfiles were not read in the latest check";

/// How many projects in `places` have no lockfile this version reads (`none_found`), and how
/// many others were not wholly read: the first are one counted item, never a row per record.
pub fn project_counts(places: &[UnreadPlace]) -> (usize, usize) {
    let none: BTreeSet<&str> = places
        .iter()
        .filter(|p| p.2 == NONE_FOUND)
        .map(|p| p.0.as_str())
        .collect();
    let not_read: BTreeSet<&str> = places
        .iter()
        .filter(|p| p.2 != NONE_FOUND)
        .map(|p| p.0.as_str())
        .collect();
    (none.len(), not_read.len())
}

/// The ecosystem of a place that stands for every ecosystem of a project.
const ANY_ECOSYSTEM: &str = "any";
/// Why a project with no lockfile is not compared.
const NONE_FOUND_SAID: &str = "no lockfile this version knows of was found in it";

/// Each project with a place whose lockfiles were not all read, with why, every place said.
fn untold(places: &[UnreadPlace]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (checkout, ecosystem, lockfiles, why) in places {
        out.entry(checkout.clone()).or_default().push(match why {
            Some(why) => format!("{ecosystem} lockfiles {lockfiles}: {why}"),
            None => format!("{ecosystem} lockfiles {lockfiles}"),
        });
    }
    out.into_iter()
        .map(|(c, said)| {
            (
                c,
                format!(
                    "not every lockfile of the project was read ({})",
                    said.join("; ")
                ),
            )
        })
        .collect()
}

/// The places whose lockfiles are of a kind this version has no reader for, in an ecosystem no
/// data was matched for, as checkout, ecosystem and the kinds by name, from each checkout's
/// latest reading of lockfiles. Such a project was compared with nothing there, though every
/// lockfile it has of a matched ecosystem was read. A kind whose place the latest matching
/// judged (`rowed`), such as `bun.lockb` for npm, is not here: that place is `partial`
/// (`vulnerability_place`). Nor is a kind of no ecosystem a record can be about. The store
/// keeps only the ecosystem of a record's own feed, so a place of any other OSV ecosystem
/// stands, through `untold`, between the project and every record, which may name that
/// ecosystem too.
fn no_reader_places(
    conn: &Connection,
    rowed: &HashSet<(String, String)>,
) -> rusqlite::Result<Vec<(String, String, String)>> {
    let rows: Vec<(String, String)> = conn
        .prepare(&format!(
            "SELECT c.scope, l.name FROM coverage c JOIN coverage_lack l ON l.coverage = c.id
             WHERE c.reader = ?1 AND l.what = ?2 AND l.name IS NOT NULL
               AND c.id = (SELECT MAX(o.id) FROM coverage o WHERE o.reader = c.reader AND o.scope = c.scope)
               AND NOT {}
             ORDER BY c.scope, l.name",
            crate::store::gone_entity("c.scope")
        ))?
        .query_map(
            [crate::lockfiles::READER, crate::lockfiles::LOCKFILE_KIND],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .collect::<rusqlite::Result<_>>()?;
    let mut places: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for (checkout, name) in rows {
        // A kind of no ecosystem a record can be about, such as `flake.lock`, stands between no
        // record and the project: it is not a place, and the status names it among what this
        // version does not read.
        let Some(ecosystem) = crate::lockfiles::ecosystem_of(&name) else {
            continue;
        };
        let place = (checkout, ecosystem.to_string());
        if !rowed.contains(&place) {
            places.entry(place).or_default().push(name);
        }
    }
    Ok(places
        .into_iter()
        .map(|((c, e), names)| (c, e, names.join(", ")))
        .collect())
}

/// Why the lockfiles of a place of `no_reader_places` were not read: these kinds, by name.
fn no_reader_said(names: &str) -> String {
    format!("this version has no reader for {names}")
}

/// The places whose lockfiles were not all read as the contract gives them, at most `SHOWN`.
fn unread_of(places: &[UnreadPlace], this: Option<&crate::findings::This>) -> v1::UnreadPlaces {
    v1::UnreadPlaces {
        items: places
            .iter()
            .take(SHOWN)
            .map(|(checkout, ecosystem, lockfiles, why)| v1::UnreadPlace {
                project_text: whole(&crate::findings::place(checkout, this)),
                ecosystem: ecosystem.clone(),
                lockfiles: lockfiles.clone(),
                why_text: why.as_deref().map(whole),
            })
            .collect(),
        total: places.len() as u64,
    }
}

/// A place's row: checkout, ecosystem, lockfiles, why, feed, why, when the data was read.
type Place = (
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<i64>,
);

// ---- The contract's messages. ----

/// The version of the contract this build prints.
const FORMAT: u32 = 1;

/// `immunity vulnerabilities`: the "affects" answers, most severe first, at most `SHOWN`, with the
/// totals. Without a store there is nothing to count, and `not_computed` says so.
pub fn list(conn: Option<&Connection>, now: i64) -> rusqlite::Result<v1::Vulnerabilities> {
    let mut out = v1::Vulnerabilities {
        format: FORMAT,
        answered_at: now,
        declared_note: DECLARED.to_string(),
        ..Default::default()
    };
    let Some(conn) = conn else {
        out.not_computed.push(no_store("totals"));
        out.not_computed.push(no_store("affected"));
        return Ok(out);
    };
    let this = crate::findings::This::of(conn, crate::covered::this_machine(conn)?)?;
    let all = affecting(conn)?;
    let listed = catalogue_current(conn, now)?;
    out.store_id = Some(crate::store::id(conn)?);
    // Matching runs in every check that finishes.
    if crate::status::latest_finished(conn)?.is_none() {
        for section in ["totals", "affected"] {
            out.not_computed.push(v1::NotComputed {
                section: section.to_string(),
                reason: NEVER_MATCHED.to_string(),
            });
        }
        return Ok(out);
    }
    let t = totals(conn, now)?;
    out.totals = Some(totals_of(conn, now, &t)?);
    out.unknown = Some(v1::UnknownPackages {
        items: t
            .unknown_packages
            .iter()
            .take(SHOWN)
            .map(
                |(checkout, ecosystem, package, reason)| v1::UnknownPackage {
                    project_text: whole(&crate::findings::place(checkout, this.as_ref())),
                    ecosystem: ecosystem.clone(),
                    package_text: whole(package),
                    reason: reason.to_string(),
                },
            )
            .collect(),
        total: t.unknown_packages.len() as u64,
    });
    out.unread = Some(unread_of(&t.unread_places, this.as_ref()));
    out.affected = Some(v1::AffectedPackages {
        items: all
            .iter()
            .take(SHOWN)
            .map(|a| affected_message(a, this.as_ref(), listed))
            .collect(),
        total: all.len() as u64,
    });
    Ok(out)
}

/// Whether a record is used in attacks: `true` while it is on the catalogue's list, however old
/// the list, and `false` only while the catalogue is current (`catalogue_current`); else not
/// known.
pub fn exploited(on_list: bool, current: bool) -> Option<bool> {
    (on_list || current).then_some(on_list)
}

/// Whether the catalogue of exploited vulnerabilities is current at `now`, the answer's time,
/// by the rule for data answers rest on (`read_not_current` with `threats::CURRENT_FOR`). Only a
/// current catalogue says a record is off its list.
pub fn catalogue_current(conn: &Connection, now: i64) -> rusqlite::Result<bool> {
    let read = crate::threats::last_good(conn)?.map(|(at, _)| at);
    Ok(catalogue_current_at(read, now))
}

/// The same rule over when the catalogue was last read whole, as `Threats.read_at` gives it.
pub fn catalogue_current_at(read_at: Option<i64>, now: i64) -> bool {
    read_not_current(read_at, now, crate::threats::CURRENT_FOR).is_none()
}

fn no_store(section: &str) -> v1::NotComputed {
    v1::NotComputed {
        section: section.to_string(),
        reason: crate::store::NO_STORE_REASON.to_string(),
    }
}

/// An "affects" answer: the package in its project and the record. Whether the record is used in
/// attacks is absent while that list is not current (`exploited`), so that not known is never off
/// the list.
fn affected_message(
    a: &Affecting,
    this: Option<&crate::findings::This>,
    listed: bool,
) -> v1::AffectedPackage {
    v1::AffectedPackage {
        project_text: whole(&crate::findings::place(&a.checkout, this)),
        ecosystem: a.ecosystem.clone(),
        package_text: whole(&a.package),
        releases: a
            .affected()
            .iter()
            .map(|(v, at)| v1::PackageRelease {
                version_text: whole(v),
                at_text: whole(&at_shown(at)),
            })
            .collect(),
        record: Some(v1::PackageRecord {
            id_text: whole(&a.advisory),
            aliases_text: a.aliases.iter().map(|s| whole(s)).collect(),
            source: source_name(&a.advisory).to_string(),
            label: a.label.to_string(),
            exploited: exploited(a.exploited, listed),
            summary_text: a.summary.as_deref().map(whole),
            fixed_text: a.fixed.iter().map(|s| whole(s)).collect(),
        }),
        feed: a.source.clone(),
        modified_text: whole(&a.modified),
        kind: a.kind.clone(),
        data_read_at: a.read_at,
        since_at: a.since_at,
    }
}

/// `immunity vulnerability <id>`: the answer for one record id or CVE id in every checkout whose
/// lockfiles were read, with what it rests on. An id the data does not hold is said as such,
/// never as "not affected".
pub fn one(conn: Option<&Connection>, id: &str, now: i64) -> rusqlite::Result<v1::Vulnerability> {
    let mut out = v1::Vulnerability {
        format: FORMAT,
        answered_at: now,
        // What was asked, cut: it may hold a secret.
        id_text: crate::secrets::said(id),
        declared_note: DECLARED.to_string(),
        ..Default::default()
    };
    let Some(conn) = conn else {
        out.not_computed.push(no_store("vulnerability"));
        return Ok(out);
    };
    out.store_id = Some(crate::store::id(conn)?);
    out.projects_found = Some(projects_found(conn)?);
    let this = crate::findings::This::of(conn, crate::covered::this_machine(conn)?)?;
    let place_of = |c: &str| whole(&crate::findings::place(c, this.as_ref()));
    let records = held_records(conn, id)?;
    // Off the list only while the catalogue is current (`exploited`).
    out.in_catalogue = exploited(
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM threat WHERE id = ?1 AND gone_at IS NULL)",
            [id],
            |r| r.get(0),
        )?,
        catalogue_current(conn, now)?,
    );
    let in_catalogue = out.in_catalogue == Some(true);
    let places: Vec<Place> = conn
        .prepare(
            "SELECT checkout, ecosystem, lockfiles, lockfiles_why, feed, feed_why, read_at
             FROM vulnerability_place ORDER BY checkout, ecosystem",
        )?
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    // Whether the data is current is judged now, when it is asked, not as the check found it.
    let stale = stale_at(conn, now)?;
    let stale_of = |eco: &str| {
        FEEDS
            .iter()
            .find(|f| f.ecosystem == eco)
            .and_then(|f| stale.get(f.source))
    };
    let answer = |word: &str| crate::contract::value_of::<v1::PackageAnswer>(word);
    // What cannot be told about every project (`unread_places`). The store does not keep the
    // other ecosystems a record names, so a project with any place not wholly read cannot be
    // told for any record: none of its answers is "not affected".
    let unread = unread_places(conn)?;
    let untold = untold(&unread);
    let untell = |checkout: &str, a: &mut v1::PlaceAnswer| {
        let Some(why) = untold.get(checkout) else {
            return;
        };
        if a.answer == Some(answer("not_affected")) {
            a.answer = Some(answer("unknown"));
            a.reason = Some(PLACE_NOT_READ.to_string());
            a.detail_text = Some(whole(why));
            a.certainty = None;
            a.openvex = None;
        }
        for p in a
            .packages
            .iter_mut()
            .filter(|p| p.answer == answer("not_affected"))
        {
            p.answer = answer("unknown");
            p.reason = Some(PLACE_NOT_READ.to_string());
            p.detail_text = whole(why);
            p.certainty = None;
            p.openvex = None;
        }
    };
    // A place no row of `vulnerability_place` holds: lockfiles of a kind with no reader, or a
    // project not opened. A project with no lockfile has no row: it is counted, not answered.
    let unrowed = |places: &mut Vec<v1::PlaceAnswer>, ecosystem: Option<&str>| {
        for (checkout, eco, lockfiles, why) in &unread {
            if lockfiles == NO_READER || (lockfiles == NOT_READ && eco == ANY_ECOSYSTEM) {
                places.push(v1::PlaceAnswer {
                    project_text: place_of(checkout),
                    ecosystem: ecosystem.map_or(eco.clone(), str::to_string),
                    answer: Some(answer("unknown")),
                    reason: Some(PLACE_NOT_READ.to_string()),
                    detail_text: untold.get(checkout).or(why.as_ref()).map(|w| whole(w)),
                    ..Default::default()
                });
            }
        }
    };
    // A place's answer for a record that names none of its packages, from the conditions of
    // the place: "not affected" only when its lockfiles were all read and the data is
    // current, at the check and now, with this certainty.
    let derived = |p: &Place, certainty: &str| {
        let mut a = v1::PlaceAnswer {
            project_text: place_of(&p.0),
            ecosystem: p.1.clone(),
            data_read_at: p.6,
            ..Default::default()
        };
        let now_stale = stale_of(&p.1);
        match (p.2.as_str(), p.4.as_str()) {
            ("full", "current") if now_stale.is_none() => {
                a.answer = Some(answer("not_affected"));
                a.certainty = Some(certainty.to_string());
            }
            ("full", _) => {
                a.answer = Some(answer("unknown"));
                a.reason = Some(FEED_NOT_READ.to_string());
                a.detail_text = now_stale.map(String::as_str).or(p.5.as_deref()).map(whole);
            }
            _ => {
                a.answer = Some(answer("unknown"));
                a.reason = Some(PLACE_NOT_READ.to_string());
                a.detail_text = p.3.as_deref().map(whole);
            }
        }
        a
    };
    if records.is_empty() {
        if in_catalogue {
            out.data = Some(v1::RecordData::NoRecord as i32);
            out.answers = places
                .iter()
                .map(|p| {
                    let mut a = derived(p, "no_signs");
                    untell(&p.0, &mut a);
                    a
                })
                .collect();
            unrowed(&mut out.answers, None);
            out.answers.sort_by(|a, b| {
                (&a.project_text, &a.ecosystem).cmp(&(&b.project_text, &b.ecosystem))
            });
            let found = crate::covered::Found::of(out.projects_found.as_ref()).0;
            out.said = Some(no_record_said(&out.answers, found));
        } else {
            out.data = Some(v1::RecordData::UnknownId as i32);
            out.said = Some("The data held here has no record with this id or alias, so nothing can be said about it; this is not an answer that it does not affect you.".to_string());
        }
        return Ok(out);
    }
    out.data = Some(v1::RecordData::Held as i32);
    for r in &records {
        let feed = FEEDS.iter().find(|f| f.source == r.source);
        let eco = feed.map_or("", |f| f.ecosystem);
        let mut v = v1::RecordAnswers {
            record_text: whole(&r.id),
            record_source: source_name(&r.id).to_string(),
            feed: r.source.clone(),
            ecosystem: eco.to_string(),
            modified_text: whole(&r.modified),
            kind: r.kind.clone(),
            summary_text: r.summary.as_deref().map(whole),
            ..Default::default()
        };
        if r.withdrawn.is_some() || r.gone {
            v.said = Some(
                if r.gone {
                    "The record has left the data, so it matches nothing."
                } else {
                    "The record is withdrawn, so it matches nothing."
                }
                .to_string(),
            );
            out.records.push(v);
            continue;
        }
        if r.kind == "informational" {
            v.said = Some(
                "An informational advisory, such as an unmaintained crate: this version does not answer these."
                    .to_string(),
            );
            out.records.push(v);
            continue;
        }
        let mine: Vec<&Place> = places.iter().filter(|p| p.1 == eco).collect();
        let mut more: Vec<v1::PlaceAnswer> = Vec::new();
        unrowed(&mut more, Some(eco));
        more.retain(|a| !mine.iter().any(|p| place_of(&p.0) == a.project_text));
        if mine.is_empty() && more.is_empty() {
            // No answer in any place is not "affects none": nothing was compared.
            v.said = Some(format!(
                "The store knows no project whose {eco} lockfiles it compared with this record, so whether it affects one cannot be told."
            ));
            out.records.push(v);
            continue;
        }
        v.answered = true;
        let mut stored: HashMap<String, Vec<v1::PackageAnswerOf>> = HashMap::new();
        let mut stmt = conn.prepare(
            "SELECT checkout, package, answer, reason, detail, entries, fixed, read_at, since_at,
                    modified
             FROM vulnerability_answer WHERE source = ?1 AND advisory = ?2
             ORDER BY checkout, package",
        )?;
        let rows = stmt.query_map(params![r.source, r.id], |q| {
            let entries: String = q.get(5)?;
            let fixed: String = q.get(6)?;
            let word: String = q.get(2)?;
            let reason: String = q.get(3)?;
            let entries: Value = serde_json::from_str(&entries).unwrap_or(Value::Null);
            let mut p = v1::PackageAnswerOf {
                package_text: whole(&q.get::<_, String>(1)?),
                answer: answer(&word),
                detail_text: whole(&q.get::<_, String>(4)?),
                entries: entries
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|e| v1::DeclaredRelease {
                        version_text: e["version"].as_str().map(whole),
                        at_text: e["at"].as_str().map(|a| whole(&at_shown(a))),
                        from: e["from"].as_str().unwrap_or_default().to_string(),
                        affected: e["affected"] == true,
                    })
                    .collect(),
                fixed_text: serde_json::from_str::<Vec<String>>(&fixed)
                    .unwrap_or_default()
                    .iter()
                    .map(|f| whole(f))
                    .collect(),
                data_read_at: q.get(7)?,
                since_at: q.get(8)?,
                record_modified_text: whole(&q.get::<_, String>(9)?),
                ..Default::default()
            };
            match word.as_str() {
                "unknown" => p.reason = Some(reason.clone()),
                "not_affected" => {
                    p.certainty = Some("known".to_string());
                    p.openvex = Some(
                        if reason == "fixed" {
                            "fixed"
                        } else {
                            "vulnerable_code_not_present"
                        }
                        .to_string(),
                    );
                }
                _ => {}
            }
            Ok((q.get::<_, String>(0)?, word, p))
        })?;
        for row in rows {
            let (checkout, word, mut p) = row?;
            // "Not affected" stands only while its data is current now.
            if let (Some(why), "not_affected") = (stale.get(r.source.as_str()), word.as_str()) {
                p.answer = answer("unknown");
                p.reason = Some(FEED_NOT_READ.to_string());
                p.detail_text = whole(why);
                p.certainty = None;
                p.openvex = None;
            }
            stored.entry(checkout).or_default().push(p);
        }
        for p in mine {
            let mut a = match stored.remove(&p.0) {
                Some(packages) => v1::PlaceAnswer {
                    project_text: place_of(&p.0),
                    ecosystem: p.1.clone(),
                    packages,
                    ..Default::default()
                },
                // The project holds no package the record names.
                None => {
                    let mut a = derived(p, "known");
                    if a.answer == Some(answer("not_affected")) {
                        a.openvex = Some("component_not_present".to_string());
                    }
                    a
                }
            };
            untell(&p.0, &mut a);
            v.answers.push(a);
        }
        // A project with no place of this ecosystem, whose lockfiles are of a kind with no reader
        // or were not found, cannot be told for this record either: once, in the order of the rest.
        let mut seen: BTreeSet<String> = BTreeSet::new();
        more.retain(|a| seen.insert(a.project_text.clone()));
        v.answers.extend(more);
        v.answers
            .sort_by(|a, b| a.project_text.cmp(&b.project_text));
        out.records.push(v);
    }
    Ok(out)
}

/// What an id on the catalogue that no record names means for the projects, from `answers`, one
/// per project and ecosystem. The projects for which it cannot be told come first, each counted
/// once with its reasons, so that the sentence is never calmer than any answer under it; with no
/// answer at all, nothing was compared, and that cannot be told either.
fn no_record_said(answers: &[v1::PlaceAnswer], found: crate::covered::Found) -> String {
    // A record of any feed downloaded may name the id, matched or not.
    let feeds: Vec<&str> = FEEDS.iter().map(|f| f.ecosystem).collect();
    let held = format!(
        "The catalogue of exploited vulnerabilities holds this id, and no record of the {} data names it",
        crate::covered::listed(&feeds)
    );
    const NOT_EVERY: &str =
        "The data does not claim to name every vulnerability a package may hold.";
    if answers.is_empty() {
        return format!(
            "{held}. The store knows no project whose lockfiles it compared, so whether it affects one cannot be told. {NOT_EVERY}"
        );
    }
    let not_affected = crate::contract::value_of::<v1::PackageAnswer>("not_affected");
    let projects: BTreeSet<&str> = answers.iter().map(|a| a.project_text.as_str()).collect();
    // Each project for which it cannot be told, with every reason of its answers.
    let mut unknown: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for a in answers.iter().filter(|a| a.answer != Some(not_affected)) {
        unknown
            .entry(a.project_text.as_str())
            .or_default()
            .insert(a.reason.as_deref().unwrap_or_default());
    }
    if unknown.is_empty() {
        let of = match found {
            crate::covered::Found::All => "any project's lockfiles".to_string(),
            f => format!("the lockfiles of any of {}", f.projects()),
        };
        return format!("{held}: it does not affect {of}, with no signs. {NOT_EVERY}");
    }
    let projects_said = |n: usize| crate::things(n as i64, "project", "projects");
    // A place's answer is derived from its lockfiles and its data: these are its only reasons.
    // A project is counted once, under one of them or under both.
    const LOCKFILES: &str = "whose lockfiles were not all read";
    const DATA: &str = "whose vulnerability data was never read or is not current";
    let both = format!("{LOCKFILES} and {DATA}");
    let mut why: Vec<String> = Vec::new();
    for (reasons, said) in [
        (&[PLACE_NOT_READ][..], LOCKFILES),
        (&[FEED_NOT_READ][..], DATA),
        (&[PLACE_NOT_READ, FEED_NOT_READ][..], both.as_str()),
    ] {
        let n = unknown
            .values()
            .filter(|r| r.len() == reasons.len() && reasons.iter().all(|x| r.contains(x)))
            .count();
        if n > 0 {
            why.push(format!("{} {said}", projects_said(n)));
        }
    }
    let rest = projects.len() - unknown.len();
    let mut said = format!(
        "{held}. For {} of {} it cannot be told whether it affects their lockfiles: {}.",
        unknown.len(),
        projects_said(projects.len()),
        why.join(", ")
    );
    if rest > 0 {
        said.push_str(&format!(
            " It does not affect the lockfiles of the other {}, with no signs.",
            projects_said(rest)
        ));
    }
    format!("{said} {NOT_EVERY}")
}

// ---- Findings: what they say of the thing they are about. ----

/// Where a finding about a component is and what it rests on, as a person reads them: the
/// lockfile lines of the releases, and the package, its releases and the records with their
/// sources and summaries, from `list`, what `affecting` gives. `None` when no answer affects it
/// now.
pub fn finding_detail(list: &[Affecting], about: &str) -> Option<(String, String)> {
    let mine: Vec<&Affecting> = list.iter().filter(|a| a.is_about(about)).collect();
    let first = mine.first()?;
    let mut at: Vec<String> = Vec::new();
    let mut releases: BTreeSet<String> = BTreeSet::new();
    for a in &mine {
        for (v, line) in a.affected_of(about) {
            releases.insert(v);
            let shown = at_shown(&line);
            if !at.contains(&shown) {
                at.push(shown);
            }
        }
    }
    let records: Vec<String> = mine
        .iter()
        .map(|a| {
            let mut s = format!("{} from {}", a.advisory, source_name(&a.advisory));
            if let Some(summary) = &a.summary {
                s.push_str(&format!(": {summary}"));
            }
            if !a.fixed.is_empty() {
                s.push_str(&format!(" (fixed in {})", a.fixed.join(", ")));
            }
            s
        })
        .collect();
    let value = format!(
        "{} {}; {}",
        first.package,
        releases.into_iter().collect::<Vec<_>>().join(", "),
        records.join("; ")
    );
    Some((at.join(", "), value))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_places_not_all_read_are_listed_up_to_a_limit_and_always_counted_whole() {
        // More places than the message lists: the first `SHOWN` are listed, the total is all.
        let places: Vec<super::UnreadPlace> = (0..super::SHOWN + 1)
            .map(|i| {
                (
                    format!("checkout:machine:mac/dev/p{i:03}"),
                    "npm".to_string(),
                    "partial".to_string(),
                    None,
                )
            })
            .collect();
        let m = super::unread_of(&places, None);
        assert_eq!(m.items.len(), super::SHOWN);
        assert_eq!(m.total, super::SHOWN as u64 + 1);
    }

    use super::*;

    #[test]
    fn a_lockfile_in_a_folder_whose_name_holds_a_semicolon_leaves_only_its_own_ecosystem_unknown() {
        // An entry of a PyPI lockfile whose package cannot be told leaves PyPI in part unknown
        // and crates.io, read in full beside it, known, whatever its folder is named.
        use crate::baseline::Unit;
        use crate::look::{Look, Said};
        let mut look = Look::default();
        look.present = 1;
        look.read(Unit::whole("dev/shop/Cargo.lock"));
        let at = "dev/shop/web; old, new/requirements.txt";
        look.unread_as(Unit::part(at, "line 1"), Said::Untold, None, String::new());
        look.read(Unit::whole(at));
        let (completeness, reason) = look.completeness_noted(None);
        let gap = look.gap();
        let rows: Vec<crate::store::Unread> =
            gap.not_read.iter().map(crate::store::Unread::of).collect();
        let lacks = [Some("requirements.txt".to_string())];
        let of = |eco| {
            lockfiles_for(
                completeness,
                reason.as_deref(),
                &rows,
                &lacks,
                "r",
                "r",
                eco,
            )
            .0
        };
        assert_eq!((of("PyPI"), of("crates.io")), ("partial", "full"));
    }

    #[test]
    fn a_feed_is_matched_only_when_some_kind_of_lockfile_of_its_ecosystem_is_read() {
        // A feed of an ecosystem no lockfile is read for gives no place, answer or word of
        // comparison. Every feed of this build has a reader, so the rule is held on a predicate
        // that refuses one ecosystem.
        let matched =
            |read| -> Vec<&str> { matched_of(&FEEDS, read).map(|f| f.ecosystem).collect() };
        assert_eq!(matched(|e| e != "PyPI"), ["crates.io", "npm"]);
        assert_eq!(matched(|e| e == "npm"), ["npm"]);
        let all: Vec<&str> = matched_feeds().map(|f| f.ecosystem).collect();
        assert_eq!(all, ["crates.io", "npm", "PyPI"]);
    }

    #[test]
    fn a_thing_the_store_holds_no_fact_of_is_never_known_so_its_finding_is_never_cleared() {
        let dir = crate::common::Scratch::new("known-nothing");
        let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let checkout = "checkout:machine:mac/dev/shop";
        let matched = Matched {
            affected: BTreeMap::new(),
            read: HashSet::from([(checkout.to_string(), "npm")]),
            untold: HashSet::new(),
        };
        let about = format!("component:{checkout}/npm/left-pad");
        assert!(!matched.known(&conn, &about).unwrap());
    }

    #[test]
    fn a_component_id_two_checkouts_share_is_known_only_when_it_is_known_in_each() {
        // `nested/crates.io/widget` in `app` and `widget` in `app/crates.io/nested` have one id.
        // The outer checkout is gone; the inner one's package cannot be told, so the finding
        // about that id stands. Once the inner one is told too, it is known.
        let dir = crate::common::Scratch::new("known-shared-id");
        let mut conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let (outer, inner) = (
            "checkout:machine:mac/app",
            "checkout:machine:mac/app/crates.io/nested",
        );
        let about = format!("component:{inner}/crates.io/widget");
        let tx = conn.transaction().unwrap();
        let fact = |layer: &str,
                    subject: &str,
                    predicate: &str,
                    object: &str,
                    reader: &str,
                    scope: &str| {
            for id in [subject, scope] {
                crate::store::put_entity(&tx, id).unwrap();
            }
            tx.execute(
                "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                        source_ref, basis, observed_at, run_id, retracted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', ?8, 1, 'r1',
                         CASE WHEN ?1 = 'retracted' THEN 2 END)",
                params![
                    layer,
                    subject,
                    predicate,
                    object,
                    reader,
                    scope,
                    crate::lockfiles::KIND,
                    crate::lockfiles::BASIS
                ],
            )
            .unwrap();
        };
        fact(
            "retracted",
            outer,
            "located_on",
            "machine:mac",
            "checkouts",
            outer,
        );
        fact(
            "retracted",
            &about,
            "part_of",
            outer,
            crate::lockfiles::READER,
            outer,
        );
        fact(
            "live",
            &about,
            "part_of",
            inner,
            crate::lockfiles::READER,
            inner,
        );
        let mut matched = Matched {
            affected: BTreeMap::new(),
            read: HashSet::from([(inner.to_string(), "crates.io")]),
            untold: HashSet::from([about.clone()]),
        };
        assert!(!matched.known(&tx, &about).unwrap());
        matched.untold.clear();
        assert!(matched.known(&tx, &about).unwrap());
    }

    /// A record of npm's data that affects left-pad from 1.0.0 to before 1.3.0.
    const LEFT_PAD: &str = "GHSA-0000-0000-0001";
    const LEFT_PAD_RANGES: &str =
        r#"[{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.3.0"}]}]"#;

    #[test]
    fn an_entry_whose_index_is_not_recorded_is_affected_as_the_registrys_and_never_not_affected() {
        let n = Named {
            source: "osv-npm",
            advisory: LEFT_PAD.to_string(),
            modified: String::new(),
            kind: "vulnerability".to_string(),
            affects: vec![(serde_json::from_str(LEFT_PAD_RANGES).unwrap(), json!([]))],
        };
        let entry = |source, release: &str| Entry {
            component: String::new(),
            source,
            version: Some(release.to_string()),
            at: "dev/shop/package-lock.json#node_modules/left-pad".to_string(),
        };
        let answer = |entries: &[Entry], place: &'static str| {
            let place = (place, None);
            let c = answer_one("shop", "npm", "left-pad", entries, &n, Some(&place), None);
            format!("{} {}", c.answer, c.reason)
        };
        // The registry's entry, and the same entry with its index not recorded.
        for (release, registry, unrecorded) in [
            ("1.2.0", "affected affected", "affected affected"),
            ("1.3.0", "not_affected fixed", "unknown index_not_recorded"),
            (
                "0.9.0",
                "not_affected not_in_range",
                "unknown index_not_recorded",
            ),
            (
                "1.2",
                "unknown version_cannot_be_compared",
                "unknown version_cannot_be_compared",
            ),
        ] {
            let of = |source| answer(&[entry(source, release)], "full");
            assert_eq!(of(Source::Registry), registry, "{release}");
            assert_eq!(of(Source::UnrecordedIndex), unrecorded, "{release}");
        }
        // Beside other reasons: "affects me" wins over every one; a reason that left a release
        // not compared comes before it, and what is wrong with the place after it.
        for (entries, place, said) in [
            (
                vec![entry(Source::UnrecordedIndex, "1.2.0")],
                "partial",
                "affected affected",
            ),
            (
                vec![
                    entry(Source::UnrecordedIndex, "1.3.0"),
                    entry(Source::Registry, "1.2"),
                ],
                "full",
                "unknown version_cannot_be_compared",
            ),
            (
                vec![entry(Source::UnrecordedIndex, "1.3.0")],
                "partial",
                "unknown index_not_recorded",
            ),
        ] {
            assert_eq!(answer(&entries, place), said);
        }
    }

    const NOW: i64 = 1_800_000_000;

    fn checkout(project: &str) -> String {
        format!("checkout:machine:mac/dev/{project}")
    }

    fn component(project: &str, package: &str, source: Source) -> String {
        let name = crate::lockfiles::component_name(package, source);
        format!("component:{}/npm/{name}", checkout(project))
    }

    /// A reading of the projects' lockfiles in full in run `r1`, built by hand, and npm's data
    /// read then: each entry of `package` as its project, source, releases and where it is, and
    /// each record of it as its id and ranges.
    fn by_hand(
        tx: &Transaction,
        package: &str,
        entries: &[(&str, Source, &[&str], &str)],
        records: &[(&str, &str)],
    ) {
        for (project, source, releases, at) in entries {
            let (scope, subject) = (checkout(project), component(project, package, *source));
            for id in [&scope, &subject] {
                crate::store::put_entity(tx, id).unwrap();
            }
            tx.execute(
                "INSERT INTO coverage (reader, run_id, observed_at, scope, kind, completeness)
                 VALUES (?1, 'r1', ?2, ?3, ?4, 'full')",
                params![crate::lockfiles::READER, NOW, scope, crate::lockfiles::KIND],
            )
            .unwrap();
            // The lockfile the reader found, which gives the checkout its place for npm.
            let found = (&scope, crate::lockfiles::HAS_LOCKFILE, "package-lock.json");
            let facts = [found, (&subject, "part_of", scope.as_str())]
                .into_iter()
                .chain(releases.iter().map(|r| (&subject, "has_version", *r)));
            for (subject, predicate, object) in facts {
                tx.execute(
                    "INSERT INTO assertion (layer, subject, predicate, object, reader, scope,
                                            kind, source_ref, basis, observed_at, run_id)
                     VALUES ('live', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'r1')",
                    params![
                        subject,
                        predicate,
                        object,
                        crate::lockfiles::READER,
                        scope,
                        crate::lockfiles::KIND,
                        format!("dev/{project}/{at}"),
                        crate::lockfiles::BASIS,
                        NOW
                    ],
                )
                .unwrap();
            }
        }
        tx.execute(
            "INSERT INTO feed_reading (source, run_id, at, outcome)
             VALUES ('osv-npm', 'r1', ?1, 'read')",
            [NOW],
        )
        .unwrap();
        for (id, ranges) in records {
            tx.execute(
                "INSERT INTO advisory (source, id, modified, kind, cvss, aliases, cwe_ids,
                                       first_run, first_seen_at, written_run, written_at)
                 VALUES ('osv-npm', ?1, ?2, 'vulnerability', '[]', '[]', '[]', 'r1', ?3, 'r1', ?3)",
                params![id, crate::view::iso(NOW - 3600), NOW],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO advisory_affects (source, advisory, ecosystem, name, normalized,
                                               ranges, versions)
                 VALUES ('osv-npm', ?1, 'npm', ?2, ?2, ?3, '[]')",
                params![id, package, ranges],
            )
            .unwrap();
        }
    }

    #[test]
    fn a_package_whose_index_is_not_recorded_is_matched_by_name_found_about_its_component_and_never_compared_in_full()
     {
        let dir = crate::common::Scratch::new("index-not-recorded");
        let mut conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let now = NOW;
        let tx = conn.transaction().unwrap();
        let component = |project: &str, source| component(project, "left-pad", source);
        // left-pad at one release, or at two.
        let at = "package-lock.json#node_modules/left-pad";
        by_hand(
            &tx,
            "left-pad",
            &[
                ("shop", Source::Registry, &["1.3.0"], at),
                ("blog", Source::UnrecordedIndex, &["1.3.0"], at),
                ("site", Source::UnrecordedIndex, &["1.2.0", "1.3.0"], at),
            ],
            &[(LEFT_PAD, LEFT_PAD_RANGES)],
        );

        let matched = match_all(&tx, "r1", now).unwrap();

        let answers: Vec<String> = tx
            .prepare(
                "SELECT checkout, package, answer, reason FROM vulnerability_answer
                 ORDER BY checkout",
            )
            .unwrap()
            .query_map([], |r| {
                Ok([r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?].join("|"))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            answers,
            [
                "checkout:machine:mac/dev/blog|left-pad|unknown|index_not_recorded",
                "checkout:machine:mac/dev/shop|left-pad|not_affected|fixed",
                "checkout:machine:mac/dev/site|left-pad|affected|affected",
            ]
        );
        // A finding is about the component the store holds, and one whose answer cannot be told
        // is not known, so its finding stands.
        let about = component("site", Source::UnrecordedIndex);
        let held: Vec<_> = matched.affected.iter().collect();
        assert_eq!(
            held,
            [(
                &about,
                &vec![(
                    LEFT_PAD.to_string(),
                    "vulnerability".to_string(),
                    vec!["1.2.0".to_string()]
                )]
            )]
        );
        // What it says of the package is found from the answer, kept under the plain name.
        let (place, _) = finding_detail(&affecting(&tx).unwrap(), &about).unwrap();
        assert_eq!(place, "~/dev/site/package-lock.json#node_modules/left-pad");
        let packages = crate::finding_answer::packages(&tx).unwrap();
        assert_eq!(
            packages.of(&about).unwrap().1,
            BTreeSet::from(["1.2.0".to_string()])
        );
        let untold = component("blog", Source::UnrecordedIndex);
        assert!(!matched.known(&tx, &untold).unwrap());
        // `site`'s 1.3.0 cannot be told beside its affected 1.2.0; `shop`'s answer is certain.
        assert!(!matched.known(&tx, &about).unwrap());
        assert!(
            matched
                .known(&tx, &component("shop", Source::Registry))
                .unwrap()
        );

        // Only the project whose answers are all certain, and the one affected, are compared in
        // full; the package that cannot be told is counted under the new reason.
        let t = totals(&tx, now).unwrap();
        assert_eq!(t.projects_compared, 2);
        assert_eq!(
            t.unknown_packages,
            [(
                checkout("blog"),
                "npm".to_string(),
                "left-pad".to_string(),
                INDEX_NOT_RECORDED
            )]
        );
        assert_eq!(
            reason_said(t.packages_by_reason[0].0, t.packages_by_reason[0].1),
            "1 comes from an index its lockfile does not record"
        );

        // The answer for the record, as JSON and as a person reads it.
        let m = one(Some(&tx), LEFT_PAD, now).unwrap();
        let json = serde_json::to_value(&m).unwrap();
        let blog = json["records"][0]["answers"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|a| a["packages"].as_array().unwrap())
            .find(|p| p["reason"] == INDEX_NOT_RECORDED)
            .unwrap_or_else(|| panic!("{json:#}"));
        assert_eq!(
            blog["detail_text"],
            "the lockfile does not record which index left-pad 1.3.0 comes from, at \
             dev/blog/package-lock.json#node_modules/left-pad"
        );
        assert_eq!(blog["entries"][0]["from"], "an unrecorded index");
        let text = crate::answers_text::vulnerability(&m, &crate::screen::Screen::pipe());
        assert!(
            text.contains("its lockfile does not record which index it comes from"),
            "{text}"
        );
    }

    #[test]
    fn a_component_is_told_by_its_own_entries_and_its_finding_shows_only_them() {
        let dir = crate::common::Scratch::new("component-own-entries");
        let mut conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let tx = conn.transaction().unwrap();
        // In each project the registry's quill is affected by both records, so the package is
        // affected for each. Beside it, the quill whose index is not recorded is outside both
        // records in `shop`, and affected by the second in `site`.
        let (registry, unrecorded) = ("package-lock.json#node_modules/quill", "pdm.lock#quill");
        let (first, second) = (LEFT_PAD, "GHSA-0000-0000-0002");
        by_hand(
            &tx,
            "quill",
            &[
                ("shop", Source::Registry, &["1.2.0"], registry),
                ("shop", Source::UnrecordedIndex, &["2.0.0"], unrecorded),
                ("site", Source::Registry, &["1.2.0"], registry),
                ("site", Source::UnrecordedIndex, &["2.2.0"], unrecorded),
            ],
            &[
                (first, LEFT_PAD_RANGES),
                (
                    second,
                    r#"[{"type": "SEMVER", "events": [{"introduced": "1.1.0"}, {"fixed": "1.3.0"},
                                                      {"introduced": "2.1.0"}, {"fixed": "2.3.0"}]}]"#,
                ),
            ],
        );
        // A finding raised about the unrecorded quill of `shop` when it stood at an affected
        // release.
        let rule = crate::findings::MALICIOUS_PACKAGE;
        let shop = component("shop", "quill", Source::UnrecordedIndex);
        let never = |_: &str| Ok(false);
        crate::findings::hold(&tx, rule, &[(shop.clone(), vec![])], &never, "r0", NOW).unwrap();

        let matched = match_all(&tx, "r1", NOW).unwrap();
        let now: Vec<(String, Vec<i64>)> = (matched.affected.keys())
            .map(|c| (c.clone(), vec![]))
            .collect();
        let known = |about: &str| matched.known(&tx, about);
        crate::findings::hold(&tx, rule, &now, &known, "r1", NOW).unwrap();

        // The package is affected, but its unrecorded component cannot be told: its finding
        // stands.
        let state: String = tx
            .query_row("SELECT state FROM finding WHERE about = ?1", [&shop], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(state, "open");
        // Each finding of `site` shows its own component's release, line and records.
        let list = affecting(&tx).unwrap();
        let packages = crate::finding_answer::packages(&tx).unwrap();
        for (source, at, release, records) in [
            (Source::Registry, registry, "1.2.0", &[first, second][..]),
            (Source::UnrecordedIndex, unrecorded, "2.2.0", &[second]),
        ] {
            let about = component("site", "quill", source);
            let at = format!("~/dev/site/{at}");
            let (place, value) = finding_detail(&list, &about).unwrap();
            assert_eq!(place, at);
            let named: Vec<&str> = (value.split("; ").skip(1))
                .map(|r| r.split(' ').next().unwrap())
                .collect();
            assert_eq!(
                (value.split(';').next().unwrap(), &named[..]),
                (&*format!("quill {release}"), records)
            );
            let releases = BTreeSet::from([release.to_string()]);
            assert_eq!(packages.of(&about).unwrap().1, releases);
            let whole = crate::finding_answer::package(&tx, &about, crate::now_secs()).unwrap();
            let shown: Vec<(&str, &str)> = (whole.releases.iter())
                .map(|r| (r.version_text.as_str(), r.at_text.as_str()))
                .collect();
            let ids: Vec<&str> = whole.records.iter().map(|r| r.id_text.as_str()).collect();
            assert_eq!(
                (shown, ids),
                (vec![(release, at.as_str())], records.to_vec())
            );
        }
    }

    #[test]
    fn a_standing_finding_about_a_component_is_held_while_a_release_of_it_cannot_be_told_though_another_is_affected()
     {
        let dir = crate::common::Scratch::new("component-one-untold");
        let mut conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let tx = conn.transaction().unwrap();
        // A record that ends at npm's placeholder with no fix: the placeholder is affected, and
        // 1.0.0 above it is not covered by the data.
        let at = "package-lock.json#node_modules/quill";
        by_hand(
            &tx,
            "quill",
            &[("shop", Source::Registry, &["0.0.1-security", "1.0.0"], at)],
            &[(
                LEFT_PAD,
                r#"[{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "0.0.1-security"}]}]"#,
            )],
        );
        // A finding of another rule about it, from an earlier check.
        let rule = crate::findings::MALICIOUS_PACKAGE;
        let about = component("shop", "quill", Source::Registry);
        let never = |_: &str| Ok(false);
        crate::findings::hold(&tx, rule, &[(about.clone(), vec![])], &never, "r0", NOW).unwrap();

        let matched = match_all(&tx, "r1", NOW).unwrap();
        assert!(matched.affected.contains_key(&about));
        // This check holds it under another rule, so this one is cleared only if it is known.
        let known = |about: &str| matched.known(&tx, about);
        crate::findings::hold(&tx, rule, &[], &known, "r1", NOW).unwrap();

        let state: String = tx
            .query_row(
                "SELECT state FROM finding WHERE about = ?1",
                [&about],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "open");
    }

    #[test]
    fn what_a_finding_keeps_is_only_what_its_rule_found_when_it_was_last_found() {
        // Last found by run r1, about quill 1.0.0 and a malicious record. Kept: that record and
        // that release. Not kept: a malicious record of 2.0.0 that began in r2, after it, nor an
        // ordinary advisory of 1.0.0 that stood at r1, which its rule does not fire on.
        let dir = crate::common::Scratch::new("ended-what-stood");
        let mut conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let tx = conn.transaction().unwrap();
        let at = "package-lock.json#node_modules/quill";
        let (first, later, ordinary) = ("MAL-2099-0001", "MAL-2099-0002", "GHSA-0000-0000-0003");
        let records = [first, later, ordinary].map(|id| (id, LEFT_PAD_RANGES));
        let releases: &[&str] = &["1.0.0", "2.0.0"];
        by_hand(
            &tx,
            "quill",
            &[("shop", Source::Registry, releases, at)],
            &records,
        );
        tx.execute(
            "UPDATE advisory SET kind = 'malicious' WHERE id GLOB 'MAL-*'",
            [],
        )
        .unwrap();
        for run in ["r1", "r2", "r3"] {
            let journal = "INSERT INTO journal (at, run_id, entry) VALUES (?1, ?2, 'run_started')";
            tx.execute(journal, params![NOW, run]).unwrap();
        }
        let answer = |table: &str, advisory: &str, release: &str, since: &str, until: &str| {
            let entries = json!([{"version": release, "at": format!("dev/shop/{at}"),
                                  "from": Source::Registry.said(), "affected": true}]);
            let (columns, ends) = match table {
                "vulnerability_answer" => ("", String::new()),
                _ => (", until_run, until_at", format!(", '{until}', {NOW}")),
            };
            tx.execute(
                &format!(
                    "INSERT INTO {table} (checkout, ecosystem, package, source, advisory,
                         modified, answer, reason, detail, entries, fixed, since_run, since_at,
                         run_id, at{columns})
                     VALUES (?1, 'npm', 'quill', 'osv-npm', ?2, '', 'affected', 'affected', '',
                             ?3, '[]', ?4, ?5, ?4, ?5{ends})"
                ),
                params![checkout("shop"), advisory, entries.to_string(), since, NOW],
            )
            .unwrap();
        };
        answer("vulnerability_answer_past", first, "1.0.0", "r1", "r2");
        answer("vulnerability_answer_past", later, "2.0.0", "r2", "r3");
        answer("vulnerability_answer", ordinary, "1.0.0", "r1", "");
        let about = component("shop", "quill", Source::Registry);
        let rule = crate::findings::MALICIOUS_PACKAGE;
        let (why, was) = ended(&tx, rule, &about, "r1").unwrap();
        let kept: Vec<(&str, &str)> = (was.as_array().unwrap().iter())
            .map(|a| {
                let release = a["entries"][0]["version"].as_str().unwrap();
                (a["advisory"].as_str().unwrap(), release)
            })
            .collect();
        assert_eq!((why, kept), (NOT_NAMED, vec![(first, "1.0.0")]));
    }

    #[test]
    fn a_record_the_catalogue_links_through_two_cves_is_one_answer_used_in_attacks() {
        let dir = crate::common::Scratch::new("linked-twice");
        let mut conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let tx = conn.transaction().unwrap();
        let at = "package-lock.json#node_modules/left-pad";
        let entries = [("shop", Source::Registry, &["1.2.0"][..], at)];
        by_hand(&tx, "left-pad", &entries, &[(LEFT_PAD, LEFT_PAD_RANGES)]);
        match_all(&tx, "r1", NOW).unwrap();
        for cve in ["CVE-2099-0001", "CVE-2099-0002"] {
            tx.execute(
                "INSERT INTO vulnerability_linked (cve, source, advisory) VALUES (?1, 'osv-npm', ?2)",
                params![cve, LEFT_PAD],
            )
            .unwrap();
        }
        let shown: Vec<(String, bool)> = (affecting(&tx).unwrap().into_iter())
            .map(|a| (a.advisory, a.exploited))
            .collect();
        assert_eq!(shown, [(LEFT_PAD.to_string(), true)]);
    }

    fn v(s: &str) -> semver::Version {
        match version("npm", s) {
            Ok(Release::SemVer(x)) => x,
            _ => panic!("{s}"),
        }
    }

    fn p(s: &str) -> pep440_rs::Version {
        match version("PyPI", s) {
            Ok(Release::Pep440(x)) => x,
            _ => panic!("{s}"),
        }
    }

    /// The Python string literals of one line of pypa/packaging's tests, read as data: only the
    /// escapes that file uses are decoded.
    fn literals(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut chars = line.chars();
        while chars.by_ref().any(|c| c == '"') {
            let mut s = String::new();
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => match chars.next() {
                        Some('t') => s.push('\t'),
                        Some('n') => s.push('\n'),
                        Some('u') => {
                            let hex: String = chars.by_ref().take(4).collect();
                            s.push(char::from_u32(u32::from_str_radix(&hex, 16).unwrap()).unwrap());
                        }
                        Some('N') => {
                            let name: String = chars.by_ref().take_while(|c| *c != '}').collect();
                            s.push(match name.as_str() {
                                "{NARROW NO-BREAK SPACE" => '\u{202f}',
                                "{PARAGRAPH SEPARATOR" => '\u{2029}',
                                other => panic!("{other}"),
                            });
                        }
                        other => panic!("{other:?}"),
                    },
                    c => s.push(c),
                }
            }
            out.push(s);
        }
        out
    }

    /// The rows of the list that begins on the first line after `after` that is `[`, in
    /// pypa/packaging's tests, each as its literals.
    fn packaging_list(after: &str) -> Vec<Vec<String>> {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pep440/test_version.py");
        let text = std::fs::read_to_string(path).unwrap();
        text.lines()
            .skip_while(|l| !l.contains(after))
            .skip_while(|l| !l.trim_end().ends_with('['))
            .skip(1)
            .take_while(|l| !l.trim_start().starts_with(']'))
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(literals)
            .filter(|row| !row.is_empty())
            .collect()
    }

    #[test]
    fn python_versions_are_ordered_as_pypa_packaging_orders_its_own_list() {
        // packaging's VERSIONS is in ascending order: every pair of its 92 versions, 4,186
        // pairs, compares as it does, both ways, through the order the matcher uses.
        let versions: Vec<pep440_rs::Version> = packaging_list("VERSIONS = [")
            .iter()
            .map(|row| p(&row[0]))
            .collect();
        assert_eq!(versions.len(), 92);
        for (i, a) in versions.iter().enumerate() {
            for b in &versions[i + 1..] {
                assert_eq!(compare(a, b), Ordering::Less, "{a} < {b}");
                assert_eq!(compare(b, a), Ordering::Greater, "{b} > {a}");
            }
        }
        // Strings packaging refuses are not versions here either.
        let invalid = packaging_list("def test_match_args");
        assert_eq!(invalid.len(), 20);
        for row in &invalid {
            assert!(version("PyPI", &row[0]).is_err(), "{:?}", row[0]);
        }
        // Spellings packaging normalises are the same version. Only whitespace outside ASCII,
        // which packaging trims, is refused by pep440_rs: the safe side, "don't know".
        let normalized = packaging_list("def test_oversized_version_raises_valueerror");
        assert_eq!(normalized.len(), 102);
        for row in &normalized {
            let (a, b) = (&row[0], &row[1]);
            if a.trim() != a.trim_ascii() {
                assert!(version("PyPI", a).is_err(), "{a:?}");
                continue;
            }
            assert_eq!(compare(&p(a), &p(b)), Ordering::Equal, "{a:?} = {b}");
        }
        assert_eq!(compare(&p("1.0rc1"), &p("1.0c1")), Ordering::Equal);
    }

    #[test]
    fn a_python_release_is_judged_in_pep_440_order_and_what_it_cannot_say_is_never_not_affected() {
        let eco = |events: Value| json!([{ "type": "ECOSYSTEM", "events": events }]);
        let edges = eco(json!([{"introduced": "1.0"}, {"fixed": "2.0"}]));
        let zero = eco(json!([{"introduced": "0"}, {"fixed": "1.0"}]));
        let local_event = eco(json!([{"introduced": "1.0+x"}]));
        let semver = json!([{ "type": "SEMVER", "events": [{"introduced": "0"}] }]);
        let none = json!([]);
        let not_comparable = || Verdict::Unknown(NOT_COMPARABLE, String::new());
        for (release, ranges, listed, verdict) in [
            // An epoch sits above every release without one.
            (
                "1!0.5",
                &edges,
                json!([]),
                Verdict::NotAffected { fixed: true },
            ),
            ("1.5", &edges, json!([]), Verdict::Affected),
            // A pre-release and a dev release below `introduced` are outside the range; below
            // `fixed` they are inside it.
            (
                "1.0a1",
                &edges,
                json!([]),
                Verdict::NotAffected { fixed: false },
            ),
            (
                "1.0.dev0",
                &edges,
                json!([]),
                Verdict::NotAffected { fixed: false },
            ),
            ("2.0rc1", &edges, json!([]), Verdict::Affected),
            ("2.0.dev0", &edges, json!([]), Verdict::Affected),
            (
                "2.0.post1",
                &edges,
                json!([]),
                Verdict::NotAffected { fixed: true },
            ),
            // `introduced: "0"` is below every release, `0.dev0` too.
            ("0.dev0", &zero, json!([]), Verdict::Affected),
            // A listed version is equal by the order, padding and spelling aside.
            ("1.0.0", &none, json!(["1.0"]), Verdict::Affected),
            ("V1.0-RC1", &none, json!(["1.0rc1"]), Verdict::Affected),
            // What PEP 440 does not read, or a local label in the record, is not compared.
            ("2.0", &none, json!(["1.0", "lolwat"]), not_comparable()),
            ("1.0", &none, json!(["1.0+x"]), not_comparable()),
            ("1.5", &local_event, json!([]), not_comparable()),
            // A release with a local label was not served by PyPI.
            (
                "1.2+x",
                &edges,
                json!([]),
                Verdict::Unknown(NOT_FROM_REGISTRY, String::new()),
            ),
            // A SEMVER range is not in PEP 440 order.
            ("1.0", &semver, json!([]), not_comparable()),
        ] {
            let got = judge(&p(release), ranges, &listed);
            match (&got, &verdict) {
                (Verdict::Unknown(g, _), Verdict::Unknown(w, _)) => assert_eq!(g, w, "{release}"),
                _ => assert_eq!(got, verdict, "{release}"),
            }
        }
        // An ecosystem with no scheme here has no release, so it is never "not affected".
        assert!(version("Go", "1.0.0").is_err());
    }

    #[test]
    fn a_range_of_a_kind_not_ordered_is_passed_over_only_when_it_is_commits_and_releases_are_listed()
     {
        // OSV's `versions` enumerates what a range of commits covers, and nothing else: a range
        // of any other kind not ordered here, a SEMVER range in a PyPI record or a kind OSV adds
        // later, may hold the release, so it is never passed over for "not affected".
        let judged = |eco: &str, release: &str, other: &str, listed: Value| {
            let ranges = json!([
                { "type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.0"}] },
                { "type": other, "repo": "https://example.org/x",
                  "events": [{"introduced": "2.0.0"}, {"fixed": "3.0.0"}] },
            ]);
            version(eco, release).unwrap().judge(&ranges, &listed)
        };
        let reason = |v: Verdict| match v {
            Verdict::Unknown(r, _) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            reason(judged("PyPI", "2.5.0", "SEMVER", json!(["1.0.0"]))),
            NOT_COMPARABLE
        );
        for eco in ["npm", "crates.io"] {
            for listed in [json!(["1.0.0"]), json!([])] {
                assert_eq!(
                    reason(judged(eco, "2.5.0", "NEWKIND", listed)),
                    NOT_COMPARABLE
                );
            }
            // What is found affected is affected, whatever else cannot be compared.
            assert_eq!(
                judged(eco, "1.0.0", "NEWKIND", json!([])),
                Verdict::Affected
            );
            assert_eq!(
                judged(eco, "2.5.0", "GIT", json!(["1.0.0"])),
                Verdict::NotAffected { fixed: true }
            );
            assert_eq!(
                reason(judged(eco, "2.5.0", "GIT", json!([]))),
                NOT_COMPARABLE
            );
        }
    }

    #[test]
    fn at_one_version_an_event_that_ends_an_interval_comes_before_one_that_begins_the_next() {
        // Two adjacent intervals in either input order, in both schemes: a release at the
        // version where one ends and the next begins is in the next. A `last_affected` ends its
        // interval after its version, so it comes after an `introduced` there.
        let adjacent = |end: &str| {
            [
                json!([{"introduced": "1.0.0"}, {"fixed": "2.0.0"}, {"introduced": "0"}, {"fixed": end}]),
                json!([{"introduced": "0"}, {"fixed": end}, {"introduced": "1.0.0"}, {"fixed": "2.0.0"}]),
            ]
        };
        let one_release = [
            json!([{"last_affected": "1.0.0"}, {"introduced": "1.0.0"}, {"introduced": "2.0.0"}, {"fixed": "3.0.0"}]),
            json!([{"introduced": "1.0.0"}, {"last_affected": "1.0.0"}, {"introduced": "2.0.0"}, {"fixed": "3.0.0"}]),
        ];
        let range = |events: &Value| json!([{ "type": "ECOSYSTEM", "events": events }]);
        let none = json!([]);
        for events in adjacent("1.0") {
            assert_eq!(
                judge(&p("1.0.0"), &range(&events), &none),
                Verdict::Affected
            );
            assert_eq!(judge(&p("0.5"), &range(&events), &none), Verdict::Affected);
        }
        for events in adjacent("1.0.0") {
            assert_eq!(
                judge(&v("1.0.0"), &range(&events), &none),
                Verdict::Affected
            );
        }
        for events in &one_release {
            assert_eq!(judge(&v("1.0.0"), &range(events), &none), Verdict::Affected);
            assert_eq!(
                judge(&v("1.5.0"), &range(events), &none),
                Verdict::NotAffected { fixed: false }
            );
            assert_eq!(
                judge(&p("1.5"), &range(events), &none),
                Verdict::NotAffected { fixed: false }
            );
        }
    }

    /// node-semver's fixture rows, `[a, b, opt]`, as data. `opt` is loose when it is `true`
    /// or `{ loose: true }`.
    fn rows(file: &str) -> Vec<(String, String, bool)> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/semver")
            .join(file);
        let text = std::fs::read_to_string(path).unwrap();
        text.lines()
            .map(str::trim)
            .filter(|l| l.starts_with("['") || l.starts_with("[\""))
            .map(|l| {
                let quoted: Vec<&str> = l.split('\'').collect();
                let rest = quoted.get(4).copied().unwrap_or_default();
                let loose = rest.contains("true") && !rest.contains("loose: false");
                (quoted[1].to_string(), quoted[3].to_string(), loose)
            })
            .collect()
    }

    #[test]
    fn versions_are_ordered_as_node_semver_orders_strict_ones_and_a_loose_one_is_never_read() {
        // npm's reference is node-semver; its own fixtures are the samples. A strict row must
        // compare as node-semver does. A row node-semver reads only loosely must not parse:
        // coercing it would give an answer the data does not support.
        let comparisons = rows("comparisons.js");
        assert_eq!(comparisons.len(), 31);
        let mut strict = 0;
        for (a, b, loose) in &comparisons {
            if *loose {
                assert!(
                    version("npm", a).is_err() || version("npm", b).is_err(),
                    "{a} {b}"
                );
                continue;
            }
            strict += 1;
            assert_eq!(compare(&v(a), &v(b)), Ordering::Greater, "{a} > {b}");
            assert_eq!(compare(&v(b), &v(a)), Ordering::Less, "{b} < {a}");
        }
        assert_eq!(strict, 19);
        let equality = rows("equality.js");
        assert_eq!(equality.len(), 37);
        for (a, b, loose) in &equality {
            // node-semver trims and takes a leading `v` even when strict; this program does
            // neither, which is the safe side: such a version is "don't know".
            if *loose || a.trim() != a || a.starts_with('v') {
                assert!(
                    version("npm", a).is_err() || version("npm", b).is_err(),
                    "{a} {b}"
                );
                continue;
            }
            assert_eq!(compare(&v(a), &v(b)), Ordering::Equal, "{a} = {b}");
        }
        // invalid-versions.js: none is a version. Its numbers too big for JavaScript fit in
        // 64 bits here and are ordered as numbers; a registry never serves them.
        let max_length = 256;
        let too_long = format!("{}.0.0", "1".repeat(max_length - 1));
        for s in [too_long.as_str(), "hello, world", "xyz"] {
            assert!(version("npm", s).is_err(), "{s}");
        }
        assert_eq!(
            compare(&v("90071992547409910.0.0"), &v("9007199254740991.0.0")),
            Ordering::Greater
        );
    }

    #[test]
    fn a_pre_release_sits_where_semver_puts_it() {
        // semver.org, item 11: the chain, and build metadata ignored. RustSec writes
        // `0.0.0-0` and `x.y.z-0` so that every pre-release falls in a range.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "2.0.0",
            "2.1.0",
            "2.1.1",
        ];
        for w in chain.windows(2) {
            assert_eq!(
                compare(&v(w[0]), &v(w[1])),
                Ordering::Less,
                "{} < {}",
                w[0],
                w[1]
            );
        }
        assert_eq!(compare(&v("1.0.0+a"), &v("1.0.0+b")), Ordering::Equal);
        let ranges = json!([{ "type": "SEMVER", "events": [{"introduced": "0.0.0-0"}, {"fixed": "1.2.0-0"}] }]);
        assert_eq!(
            judge(&v("1.2.0-beta.1"), &ranges, &json!([])),
            Verdict::NotAffected { fixed: true }
        );
        assert_eq!(judge(&v("1.1.9"), &ranges, &json!([])), Verdict::Affected);
        assert_eq!(
            judge(&v("0.1.0-alpha"), &ranges, &json!([])),
            Verdict::Affected
        );
        let plain =
            json!([{ "type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}] }]);
        assert_eq!(
            judge(&v("2.0.0-rc.1"), &plain, &json!([])),
            Verdict::Affected
        );
    }

    #[test]
    fn a_range_is_walked_as_the_osv_schema_says_and_what_it_cannot_say_is_never_not_affected() {
        // IsVulnerable: events sorted, introduced on, fixed or past last_affected off, below a
        // limit. Unsorted events, as the schema allows, give the same answer.
        let r = |events: Value| json!([{ "type": "SEMVER", "events": events }]);
        let two = r(
            json!([{"fixed": "1.2.5"}, {"introduced": "1.2.0"}, {"introduced": "0"}, {"fixed": "1.0.0"}]),
        );
        for (release, verdict) in [
            ("0.9.0", Verdict::Affected),
            ("1.0.0", Verdict::NotAffected { fixed: true }),
            ("1.1.0", Verdict::NotAffected { fixed: true }),
            ("1.2.0", Verdict::Affected),
            ("1.2.5", Verdict::NotAffected { fixed: true }),
        ] {
            assert_eq!(judge(&v(release), &two, &json!([])), verdict, "{release}");
        }
        let last = r(json!([{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]));
        assert_eq!(judge(&v("1.4.0"), &last, &json!([])), Verdict::Affected);
        assert_eq!(
            judge(&v("0.9.0"), &last, &json!([])),
            Verdict::NotAffected { fixed: false }
        );
        assert!(matches!(
            judge(&v("1.5.0"), &last, &json!([])),
            Verdict::Unknown(NOT_COVERED, _)
        ));
        let limited = r(json!([{"introduced": "0"}, {"limit": "2.0.0"}]));
        assert_eq!(judge(&v("1.9.9"), &limited, &json!([])), Verdict::Affected);
        assert_eq!(
            judge(&v("2.0.0"), &limited, &json!([])),
            Verdict::NotAffected { fixed: false }
        );
        // A listed release is affected by equality; a value that is not SemVer is never
        // taken for "not affected".
        assert_eq!(
            judge(&v("3.1.4"), &json!([]), &json!(["3.1.4"])),
            Verdict::Affected
        );
        let loose = r(json!([{"introduced": "13.0"}, {"fixed": "14.2.10"}]));
        assert!(matches!(
            judge(&v("15.0.0"), &loose, &json!([])),
            Verdict::Unknown(NOT_COMPARABLE, _)
        ));
        let commits = json!([{ "type": "GIT", "repo": "https://example.org/x", "events": [{"introduced": "0"}] }]);
        assert!(matches!(
            judge(&v("1.0.0"), &commits, &json!([])),
            Verdict::Unknown(NOT_COMPARABLE, _)
        ));
        assert!(matches!(
            judge(&v("1.0.0"), &json!([]), &json!([])),
            Verdict::Unknown(NOT_COMPARABLE, _)
        ));
        assert!(matches!(
            judge(&v("1.0.0"), &json!([]), &json!(["v1.0.0"])),
            Verdict::Unknown(NOT_COMPARABLE, _)
        ));
    }
}
