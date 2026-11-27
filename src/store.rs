//! The store: vocabulary, entities, the three assertion layers, coverage and the journal.
//! The shape is described in docs/how-it-works.md.

use crate::outcome::{Code, Outcome};
use crate::resolver;
use rusqlite::config::DbConfig;
use rusqlite::{
    Connection, FileControl, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use std::collections::BTreeSet;
use std::fs::{File, TryLockError};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The store's format. A store of any other format is refused and left as it is: this build
/// reads only what a build of format 10 wrote, with every table and column this build reads and
/// text from a source kept cut, in the store's form (see `secrets`).
pub const FORMAT_VERSION: &str = "10";

const SCHEMA: &str = "
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Vocabulary is data: a new type or predicate is a new row, not a new table.
CREATE TABLE entity_type (
    name   TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('used', 'reserved'))
);
CREATE TABLE predicate (
    name        TEXT PRIMARY KEY,
    object_kind TEXT CHECK (object_kind IN ('entity', 'literal')),
    status      TEXT NOT NULL CHECK (status IN ('used', 'reserved'))
);
CREATE TABLE basis_kind (
    name     TEXT PRIMARY KEY,
    strength INTEGER NOT NULL UNIQUE  -- 1 is strongest
);
-- What a reading looks for in its scope. A reading of an unknown kind cannot be written.
CREATE TABLE coverage_kind (
    name TEXT PRIMARY KEY
);

CREATE TABLE entity (
    id   TEXT PRIMARY KEY,
    type TEXT NOT NULL REFERENCES entity_type (name)
);

-- One row is one assertion in one layer. scope and kind tie it to the coverage
-- record of the reading that made it; the lifecycle compares within them.
CREATE TABLE assertion (
    id           INTEGER PRIMARY KEY,
    layer        TEXT NOT NULL CHECK (layer IN ('draft', 'live', 'retracted')),
    subject      TEXT NOT NULL REFERENCES entity (id),
    predicate    TEXT NOT NULL REFERENCES predicate (name),
    object       TEXT NOT NULL,
    reader       TEXT NOT NULL,
    scope        TEXT NOT NULL REFERENCES entity (id),
    kind         TEXT NOT NULL REFERENCES coverage_kind (name),
    source_ref   TEXT NOT NULL,
    basis        TEXT NOT NULL REFERENCES basis_kind (name),
    observed_at  INTEGER NOT NULL,  -- UTC seconds
    run_id       TEXT NOT NULL,
    retracted_at INTEGER,           -- UTC seconds
    retracted_by TEXT,              -- run id
    CHECK ((layer = 'retracted') = (retracted_at IS NOT NULL))
);
CREATE INDEX assertion_reading ON assertion (layer, reader, scope, kind);

CREATE TABLE coverage (
    id           INTEGER PRIMARY KEY,
    reader       TEXT NOT NULL,
    run_id       TEXT NOT NULL,
    observed_at  INTEGER NOT NULL,
    scope        TEXT NOT NULL REFERENCES entity (id),
    kind         TEXT NOT NULL REFERENCES coverage_kind (name),
    completeness TEXT NOT NULL CHECK (completeness IN ('full', 'partial', 'none')),
    -- Why the reading was not full. On a full reading it is a note: why there was
    -- nothing to read, such as a tool that is not installed.
    reason       TEXT,
    -- Why the reading is incomplete, from a closed set (`Cause`); none on a full reading.
    cause        TEXT CHECK (cause IN ('failed', 'no_reader', 'not_given')),
    CHECK (completeness = 'full' OR reason IS NOT NULL)
);
-- What a reading found that this build has no reader for (`Lack`).
CREATE TABLE coverage_lack (
    coverage INTEGER NOT NULL REFERENCES coverage (id),
    what     TEXT NOT NULL,
    name     TEXT  -- as the source gives it, where it names one
);
-- How a thing was not read. Vocabulary: a new word is a seeded row.
CREATE TABLE unread_how (
    name TEXT PRIMARY KEY
);
-- What one reading did not read (`NotRead`): a row for each unit, and a row with no unit for what
-- is no unit of the reading. A full reading has none, and the cause of any other is the worst of
-- its rows.
CREATE TABLE coverage_unread (
    coverage INTEGER NOT NULL REFERENCES coverage (id) ON DELETE CASCADE,
    path     TEXT,                      -- the unit as the reading's ids name it; NULL: no unit
    part     TEXT NOT NULL DEFAULT '',  -- a part of the file, such as an entry's key
    cause    TEXT NOT NULL CHECK (cause IN ('failed', 'no_reader', 'not_given')),
    how      TEXT NOT NULL REFERENCES unread_how (name),
    errno    INTEGER,                   -- the system's error number, when it gave one
    said     TEXT,                      -- what the source said, cut, in the store's form
    CHECK (path IS NOT NULL OR part = '')
);

-- Containers and checkouts that were somewhere and are no longer anywhere. What was read
-- inside them was retracted with them, and their readings no longer count.
CREATE VIEW gone_entity AS
    SELECT DISTINCT r.subject AS id FROM assertion r
    WHERE r.layer = 'retracted' AND r.predicate = 'located_on'
      AND NOT EXISTS (SELECT 1 FROM assertion l
                      WHERE l.layer = 'live' AND l.predicate = 'located_on'
                        AND l.subject = r.subject);

-- The last saved copy of each raw input, so that unchanged input is not copied again.
CREATE TABLE raw_input (
    reader TEXT NOT NULL,
    input  TEXT NOT NULL,
    path   TEXT NOT NULL,  -- relative to the store's folder
    run_id TEXT NOT NULL,
    PRIMARY KEY (reader, input)
);
";

/// What the journal records: the words `journal_entry` is seeded with. A new kind of entry is a new
/// word here, which a store of this format learns at its next open, as it learns any vocabulary.
const JOURNAL_ENTRIES: [&str; 27] = [
    "run_started",
    "added",
    "changed",
    "removed",
    "report",
    "run_finished",
    // A run told to read less than a full check reads, with what it did not read: it is not a
    // full check (`status::FULL_CHECKS`).
    "run_narrowed",
    "owner_said",
    "owner_withdrew",
    "threat_added",
    "threat_gone",
    "threats_first_read",
    "finding_raised",
    "finding_reopened",
    "finding_cleared",
    "finding_expected",
    "finding_seen",
    // What a sample saw that a finding rests on, see `processes.rs`.
    "sampled",
    // One reading of a vulnerability data feed with its counts, see `osv.rs`.
    "advisories_read",
    // A reading in which a published rule matched: the rule and a count, see `events.rs`. The
    // finding rests on the one that raised it.
    "matched",
    // A place new in a worktree that is the same as in another checkout of its repository,
    // and so raised no finding, see `worktrees.rs`.
    "same_as_sibling",
    // A place read for the first time, with how many things it held that were taken as its
    // baseline, see `baseline.rs`.
    "place_first_read",
    // Something an earlier reading read in full that is there and could not be read, with why,
    // see `baseline.rs`.
    "not_read",
    // A fact of a kind this version no longer reads, closed with why: not a removal, see
    // `lifecycle::retire`.
    "retired",
    // A verdict of the response layer about a match or a finding, see `verdict.rs`.
    "verdict",
    // `immunity on` loaded the login job, and `immunity off` stopped it or removed its property
    // list: the time alone, see `service.rs`.
    "turned_on",
    "turned_off",
];

/// The journal. It cannot be rebuilt from raw input, so it only grows. Its entries are the
/// differences a run finds, the run's own notes, the owner's word, the threat list's
/// changes, and findings raised and answered. Its words are vocabulary: an entry whose word is not
/// in `journal_entry` cannot be written.
const JOURNAL: &str = "
CREATE TABLE journal_entry (
    name TEXT PRIMARY KEY
);
CREATE TABLE journal (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    run_id    TEXT NOT NULL,
    entry     TEXT NOT NULL REFERENCES journal_entry (name),
    reader    TEXT,
    scope     TEXT,
    kind      TEXT,
    subject   TEXT,
    predicate TEXT,
    old_value TEXT,
    new_value TEXT,
    text      TEXT
);
CREATE TRIGGER journal_no_update BEFORE UPDATE ON journal
    BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER journal_no_delete BEFORE DELETE ON journal
    BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
";

/// The seed of `journal_entry`, applied with the rest of the vocabulary.
fn journal_seed() -> String {
    let entries: Vec<String> = JOURNAL_ENTRIES.iter().map(|e| format!("('{e}')")).collect();
    format!(
        "INSERT OR IGNORE INTO journal_entry (name) VALUES {};",
        entries.join(", ")
    )
}

/// The owner's word: what the owner said about an entity, next to the facts and never an
/// edit of them. A withdrawn statement is kept with the time it was withdrawn.
const OWNER: &str = "
CREATE TABLE owner_statement (
    id           INTEGER PRIMARY KEY,
    entity       TEXT NOT NULL REFERENCES entity (id),
    said         TEXT NOT NULL CHECK (said IN ('retired', 'not mine')),
    reason       TEXT NOT NULL,
    made_at      INTEGER NOT NULL,  -- UTC seconds
    withdrawn_at INTEGER,           -- UTC seconds
    via          TEXT               -- how it was given: app, agent or command
);
";

/// The threat list and its readings, see docs/threats.md. Threats are not facts: they live
/// in their own tables and never touch assertions. Text in `threat` is the catalogue's own and is partly written by an attacker.
const THREATS: &str = "
CREATE TABLE threat (
    source        TEXT NOT NULL,     -- which list, such as 'cisa-kev'
    id            TEXT NOT NULL,     -- the CVE id
    vendor        TEXT NOT NULL,
    product       TEXT NOT NULL,
    name          TEXT NOT NULL,
    date_added    TEXT NOT NULL,     -- as the list gives it
    first_run     TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,  -- UTC seconds
    gone_at       INTEGER,           -- when it left the list, UTC seconds
    gone_run      TEXT,
    PRIMARY KEY (source, id),
    CHECK ((gone_at IS NULL) = (gone_run IS NULL))
);
CREATE TABLE feed_reading (
    id       INTEGER PRIMARY KEY,
    source   TEXT NOT NULL,
    run_id   TEXT NOT NULL,
    at       INTEGER NOT NULL,       -- UTC seconds
    outcome  TEXT NOT NULL CHECK (outcome IN ('read', 'unchanged', 'failed')),
    reason   TEXT,
    etag     TEXT,                   -- what the source sent, for the next conditional request
    sha256   TEXT,                   -- of the raw copy
    raw_path TEXT,                   -- relative to the store's folder
    entries  INTEGER,                -- how many entries the list held
    CHECK ((outcome = 'failed') = (reason IS NOT NULL))
);
";

/// The vocabulary seed. It is data, not format: it is applied on every open that may write, so
/// a store of the current format learns a new row without being rebuilt, and a row is never
/// removed.
const VOCABULARY: &str = "
INSERT OR IGNORE INTO entity_type (name, status) VALUES
    ('machine', 'used'), ('container', 'used'), ('checkout', 'used'), ('component', 'used'),
    ('repository', 'reserved'), ('service', 'reserved'), ('account', 'reserved'),
    ('domain', 'reserved'), ('key', 'reserved'), ('party', 'reserved'), ('file', 'used'),
    ('check', 'used');
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('located_on', 'entity', 'used'), ('part_of', 'entity', 'used'),
    ('has_version', 'literal', 'used'), ('runs_os', 'literal', 'used'),
    ('runs_kernel', 'literal', 'used'), ('runs_image', 'literal', 'used'),
    ('known_as', 'literal', 'used'), ('same_as', 'entity', 'used'),
    ('relation_to_owner', 'literal', 'used'), ('built_from', 'literal', 'used'),
    ('runs_release', 'literal', 'used'), ('release_codename', 'literal', 'used'),
    ('runs_kernel_package', 'literal', 'used'), ('watched_as', 'literal', 'used'),
    ('has_content', 'literal', 'used'), ('links_to', 'literal', 'used'),
    ('copy_of', NULL, 'reserved'), ('reachable_from', NULL, 'reserved');
INSERT OR IGNORE INTO basis_kind (name, strength) VALUES
    ('observed', 1), ('declared', 2), ('mentioned', 3);
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('brew packages'), ('checkouts under the home folder'), ('lockfile dependencies'),
    ('system packages'), ('containers'), ('container version variables'),
    ('wordpress core version'), ('container contents'),
    ('ssh configuration'), ('known hosts'), ('tailnet peers'),
    ('machines under several names'), ('checkouts in agent working folders'),
    ('own names and addresses'), ('sweep visit'), ('system package sources'),
    ('system release'), ('running kernel package'), ('launch agents and daemons'),
    ('shell profiles of zsh and bash'), ('ssh access files'),
    ('hooks in the checkout''s .git folder'), ('content of a watched file');
-- Integrity of what is installed, see src/integrity.rs.
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('installed_at', 'literal', 'used'), ('signed_by', 'literal', 'used'),
    ('has_seal', 'literal', 'used'), ('has_digest', 'literal', 'used');
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('application bundles in /Applications and ~/Applications'), ('Homebrew kegs'),
    ('global npm packages'),
    ('code kept by applications not signed by Apple under ~/Library/Application Support'),
    ('software of package managers this version does not read');
-- What runs by itself, see src/autorun.rs, and indicators, see src/indicators.rs.
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('matches_indicator', 'literal', 'used');
-- Which startup item runs a program, see src/targets.rs.
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('started_by', 'entity', 'used');
-- A peer's system as the private network names it, see src/tailnet.rs.
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('runs_platform', 'literal', 'used');
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('editor tasks set to run when a checkout''s folder is opened'),
    ('other ways a checkout runs code by itself'),
    ('indicator list given as a file'),
    ('indicators matched against watched files and texts read in checkouts'),
    ('indicators against what this build does not match them with');
-- A lockfile found in a checkout, see src/lockfiles.rs.
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('has_lockfile', 'literal', 'used');
-- Folders macOS asks the owner's permission for, see src/guarded.rs.
INSERT OR IGNORE INTO coverage_kind (name) VALUES ('folders macOS asks permission for');
-- How a thing a reading did not read was not read: the words of `look::Said::word` for a unit,
-- and of `NotRead::short` for what a reading said as a whole.
INSERT OR IGNORE INTO unread_how (name) VALUES
    ('unreadable'), ('unparsed'), ('unlisted'), ('kept'), ('same_name'), ('past_limit'),
    ('guarded'), ('untold'), ('no_reader'), ('source');
-- A place a tool read before was looked for and not found (`tools::LOOKED_FOR`), and a walk
-- for checkouts limited to the folder given (`checkouts::GIVEN`).
INSERT OR IGNORE INTO unread_how (name) VALUES ('looked_for'), ('only_given');
";

/// Indexes what `immunity status` and the view read by. Without them the status of a store of tens of thousands of
/// things took seconds: each finding looked up its subject and its basis by a full scan, and
/// each latest reading looked for its last full one the same way.
///
/// Every reading adds coverage rows, a watcher's too; only those older than the runs kept whole
/// are folded (`fold`), so the runs kept whole and what came after them can be many. The latest
/// reading of a kind, which a watcher asks for at every reading to know which machine it
/// reads, is found through `coverage_latest_of_kind`. Without it a watcher's reading looked
/// through every reading before it: 3 ms after ten readings, 124 ms after ten thousand,
/// measured when it also counted every earlier failed reading, which it no longer does.
///
/// The status and the view ask for the latest reading of each reader, scope and kind, when
/// each was last read in full, and what one run read. `LATEST` finds the first through
/// `coverage_reading`, `coverage_full` answers the second in one look-up and `coverage_run`
/// the third; `coverage_lack_of` and `coverage_unread_of` find what a latest reading names as not read. Without them `immunity status` took 8 ms after ten watcher readings and 325 ms after
/// ten thousand, and `immunity view` 9 ms and 589 ms.
const INDEXES: &str = "
CREATE INDEX coverage_reading ON coverage (reader, scope, kind);
CREATE INDEX coverage_latest_of_kind ON coverage (reader, kind);
CREATE INDEX coverage_full ON coverage (reader, scope, kind, completeness, observed_at);
CREATE INDEX coverage_run ON coverage (run_id);
CREATE INDEX coverage_lack_of ON coverage_lack (coverage);
CREATE INDEX coverage_unread_of ON coverage_unread (coverage);
CREATE INDEX assertion_subject ON assertion (subject, predicate);
CREATE INDEX finding_basis_finding ON finding_basis (finding);
";

/// The journal by run: what one run found, how it started and ended, what a reading of a feed
/// or the catalogue changed. Every run, watcher reading and sample adds to the journal and
/// nothing is ever removed from it, so without this each of those questions went through
/// the whole journal: the page of threats asked it once for each of the catalogue's 1,450
/// entries, 2.5 s of a full `immunity view` on a journal of 40,000 entries.
const JOURNAL_INDEXES: &str = "
CREATE INDEX journal_run ON journal (run_id, entry);
";

/// The start of a query that names two tables: `reading (reader, scope, kind)`, one row for
/// each reader, scope and kind ever read, and `latest`, the coverage row of the latest
/// reading of each, with every column of `coverage`. It is what `coverage WHERE id IN (SELECT
/// MAX(id) FROM coverage GROUP BY reader, scope, kind)` says, asked so that its cost follows
/// the number of things read and not the number of readings: `reading` steps through
/// `coverage_reading` from one reader, scope and kind to the next (a loose index scan), and
/// `latest` takes the last row of each from the same index. A query starts from `latest`, not
/// from `coverage`, so that SQLite never goes through every reading to match it.
pub const LATEST: &str = "
WITH RECURSIVE reading (reader, scope, kind) AS (
    SELECT * FROM (SELECT reader, scope, kind FROM coverage ORDER BY reader, scope, kind LIMIT 1)
    UNION ALL
    SELECT n.reader, n.scope, n.kind FROM reading r JOIN coverage n ON n.id = COALESCE(
        (SELECT id FROM coverage WHERE reader = r.reader AND scope = r.scope AND kind > r.kind
         ORDER BY reader, scope, kind LIMIT 1),
        (SELECT id FROM coverage WHERE reader = r.reader AND scope > r.scope
         ORDER BY reader, scope, kind LIMIT 1),
        (SELECT id FROM coverage WHERE reader > r.reader ORDER BY reader, scope, kind LIMIT 1))
),
latest AS (
    SELECT c.* FROM reading r CROSS JOIN coverage c
    ON c.id = (SELECT l.id FROM coverage l
               WHERE l.reader = r.reader AND l.scope = r.scope AND l.kind = r.kind
               ORDER BY l.id DESC LIMIT 1)
)
";

/// The condition that the entity `x` names is gone: what `x IN (SELECT id FROM gone_entity)`
/// says for an `x` that is never NULL, asked of that one id through `assertion_subject`. The
/// view reads every retracted fact through `assertion_reading`, about 130 ms on an invented
/// store a year old; the unary `+` keeps the planner off that index. `x` is qualified by a table
/// of the statement, since an unqualified name such as `scope` would be read as a column of
/// `assertion` here, and the aliases are unlike any a statement around it uses.
pub fn gone_entity(x: &str) -> String {
    format!(
        "(EXISTS (SELECT 1 FROM assertion gone_r WHERE gone_r.subject = {x}
                  AND gone_r.predicate = 'located_on' AND +gone_r.layer = 'retracted')
          AND NOT EXISTS (SELECT 1 FROM assertion gone_l WHERE gone_l.subject = {x}
                          AND gone_l.predicate = 'located_on' AND +gone_l.layer = 'live'))"
    )
}

/// Why a reading is incomplete. The order is from worst: a reading incomplete for several
/// reasons takes the worst of them, so that it never looks better than it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cause {
    /// The reader tried and could not: no access, an error, a visit that failed or did not
    /// complete, a file that could not be opened.
    Failed,
    /// The thing is there and this build has no reader for it.
    NoReader,
    /// The source was read and does not hold this.
    NotGiven,
}

impl Cause {
    /// The literal kept in `coverage.cause`.
    pub fn literal(self) -> &'static str {
        match self {
            Cause::Failed => "failed",
            Cause::NoReader => "no_reader",
            Cause::NotGiven => "not_given",
        }
    }

    /// The worst of several causes, or `None` when there is none.
    pub fn worst(causes: impl IntoIterator<Item = Cause>) -> Option<Cause> {
        causes.into_iter().min()
    }
}

/// Something this build has no reader for, found in a reading: what it is in the program's
/// words, and its name where the source gives one, such as a lockfile's or a package
/// manager's. It is recorded whatever the reading's worst cause is.
#[derive(Clone, Debug, PartialEq)]
pub struct Lack {
    pub what: &'static str,
    pub name: Option<String>,
}

impl Lack {
    pub fn new(what: &'static str, name: Option<&str>) -> Lack {
        Lack {
            what,
            name: name.map(str::to_string),
        }
    }
}

/// One thing a reading did not read, as `coverage_unread` keeps it: a unit, by the path and part
/// the reading's ids name it by, or no unit for what is no unit of the reading; its cause; how it
/// was not read, a word of `unread_how`; the system's error number; and what the source said,
/// cut, in the store's form.
#[derive(Clone, Debug, PartialEq)]
pub struct NotRead {
    pub unit: Option<crate::baseline::Unit>,
    pub cause: Cause,
    pub how: &'static str,
    pub errno: Option<i32>,
    pub said: Option<String>,
}

impl NotRead {
    /// What a reading said as a whole, of a unit or of none: with no reader, or else said by the
    /// reading's source.
    pub fn short(unit: Option<crate::baseline::Unit>, cause: Cause) -> NotRead {
        NotRead::said(unit, cause, NotRead::word(cause))
    }

    /// The same, said by `how`, a word of `unread_how` of its own.
    pub fn said(unit: Option<crate::baseline::Unit>, cause: Cause, how: &'static str) -> NotRead {
        NotRead {
            unit,
            cause,
            how,
            errno: None,
            said: None,
        }
    }

    /// The word of what a reading said as a whole with this cause.
    pub fn word(cause: Cause) -> &'static str {
        match cause {
            Cause::NoReader => "no_reader",
            Cause::Failed | Cause::NotGiven => "source",
        }
    }
}

/// One row of `coverage_unread` as it is read back (`unread_of`): what a reading did not read.
/// What a reading did not read is decided from these rows, never from its reason, which names
/// places in prose a name from the Mac can break.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Unread {
    /// The unit, as the reading's ids name it; `None` for what is no unit of the reading.
    pub path: Option<String>,
    pub part: String,
    /// As `Cause::literal` writes it.
    pub cause: String,
    /// A word of `unread_how`.
    pub how: String,
    pub errno: Option<i32>,
}

impl Unread {
    /// Whether it failed because the system refused for want of permission, which the person can
    /// change: EPERM or EACCES. A file of another account closed to this one keeps no number
    /// (`closed::Failure::errno`), as its reason is the core's.
    pub fn refused(&self) -> bool {
        self.cause == Cause::Failed.literal()
            && matches!(self.errno, Some(libc::EPERM | libc::EACCES))
    }

    /// Whether its unit is the place at `path`, as ids name it, or holds it.
    pub fn hides(&self, path: &str) -> bool {
        use crate::baseline::Unit;
        (self.path.as_ref()).is_some_and(|p| Unit::part(p, &self.part).hides(&Unit::whole(path)))
    }

    /// The row a reading writes for `n`, as it is read back.
    #[cfg(test)]
    pub fn of(n: &NotRead) -> Unread {
        Unread {
            path: n.unit.as_ref().map(|u| u.path.clone()),
            part: n.unit.as_ref().map(|u| u.part.clone()).unwrap_or_default(),
            cause: n.cause.literal().to_string(),
            how: n.how.to_string(),
            errno: n.errno,
        }
    }
}

/// What each of the readings `coverage` did not read, in the order given, each in the order it was
/// written.
pub fn unread_of(conn: &Connection, coverage: &[i64]) -> rusqlite::Result<Vec<Vec<Unread>>> {
    let mut stmt = conn.prepare(
        "SELECT path, part, cause, how, errno FROM coverage_unread WHERE coverage = ?1
         ORDER BY rowid",
    )?;
    let row = |r: &rusqlite::Row| {
        Ok(Unread {
            path: r.get(0)?,
            part: r.get(1)?,
            cause: r.get(2)?,
            how: r.get(3)?,
            errno: r.get(4)?,
        })
    };
    (coverage.iter())
        .map(|id| stmt.query_map([id], row)?.collect())
        .collect()
}

/// Why a reading is incomplete, what this build has no reader for in it, and what it did not
/// read. Empty on a full reading.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Gap {
    pub cause: Option<Cause>,
    pub lacks: Vec<Lack>,
    pub not_read: Vec<NotRead>,
}

impl Gap {
    pub fn of(cause: Cause) -> Gap {
        Gap::when(Some(cause))
    }

    /// The gap of a reading that failed as a whole, with the system's error number when it gave
    /// one, kept on its row.
    pub fn failed(errno: Option<i32>) -> Gap {
        let row = NotRead {
            errno,
            ..NotRead::short(None, Cause::Failed)
        };
        Gap {
            not_read: vec![row],
            ..Gap::of(Cause::Failed)
        }
    }

    /// The gap of a reading with this cause, if it is incomplete at all.
    pub fn when(cause: Option<Cause>) -> Gap {
        Gap {
            cause,
            ..Gap::default()
        }
    }
}

/// One reading: which reader looked for which kind of thing in which scope.
/// `at` is the time of the run; `observed_at` is when the source itself was read,
/// which for a server file is when the sweep wrote it.
pub struct Reading<'a> {
    pub reader: &'a str,
    pub scope: &'a str,
    pub kind: &'a str,
    pub run_id: &'a str,
    pub at: i64,
    pub observed_at: i64,
}

/// A statement as a reader makes it, before it becomes a draft assertion.
pub struct Statement {
    pub subject: String,
    pub predicate: &'static str,
    pub object: String,
    pub source_ref: String,
}

/// A difference between draft and live for one subject and predicate.
#[derive(Clone)]
pub struct Event {
    pub kind: &'static str,
    pub subject: String,
    pub predicate: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Every statement that makes a store of this format: every table, index, view and trigger of
/// every part of the program. It is the one place the schema is made from: a new store is made
/// from it, in one transaction, and every open compares a store with what it makes (`check`).
/// No other code creates, alters or drops a table of the store.
fn schema() -> String {
    [
        SCHEMA,
        JOURNAL,
        OWNER,
        THREATS,
        crate::osv::SCHEMA,
        crate::vulnerabilities::SCHEMA,
        crate::findings::SCHEMA,
        crate::agent_folders::SCHEMA,
        crate::verdict::SCHEMA,
        crate::events::SCHEMA,
        crate::processes::SCHEMA,
        crate::baseline::SCHEMA,
        crate::watch::SCHEMA,
        INDEXES,
        JOURNAL_INDEXES,
    ]
    .join("\n")
}

/// Opens the store, making it first where no file is: what `immunity run`, `immunity sample` and
/// the start of `immunity watch` do. Every other command, and a watcher already running, only
/// opens (`open`).
pub fn open_or_make(path: &Path) -> Result<Connection, Outcome> {
    make_if_absent(path).map_err(Outcome::from)?;
    open(path)
}

/// Makes a store where no file is, and leaves alone whatever is at the path.
pub fn make_if_absent(path: &Path) -> Res<()> {
    match exists(path)? {
        true => Ok(()),
        false => make(path),
    }
}

/// Whether anything is at the path, a file of any kind or a link, even one that leads nowhere.
fn exists(path: &Path) -> Res<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => {
            Err(Outcome::new(Code::Io, format!("cannot look at {}: {e}", path.display())).into())
        }
    }
}

/// The two files SQLite keeps beside a store in write-ahead mode: the log of what was committed
/// since the last checkpoint (`-wal`) and its index (`-shm`). They are part of the store.
pub fn beside(path: &Path) -> [PathBuf; 2] {
    ["-wal", "-shm"].map(|end| ended(path, end))
}

fn ended(path: &Path, end: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(end);
    PathBuf::from(name)
}

/// A store of this format never has a rollback journal beside it. One that is there is the
/// unfinished write of a store an earlier build made in rollback mode, or of something else, and
/// SQLite plays it back into the file it opens at the path before anything can be checked, a
/// store just made included. So where one stands nothing is opened or made, by any command.
fn no_journal(path: &Path) -> Res<()> {
    let journal = ended(path, "-journal");
    if !exists(&journal)? {
        return Ok(());
    }
    let said = format!(
        "{} is beside {}: the unfinished write of a store an earlier build of Immunity Core \
         made, or of something else, which SQLite would play back into the store. A store of \
         this build never has one. Nothing was opened, made or changed. Move the store aside \
         with its -journal, -wal and -shm files or pass another --store; the next run starts a \
         store from the beginning.",
        journal.display(),
        path.display()
    );
    Err(Outcome::new(Code::UnknownFormat, said).into())
}

/// Makes a whole store where there was no file. It is made under a name of its own in the same
/// folder, committed and closed, and then linked to the path with link(2), which fails if
/// anything is at the path: so the path holds no file or a whole store, never a half-made one,
/// whether the process dies part way or two commands make a store at once. The one that links
/// second finds the other's store, keeps it and removes its own. A process killed before the
/// link leaves only files named `.<store>.making-…` beside the store, which no command reads.
///
/// The store is in write-ahead mode from its making. The making connection keeps none of its
/// own `-wal` and `-shm`: it checkpoints and removes them as it closes, so the file linked holds
/// everything. The store is then opened once to write, which makes its `-wal` and `-shm` and
/// keeps them (`writer`). A `-wal` or `-shm` already beside a path that holds no store was left
/// by a store moved or deleted without it, and SQLite would read it as part of the new store,
/// so nothing is made there, nor where a rollback journal stands (`no_journal`).
fn make(path: &Path) -> Res<()> {
    no_journal(path)?;
    for left in beside(path) {
        if exists(&left)? && !exists(path)? {
            let said = format!(
                "there is no store at {}, but {} is beside it, left by a store moved or deleted \
                 without it, and SQLite would read it as part of a new store. Nothing was made. \
                 Move it aside with the other files of the old store or pass another --store.",
                path.display(),
                left.display()
            );
            return Err(Outcome::new(Code::NotAStore, said).into());
        }
    }
    let folder = path.parent().filter(|p| !p.as_os_str().is_empty());
    let folder = folder.unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let making = folder.join(format!(
        ".{name}.making-{}-{}",
        std::process::id(),
        now.as_nanos()
    ));
    let made = (|| -> Res<()> {
        let mut conn = Connection::open_with_flags(
            &making,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "wal", |r| r.get(0))?;
        if mode != "wal" {
            return Err(
                format!("SQLite did not put the new store in write-ahead mode: {mode}").into(),
            );
        }
        let tx = conn.transaction()?;
        tx.execute_batch(&schema())?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('format_version', ?1)",
            [FORMAT_VERSION],
        )?;
        give_id(&tx)?;
        tx.commit()?;
        conn.close().map_err(|(_, e)| e)?;
        match std::fs::hard_link(&making, path) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e.into()),
            // Its first read makes the `-wal` and `-shm`, which its close keeps.
            Ok(()) => {
                writer(path)?.query_row("PRAGMA journal_mode", [], |_| Ok(()))?;
                Ok(())
            }
        }
    })();
    for file in [making.clone()].into_iter().chain(beside(&making)) {
        let _ = std::fs::remove_file(file);
    }
    made
}

/// Opens a store that is there. It never makes a store or a table, whatever the file holds:
/// a file that is not a store of this format, or one that does not hold exactly the schema of
/// this format and its id, is refused before anything is written and is left as it is. Old
/// stores are not converted and a damaged one is not repaired.
///
/// The store is in write-ahead mode, SQLite's design for one writer beside readers in other
/// processes: a reader reads the last committed state from the file and its `-wal`, and never
/// waits for a writer, and a writer never waits for a reader, however long either holds its
/// transaction. A run writes in one transaction that lasts the whole run, and `immunity status`
/// reads what was committed before it all that time. Two writers still meet: a writer begins
/// every transaction by taking the write lock (`writer`), and waits for it up to rusqlite's
/// busy timeout of five seconds.
///
/// Every command and every step of a watcher opens the store and closes it again. A writer that
/// closes while no other connection is open copies the log into the file, as SQLite does by
/// default, and keeps the `-wal`, cut to nothing, and the `-shm` (`opened`). So the next open
/// finds no log to read through before it answers, unless a writer died or another connection
/// was open when the last writer closed; then the first open reads the log through to rebuild
/// its index, and a reader or writer that comes in that moment waits for it, as for a writer.
pub fn open(path: &Path) -> Result<Connection, Outcome> {
    opened(path).map_err(Outcome::from)
}

fn opened(path: &Path) -> Res<Connection> {
    if !exists(path)? {
        return Err(absent(path).into());
    }
    no_journal(path)?;
    let conn = writer(path)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    check(&conn, path)?;
    // Only now that the store is this build's does the close copy the log into the file. The
    // `-wal` and `-shm` are kept, for a reader that cannot make them, and the `-wal` is cut to
    // nothing at that close (`journal_size_limit`, which also cuts it back to the size the
    // automatic checkpoint lets it reach while the connection is open).
    let page: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    let pages: i64 = conn.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))?;
    conn.pragma_update(None, "journal_size_limit", page * pages)?;
    conn.file_control(Some(rusqlite::MAIN_DB), FileControl::PersistWal(&mut 1))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)?;
    conn.execute_batch(VOCABULARY)?;
    conn.execute_batch(&journal_seed())?;
    conn.execute_batch(crate::processes::KINDS)?;
    crate::autorun::add_kinds(&conn)?;
    crate::watched::add_kinds(&conn)?;
    Ok(conn)
}

/// A connection that may write the store, opened without making it. Its close copies nothing
/// into the file (`SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE`) until `opened` has found the store this
/// build's, so a refused store's file is left as it was, and SQLite removes no `-wal` or `-shm`
/// it did not copy. Every transaction takes the write lock as it begins (`BEGIN IMMEDIATE`): one
/// that read first and wrote after another writer's commit would fail on a snapshot that is no
/// longer the latest, and waiting does not end that.
fn writer(path: &Path) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    conn.set_transaction_behavior(TransactionBehavior::Immediate);
    Ok(conn)
}

/// The store's own id, as every message of the contract carries it (`store_id`): a finding's id
/// is unique only within one store, and a store deleted and made again can give it to another
/// finding. Every store of this format holds one from when it is made; a store without it fails
/// to read.
pub fn id(conn: &Connection) -> rusqlite::Result<String> {
    conn.query_row("SELECT value FROM meta WHERE key = 'store_id'", [], |r| {
        r.get(0)
    })
}

/// Gives the store its id, in the transaction that makes it. 16 random bytes from `getentropy`,
/// which macOS ships, as hexadecimal. It is never derived from anything on the Mac, so it says
/// nothing about it.
fn give_id(conn: &Connection) -> Res<()> {
    let mut bytes = [0u8; 16];
    // SAFETY: the pointer and the length are those of `bytes`, which outlives the call;
    // getentropy fills at most 256 bytes and writes nothing else.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(format!(
            "no random bytes for the store's id: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('store_id', ?1)",
        [hex],
    )?;
    Ok(())
}

/// One read of the store, as every command that only reads it reads: the store opened read-only
/// (`open_read_only`) and `f` run in one read transaction, so that everything `f` reads is of one
/// state of the store and a writer commits before it or after it, never between two of its
/// reads. No store at the path is refused as `open` refuses it (`absent`). Every error, the
/// opening's and each of `f`'s, is told by the one mapping (`outcome::of`): another process that
/// holds the store past the busy timeout is `store_busy`, whichever read met it.
pub fn read<T>(path: &Path, f: impl FnOnce(&Connection) -> Res<T>) -> Result<T, Outcome> {
    if !exists(path).map_err(Outcome::from)? {
        return Err(absent(path));
    }
    let conn = open_read_only(path)?;
    let tx = conn.unchecked_transaction()?;
    f(&tx).map_err(Outcome::from)
}

/// One short write of the store, as every command that writes a little writes it: an answer, a
/// verdict, a statement about a machine, the entry of `immunity off`, a sample, a check's start.
/// A store that is there is checked first, read-only (`read`), so one this build refuses is told
/// at once and never as a skip. Then the run lock is taken, waited for up to `wait`, and `open`
/// opens the store under it: `open_or_make` for a command that makes the store where there is
/// none. `f` runs in one transaction, which takes the write lock as it begins, and is committed
/// only when `f` returns `Ok`. The check, the lock and the opening fail with their `Outcome`;
/// SQLite's error at the transaction's start or commit is given as SQLite gave it, for the
/// caller's mapping (`outcome::of`), as `f`'s own errors are.
pub fn write<T, E: From<Outcome> + From<rusqlite::Error>>(
    path: &Path,
    wait: Duration,
    open: fn(&Path) -> Result<Connection, Outcome>,
    f: impl FnOnce(&Transaction) -> Result<T, E>,
) -> Result<T, E> {
    if exists(path).map_err(Outcome::from)? {
        read(path, |_| Ok(()))?;
    }
    let _lock = lock_run_waiting(&crate::home(path), wait)
        .map_err(|e| crate::outcome::of(&e))?
        .ok_or_else(|| Outcome::new(Code::RunLockHeld, ""))?;
    committed(open(path)?, f)
}

/// A write by the watcher, which holds the run lock across its steps, in one transaction as
/// `write` runs it.
pub fn write_held<T, E: From<Outcome> + From<rusqlite::Error>>(
    path: &Path,
    f: impl FnOnce(&Transaction) -> Result<T, E>,
) -> Result<T, E> {
    committed(open(path)?, f)
}

fn committed<T, E: From<Outcome> + From<rusqlite::Error>>(
    mut conn: Connection,
    f: impl FnOnce(&Transaction) -> Result<T, E>,
) -> Result<T, E> {
    let tx = conn.transaction()?;
    let done = f(&tx)?;
    tx.commit()?;
    Ok(done)
}

/// Opens an existing store so that nothing can be written to it. A command that only reads the
/// store reads it through `read`.
///
/// It reads the last committed state, from the store's file and its `-wal`. A writer killed
/// inside its transaction, a run or a watcher stopped by a crash or a forced restart, may have
/// left pages of it in the `-wal`, but no commit names them, so no reader reads them and
/// nothing has to be undone first. In a folder this process cannot write, SQLite reads the
/// store as long as its `-wal` and `-shm` are beside it, which every writer keeps (`opened`).
/// Without one, SQLite says only that it cannot write or open, so the refusal names the file.
pub fn open_read_only(path: &Path) -> Result<Connection, Outcome> {
    no_journal(path).map_err(Outcome::from)?;
    let read = || -> Res<Connection> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        check(&conn, path)?;
        Ok(conn)
    };
    read().map_err(|e| {
        let refused = Outcome::from(e);
        let gone = beside(path).into_iter().find(|f| !f.exists());
        match gone.filter(|_| matches!(refused.code, Code::NotWritable | Code::CannotOpen)) {
            Some(gone) => Outcome::new(
                refused.code,
                format!(
                    "SQLite reads the store at {} only with {} beside it, which is not there, and \
                     this process cannot make it in that folder. Nothing was changed. A command \
                     that may write the folder makes it, such as `immunity run`.",
                    path.display(),
                    gone.display()
                ),
            ),
            None => refused,
        }
    })
}

/// The refusal of a path that holds no store, as every command gives it: the same words wherever
/// it is found that there is none.
pub fn absent(path: &Path) -> Outcome {
    let said = format!(
        "there is no store at {}; `immunity run` makes it",
        path.display()
    );
    Outcome::new(Code::NoStore, said)
}

/// Why a part of an answer was not computed when there is no store (`not_computed`), as every
/// message of the contract gives it.
pub const NO_STORE_REASON: &str = "there is no store yet; `immunity run` makes it";

/// What every command tells a person when there is no store at the path, in one wording: the
/// headline or the cause, and what makes one. A span in backticks is a command.
pub const NO_STORE: &str = "there is no store here yet";
pub const NO_STORE_FIX: &str =
    "`immunity run` makes one, or `immunity on`, which also keeps it checked.";

/// What every command tells a person about a store another build made, in one wording.
pub const OTHER_FORMAT: &str = "this store was made by another build of Immunity Core";
pub const OTHER_FORMAT_FIX: &str = "It was left unchanged. Move it aside with its -wal and -shm \
                                    files or pass another --store; the next check starts one from \
                                    the beginning.";

/// What every refusal of a store ends with: what was done to it and what to do.
const START_OVER: &str = "Nothing was changed. Move the old store aside with its -wal and -shm \
                          files or pass another --store; the next run starts a store from the \
                          beginning.";

/// What the refusal of a file that holds no store says to do.
const NOT_A_STORE: &str = "Nothing was changed. Move it aside with any -wal and -shm files beside \
                           it or pass another --store; the next run makes a store where there is \
                           no file.";

/// Checks a store before anything else is done with it: that the file is a store at all, its
/// format, that it is in write-ahead mode, that it holds exactly the schema of this format, and
/// its id. A store that fails is refused with what to do and is not touched. So no answer ever
/// rests on a table that is not there, and no command makes again, empty, a table or a store
/// that was lost with what it held.
fn check(conn: &Connection, path: &Path) -> Res<()> {
    let at = path.display();
    let refused =
        |code, said: String| -> Box<dyn std::error::Error> { Outcome::new(code, said).into() };
    let objects: i64 = match conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))
    {
        Err(e) if e.sqlite_error_code() == Some(rusqlite::ErrorCode::NotADatabase) => {
            return Err(refused(
                Code::NotAStore,
                format!("{at} is not a store: it is not an SQLite file. {NOT_A_STORE}"),
            ));
        }
        other => other?,
    };
    if objects == 0 {
        let empty = std::fs::metadata(path).is_ok_and(|m| m.len() == 0);
        return Err(refused(
            Code::NotAStore,
            match empty {
                true => format!("{at} is an empty file, not a store. {NOT_A_STORE}"),
                false => format!(
                    "{at} is an SQLite file that holds no tables, not a store. {NOT_A_STORE}"
                ),
            },
        ));
    }
    let one = |key: &str| -> rusqlite::Result<Option<String>> {
        // A table `meta` without the columns `key` and `value` holds no value; any other
        // failure is returned as it is.
        let readable: bool = conn.query_row(
            "SELECT COUNT(*) = 2 FROM pragma_table_info('meta') WHERE name IN ('key', 'value')",
            [],
            |r| r.get(0),
        )?;
        if !readable {
            return Ok(None);
        }
        let (rows, value): (i64, Option<String>) = conn.query_row(
            "SELECT COUNT(*), MAX(CASE WHEN typeof(value) = 'text' THEN value END)
             FROM meta WHERE key = ?1",
            [key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(value.filter(|_| rows == 1))
    };
    let Some(version) = one("format_version")? else {
        return Err(refused(
            Code::UnknownFormat,
            format!(
                "{at} is not a store of this tool: it does not name exactly one format. \
                 {START_OVER}"
            ),
        ));
    };
    let ours: u32 = FORMAT_VERSION.parse()?;
    // A format is a number written as `FORMAT_VERSION` is: digits, with no sign or leading zero.
    let found = version
        .parse::<u32>()
        .ok()
        .filter(|n| n.to_string() == version);
    match found {
        None => {
            return Err(refused(
                Code::UnknownFormat,
                format!(
                    "the store at {at} names a format this version does not know ({version:?}). \
                     {START_OVER}"
                ),
            ));
        }
        Some(found) if found < ours => {
            return Err(refused(
                Code::OlderFormat,
                format!(
                    "the store at {at} is from an older format ({found}); this version uses \
                     format {ours} and does not convert old stores. {START_OVER}"
                ),
            ));
        }
        Some(found) if found > ours => {
            return Err(refused(
                Code::NewerFormat,
                format!(
                    "the store at {at} is from a newer format ({found}) than this version knows \
                     ({ours}). Nothing was changed. Use the version of Immunity Core that made it, \
                     or pass another --store."
                ),
            ));
        }
        Some(_) => {}
    }
    // The journal mode is written in the file and is part of the format: a store in another
    // was changed by something else, and converting it would be a write at open.
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if mode != "wal" {
        let why = format!("it is in the journal mode {mode:?}, not in write-ahead mode");
        return Err(refused(Code::Damaged, damaged(path, &why)));
    }
    if let Some(why) = differs(expected(), &shape(conn)?) {
        return Err(refused(Code::Damaged, damaged(path, &why)));
    }
    if !one("store_id")?.is_some_and(|id| is_id(&id)) {
        let why = "it has no id of the form Immunity Core gives one";
        return Err(refused(Code::Damaged, damaged(path, why)));
    }
    Ok(())
}

/// Whether `id` has the form `give_id` writes: 32 lower-case hexadecimal characters.
fn is_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn damaged(path: &Path, why: &str) -> String {
    format!(
        "the store at {} is damaged: {why}. A store of format {FORMAT_VERSION} is exactly as \
         this version makes it, so something other than Immunity Core changed it. {START_OVER}",
        path.display()
    )
}

/// What a store of this format holds, made once in each process from `schema` in a store in
/// memory, so that the check and the making of a store can never disagree.
fn expected() -> &'static Shape {
    static SHAPE: std::sync::OnceLock<Shape> = std::sync::OnceLock::new();
    SHAPE.get_or_init(|| {
        let conn = Connection::open_in_memory().expect("SQLite opens a store in memory");
        conn.execute_batch(&schema())
            .expect("the schema of this format makes a store");
        shape(&conn).expect("SQLite describes a store it made")
    })
}

/// A store's schema as the check compares it: every object `sqlite_master` holds, SQLite's own
/// among them (the indexes it makes for a UNIQUE or a primary key, the table that keeps
/// AUTOINCREMENT's counters), by its type and name, with its table and its text. The text is
/// the statement that made it, so it holds every column, type, constraint, collation, key and
/// option, `WITHOUT ROWID` and AUTOINCREMENT among them. It is compared as `normal` gives it,
/// with comments taken out and blank space made one space, so that a comment or the layout of
/// the schema's source is not a change of format.
type Shape = std::collections::BTreeMap<String, String>;

fn shape(conn: &Connection) -> rusqlite::Result<Shape> {
    conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master")?
        .query_map([], |r| {
            let (kind, name): (String, String) = (r.get(0)?, r.get(1)?);
            let (table, sql): (String, Option<String>) = (r.get(2)?, r.get(3)?);
            Ok((
                format!("{kind} {name}"),
                format!("on {table}: {}", normal(sql.as_deref().unwrap_or_default())),
            ))
        })?
        .collect()
}

/// A statement of the schema with its comments, from `--` to the end of the line, taken out and
/// every run of blank space made one space. The schema's source holds no `--` and no run of
/// blank space inside a quoted string, which a test pins, so this changes no string.
fn normal(sql: &str) -> String {
    sql.lines()
        .map(|line| line.split_once("--").map_or(line, |(code, _)| code))
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The first way a store's schema is not the one this format makes, in words; `None` when it
/// is the same.
fn differs(want: &Shape, got: &Shape) -> Option<String> {
    // A missing table is said before what went with it.
    let mut objects: Vec<(&String, &String)> = want.iter().collect();
    objects.sort_by_key(|(object, _)| !object.starts_with("table "));
    for (object, detail) in objects {
        match got.get(object) {
            None => return Some(format!("it lacks the {object}")),
            Some(d) if d != detail => {
                return Some(format!("its {object} is not as this format makes it"));
            }
            Some(_) => {}
        }
    }
    got.keys()
        .find(|object| !want.contains_key(*object))
        .map(|object| format!("it holds a {object} this format does not"))
}

/// How long a command waits for the run lock before it says another holds it. A `immunity
/// status` holds the lock shared for a moment only; a check holds it for minutes.
pub const LOCK_WAIT: Duration = Duration::from_secs(2);

/// Takes the run lock on the store's folder, for as long as the handle returned stays open,
/// or `None` when another run holds it. The lock is flock(2) on the folder: on macOS flock
/// and the record locks SQLite takes on the database file are one mechanism, so the file
/// itself cannot carry it, and a folder needs no file of its own. It is the kernel's lock:
/// it goes when the process ends, however it ends, so a run that died never looks like one
/// in progress. Two stores in one folder share it.
pub fn lock_run(folder: &Path) -> std::io::Result<Option<File>> {
    lock_waiting(File::open(folder)?)
}

/// Takes the kernel's lock on `handle`, waiting up to `LOCK_WAIT` for whoever holds it, or
/// `None` when it is still held. The wait is also what lets `held` look at a lock without
/// turning away a process that takes it at that moment.
pub fn lock_waiting(handle: File) -> std::io::Result<Option<File>> {
    let start = Instant::now();
    loop {
        match handle.try_lock() {
            Ok(()) => return Ok(Some(handle)),
            Err(TryLockError::WouldBlock) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Error(e)) => return Err(e),
        }
    }
}

/// Whether a process holds the lock taken by `lock_waiting` on the file at `path` now. It opens
/// it only to read (`open::open`), creates nothing, and holds the lock shared for a moment,
/// which a process taking it meanwhile waits out. Nothing at the path is no lock held; anything
/// but a regular file there is an error.
pub fn held(path: &Path) -> std::io::Result<bool> {
    use crate::open::Refused;
    let handle = match crate::open::open(path, crate::open::Reach::Own, crate::open::UNCAPPED) {
        Ok((handle, _)) => handle,
        Err(Refused::Look(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(Refused::Look(e) | Refused::Failed(e)) => return Err(e),
        Err(refused) => return Err(std::io::Error::other(refused)),
    };
    match handle.try_lock_shared() {
        Ok(()) => Ok(false),
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

// --- The watcher's lock, for `immunity watch` (src/watch.rs). ---

/// The file in the store's folder that the watcher holds locked while it runs. The run lock is
/// on the folder itself, so the watcher's needs a file of its own.
pub const WATCH_LOCK: &str = "watch.lock";

/// Takes the watcher's lock on the store's folder for as long as the handle returned stays
/// open, or `None` when another watcher holds it. The same kernel lock as the run lock: it
/// goes when the process ends, however it ends, so a watcher that died never looks alive.
pub fn lock_watch(folder: &Path) -> std::io::Result<Option<File>> {
    lock_waiting(
        File::options()
            .create(true)
            .append(true)
            .open(folder.join(WATCH_LOCK))?,
    )
}

/// Whether a watcher holds its lock on the store's folder now (`held`).
pub fn watch_in_progress(folder: &Path) -> std::io::Result<bool> {
    held(&folder.join(WATCH_LOCK))
}

/// How long a full run waits for the run lock, held by a watcher's reading or a command. Measured on a store of 30,000 things: a watcher's
/// reading holds the lock 0.03 s when one of 40 watched files changed, 0.3 s when all 40 did,
/// and about 1 s and 8 s with 1,000 watched files. It leaves at least a second between
/// readings, so a run waiting gets the lock. A reading under a heavy load of the Mac has held
/// the store for 12 s.
pub const CHECK_WAIT: Duration = Duration::from_secs(60);

/// The run lock, waited for up to `wait`, then `None`: `LOCK_WAIT` for a command, `CHECK_WAIT`
/// for a full run. A full run holds the lock on the downloads (`osv::lock_fetch`), so whoever
/// holds the run lock it waits for is a reading or a command, never another full run.
pub fn lock_run_waiting(folder: &Path, wait: Duration) -> std::io::Result<Option<File>> {
    let start = Instant::now();
    loop {
        if let Some(lock) = lock_run(folder)? {
            return Ok(Some(lock));
        }
        if start.elapsed() >= wait {
            return Ok(None);
        }
    }
}

// --- End of the watcher's lock. ---

/// The entity type is the part of the id before the first colon.
pub fn put_entity(tx: &Transaction, id: &str) -> rusqlite::Result<()> {
    let entity_type = id.split(':').next().unwrap_or(id);
    tx.execute(
        "INSERT OR IGNORE INTO entity (id, type) VALUES (?1, ?2)",
        params![id, entity_type],
    )?;
    Ok(())
}

/// Writes one draft assertion, and the entities it names: the subject, and the object
/// when the vocabulary says the predicate points at an entity.
pub fn put_draft(
    tx: &Transaction,
    r: &Reading,
    basis: &str,
    s: &Statement,
) -> rusqlite::Result<()> {
    put_entity(tx, &s.subject)?;
    let points_at_entity: bool = tx.query_row(
        "SELECT object_kind = 'entity' FROM predicate WHERE name = ?1",
        [s.predicate],
        |row| row.get(0),
    )?;
    if points_at_entity {
        put_entity(tx, &s.object)?;
    }
    tx.execute(
        "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                source_ref, basis, observed_at, run_id)
         VALUES ('draft', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
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
        ],
    )?;
    Ok(())
}

/// Writes one reading's coverage, with why it is incomplete, what this build has no reader for
/// in it and what it did not read. A full reading has no cause and no row of what it did not
/// read. An incomplete one without a cause is a mistake in a reader: it is read back as `failed`,
/// because unknown is never calm. An incomplete one has a row for each thing it did not read, and
/// where none of them has its cause, as for a reader that names no unit, a row with no unit that
/// has it, so that its cause is always the worst of its rows.
pub fn put_coverage(
    tx: &Transaction,
    r: &Reading,
    completeness: &str,
    reason: Option<&str>,
    gap: &Gap,
) -> rusqlite::Result<()> {
    debug_assert_eq!(
        completeness == "full",
        gap.cause.is_none(),
        "{} {} {completeness}",
        r.reader,
        r.kind
    );
    // An incomplete reading without a cause is read back as failed.
    let cause = gap.cause.map(Cause::literal);
    tx.execute(
        "INSERT INTO coverage (reader, run_id, observed_at, scope, kind, completeness, reason,
                               cause)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            r.reader,
            r.run_id,
            r.observed_at,
            r.scope,
            r.kind,
            completeness,
            reason,
            cause
        ],
    )?;
    let id = tx.last_insert_rowid();
    for lack in &gap.lacks {
        tx.execute(
            "INSERT INTO coverage_lack (coverage, what, name) VALUES (?1, ?2, ?3)",
            params![id, lack.what, lack.name],
        )?;
    }
    let Some(own) = gap.cause else {
        return Ok(());
    };
    let worst = Cause::worst(gap.not_read.iter().map(|n| n.cause));
    debug_assert!(worst.is_none_or(|w| w >= own), "{} {}", r.reader, r.kind);
    let source = (worst != Some(own)).then(|| NotRead::short(None, own));
    for n in gap.not_read.iter().chain(&source) {
        let (path, part) = n
            .unit
            .as_ref()
            .map_or((None, ""), |u| (Some(&u.path), u.part.as_str()));
        tx.execute(
            "INSERT INTO coverage_unread (coverage, path, part, cause, how, errno, said)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, path, part, n.cause.literal(), n.how, n.errno, n.said],
        )?;
    }
    Ok(())
}

// --- Folding the history of readings. ---

/// How many runs the changes page lists, each with every reading it made.
pub const RUNS_KEPT: i64 = 20;

/// One run the changes page lists.
pub struct Listed {
    pub run_id: String,
    /// When it began: its earliest journal entry.
    pub at: i64,
    pub finished: bool,
    /// The report line of a full run that finished.
    pub report: Option<String>,
}

/// The runs a page or an answer asks about by their id, newest first: the last `RUNS_KEPT`
/// the journal holds, which the changes page lists. A run is what the journal says started as
/// one, a watcher's reading or a sample; an answer, a statement or a verdict is not a run,
/// whatever its id. The fold keeps every reading of each of them (`kept_from`).
pub fn listed_runs(conn: &Connection) -> rusqlite::Result<Vec<Listed>> {
    conn.prepare(
        "SELECT run_id, MIN(at),
                MAX(entry = 'run_finished'),
                MAX(CASE WHEN entry = 'report' THEN text END)
         FROM journal WHERE entry NOT IN ('owner_said', 'owner_withdrew')
         GROUP BY run_id
         HAVING MAX(entry = 'run_started') OR run_id LIKE ?2 OR run_id LIKE ?3
         ORDER BY MAX(seq) DESC LIMIT ?1",
    )?
    .query_map(
        params![
            RUNS_KEPT,
            format!("{}%", crate::watch::RUN_PREFIX),
            format!("{}%", crate::processes::RUN_PREFIX)
        ],
        |r| {
            Ok(Listed {
                run_id: r.get(0)?,
                at: r.get(1)?,
                finished: r.get(2)?,
                report: r.get(3)?,
            })
        },
    )?
    .collect()
}

/// Where the history of readings the fold thins ends: the first row of the runs any page or
/// answer asks about by their id, the listed runs (`listed_runs`) and the latest finished run,
/// which `immunity status` reports on. Every row from there on is kept. Rows are written with ids
/// that grow, and runs never overlap, so a row with a smaller id was written before every one
/// of those runs. A reader that keeps one row per reading, the event level and the samples,
/// takes its row out and writes it again: a reading of one row, which no fold touches. `None`
/// while no such run wrote a reading.
fn kept_from(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    let finished: Option<String> = conn
        .query_row(
            "SELECT run_id FROM journal WHERE entry = 'run_finished' ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let mut first = conn.prepare("SELECT MIN(id) FROM coverage WHERE run_id = ?1")?;
    let mut from = None;
    for run in listed_runs(conn)?
        .into_iter()
        .map(|l| l.run_id)
        .chain(finished)
    {
        let id: Option<i64> = first.query_row([run], |r| r.get(0))?;
        from = from.into_iter().chain(id).min();
    }
    Ok(from)
}

/// The readings older than `kept_from` that lie between the first and the last of a run of
/// unchanged readings of one reader, scope and kind: the same completeness, reason and cause,
/// one after another, with times that do not go back. A reading that differs in any of them,
/// a failure or a loss of sight among them, ends the run, and so does one dated before the
/// reading before it, as a server's reading dated by its sweep or one made after the clock
/// went back: the next starts a run of its own. What is left of a run is its first reading,
/// which says since when, and its last, which says until when, and so every earliest and
/// latest time of a reading is kept. What a reading names as having no reader is not part of
/// what it said here: only the latest reading's is ever asked for.
const FOLDED: &str = "
INSERT INTO temp.folded (id)
SELECT id FROM (
    SELECT id, completeness, reason, cause, observed_at AS t,
           LAG(completeness) OVER w AS c0, LAG(reason) OVER w AS r0, LAG(cause) OVER w AS k0,
           LAG(observed_at) OVER w AS t0,
           LEAD(completeness) OVER w AS c1, LEAD(reason) OVER w AS r1, LEAD(cause) OVER w AS k1,
           LEAD(observed_at) OVER w AS t1
    FROM coverage WHERE id < ?1
    WINDOW w AS (PARTITION BY reader, scope, kind ORDER BY id)
)
WHERE c0 IS completeness AND r0 IS reason AND k0 IS cause AND t0 <= t
  AND c1 IS completeness AND r1 IS reason AND k1 IS cause AND t <= t1
";

/// How many readings `fold` took out, of how many there were.
#[derive(Debug, Default, PartialEq)]
pub struct Folded {
    pub removed: usize,
    pub rows: i64,
}

/// Whether `free` pages of the file's `pages` are a quarter of it or more: then the space goes
/// back to the file, whichever run freed it. Fewer free pages are left for the rows written
/// next, as SQLite keeps them.
fn worth_giving_back(free: i64, pages: i64) -> bool {
    free > 0 && free * 4 >= pages
}

/// The free pages of the store's file and all its pages, as SQLite counts them.
fn free_pages(conn: &Connection) -> rusqlite::Result<(i64, i64)> {
    let free = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let pages = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    Ok((free, pages))
}

/// How many readings one transaction of `fold` takes out. Each commit lets the automatic
/// checkpoint copy into the file what the fold wrote so far, so the `-wal` grows by one such
/// transaction and not by the whole fold.
const FOLD_AT_ONCE: i64 = 10_000;

/// Folds the history of readings older than the runs kept whole (`FOLDED`), outside any
/// transaction of the caller's, in transactions of `FOLD_AT_ONCE` readings, so that a reading
/// unchanged for a year is two rows and not one per run. A fold cut short leaves only readings
/// that lay between two of the same kept, and the next one goes on. Nothing a finding or an
/// answer rests on is a coverage row, and the latest reading of each reader, scope and kind is
/// never taken out.
pub fn fold(conn: &Connection) -> rusqlite::Result<Folded> {
    let rows: i64 = conn.query_row("SELECT COUNT(*) FROM coverage", [], |r| r.get(0))?;
    let Some(kept_from) = kept_from(conn)? else {
        return Ok(Folded { removed: 0, rows });
    };
    conn.execute_batch(
        "DROP TABLE IF EXISTS temp.folded;
         CREATE TEMP TABLE folded (id INTEGER PRIMARY KEY);",
    )?;
    conn.execute(FOLDED, [kept_from])?;
    let mut removed = 0;
    loop {
        let tx = conn.unchecked_transaction()?;
        let next = "SELECT id FROM temp.folded ORDER BY id LIMIT ?1";
        tx.execute(
            &format!("DELETE FROM coverage_lack WHERE coverage IN ({next})"),
            [FOLD_AT_ONCE],
        )?;
        removed += tx.execute(
            &format!("DELETE FROM coverage WHERE id IN ({next})"),
            [FOLD_AT_ONCE],
        )?;
        let done = tx.execute(
            &format!("DELETE FROM temp.folded WHERE id IN ({next})"),
            [FOLD_AT_ONCE],
        )?;
        tx.commit()?;
        if done == 0 {
            break;
        }
    }
    conn.execute_batch("DROP TABLE temp.folded")?;
    Ok(Folded { removed, rows })
}

/// Gives the file back the space of what was taken out of it, outside any transaction. SQLite
/// keeps freed pages for the rows written next, so the file does not grow again by them; this
/// is for when much was freed (`worth_giving_back`).
pub fn give_back(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("VACUUM")
}

/// What follows a full run's commit, still under the run lock: the fold, and where a quarter of
/// the file or more is free pages, the space given back. It is housekeeping and never changes
/// what the run did, so it returns nothing: a fold or a vacuum that fails is left as it is. The
/// next run folds what is left, and gives back the space still free, whichever run freed it.
///
/// What a vacuum wrote is in the `-wal` until a checkpoint copies it into the file, and only
/// then is the file cut to its new size. So a passive checkpoint ends it, which never waits: a
/// reader that holds an older state keeps it from going all the way, and the next run's goes on.
pub fn tidy(conn: &Connection) {
    let _ = fold(conn);
    if free_pages(conn).is_ok_and(|(free, pages)| worth_giving_back(free, pages)) {
        let _ = give_back(conn);
    }
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)");
}

// --- End of folding. ---

/// What the report line says about the store after a run.
pub struct Totals {
    /// Machines, each counted once however many names it has.
    pub machines: i64,
    pub checkouts: i64,
    pub components: i64,
    pub partial: i64,
    pub none: i64,
    /// Machines this run tried to read and could read nothing on.
    pub machines_unread: i64,
    /// Readings made by earlier runs whose scope this run did not read at all:
    /// nothing is known about what changed in them. A scope that is gone is not counted.
    pub not_repeated: i64,
}

/// How many projects the store holds.
pub fn checkouts(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT COUNT(DISTINCT subject) FROM assertion
         WHERE layer = 'live' AND predicate = 'located_on' AND subject LIKE 'checkout:%'",
        [],
        |row| row.get(0),
    )
}

pub fn totals(tx: &Connection, run_id: &str) -> rusqlite::Result<Totals> {
    let all = |sql: &str| tx.query_row(sql, [], |row| row.get::<_, i64>(0));
    let one = |sql: &str| tx.query_row(sql, [run_id], |row| row.get::<_, i64>(0));
    Ok(Totals {
        machines: machine_groups(tx)?.len() as i64,
        checkouts: checkouts(tx)?,
        components: all("SELECT COUNT(DISTINCT subject) FROM assertion
             WHERE layer = 'live' AND predicate = 'part_of'")?,
        // A partial reading that never made an assertion has nothing that could be removed.
        partial: one("SELECT COUNT(*) FROM coverage c
             WHERE run_id = ?1 AND completeness = 'partial'
               AND EXISTS (SELECT 1 FROM assertion a WHERE a.layer IN ('live', 'retracted')
                             AND a.reader = c.reader
                             AND a.scope = c.scope AND a.kind = c.kind)")?,
        // Folders macOS asks permission for were not looked into, which is not a reading
        // that read nothing: they are told apart, under what is not covered. The event level
        // keeps no facts, so a reading of it that read nothing hides no change of one.
        none: tx.query_row(
            "SELECT COUNT(*) FROM coverage WHERE run_id = ?1 AND completeness = 'none'
               AND kind NOT IN (?2, ?3, ?4)",
            params![
                run_id,
                crate::guarded::KIND,
                crate::events::KIND,
                crate::events::KIND_FILES
            ],
            |row| row.get::<_, i64>(0),
        )?,
        machines_unread: one("SELECT COUNT(*) FROM (SELECT scope FROM coverage
             WHERE run_id = ?1 AND scope IN (SELECT id FROM entity WHERE type = 'machine')
             GROUP BY scope HAVING MAX(completeness != 'none') = 0)")?,
        not_repeated: one(&format!(
            "{LATEST}
             SELECT COUNT(*) FROM reading
             WHERE scope NOT IN (SELECT scope FROM coverage WHERE run_id = ?1)
               AND NOT {}",
            gone_entity("reading.scope")
        ))?,
    })
}

/// The ids of machines the store knows now: something live names them, or a reading
/// covered them. An entity whose every trace was retracted is no longer known.
fn machines_known(conn: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    let column = |sql: &str| -> rusqlite::Result<BTreeSet<String>> {
        conn.prepare(sql)?.query_map([], |r| r.get(0))?.collect()
    };
    let entities = column("SELECT id FROM entity WHERE type = 'machine'")?;
    let mut named = column(&format!("{LATEST} SELECT DISTINCT scope FROM reading"))?;
    named.extend(column(
        // Every id from `machine:` up to, not including, the same with `;`, the character after
        // `:`: a range of `assertion_subject`, where `LIKE` reads every live fact. It gives what
        // `LIKE` would: an entity of the type `machine` has an id that begins with exactly that.
        "SELECT DISTINCT subject FROM assertion
         WHERE +layer = 'live' AND subject >= 'machine:' AND subject < 'machine;'",
    )?);
    named.extend(column(
        "SELECT DISTINCT object FROM assertion WHERE layer = 'live' AND object LIKE 'machine:%'",
    )?);
    Ok(entities.intersection(&named).cloned().collect())
}

/// The machines the store knows, as groups of entities the resolver found to be one
/// machine. Each group and the list are sorted.
pub fn machine_groups(conn: &Connection) -> rusqlite::Result<Vec<Vec<String>>> {
    let links: Vec<(String, String)> = conn
        .prepare(
            "SELECT subject, object FROM assertion WHERE layer = 'live' AND predicate = 'same_as'",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(resolver::groups(machines_known(conn)?, &links))
}

/// Machine entities known only as another user's device: the reader that says so is the
/// only one that names them, besides the resolver, and nothing was ever read on them.
pub fn other_users_devices(conn: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare(
        "SELECT DISTINCT a.subject FROM assertion a
         WHERE a.layer = 'live' AND a.predicate = 'relation_to_owner' AND a.object = ?1
           AND NOT EXISTS (SELECT 1 FROM assertion o
                           WHERE o.layer = 'live' AND o.subject = a.subject
                             AND o.reader NOT IN (a.reader, ?2))
           AND NOT EXISTS (SELECT 1 FROM coverage c WHERE c.scope = a.subject)",
    )?
    .query_map(params![crate::tailnet::OTHER_USER, resolver::READER], |r| {
        r.get(0)
    })?
    .collect()
}

/// Whether a machine, as a group of entities, is another user's device and nothing more.
pub fn only_someone_elses(group: &[String], devices: &BTreeSet<String>) -> bool {
    group.iter().all(|m| devices.contains(m))
}

/// Live `known_as` assertions, which the resolver works from.
pub fn live_known_as(conn: &Connection) -> rusqlite::Result<Vec<resolver::Known>> {
    conn.prepare(
        "SELECT subject, object, basis, reader FROM assertion
         WHERE layer = 'live' AND predicate = 'known_as' ORDER BY subject, object",
    )?
    .query_map([], |r| {
        Ok(resolver::Known {
            entity: r.get(0)?,
            value: r.get(1)?,
            basis: r.get(2)?,
            reader: r.get(3)?,
        })
    })?
    .collect()
}

/// The subjects one reader makes live assertions about.
pub fn live_subjects(conn: &Connection, reader: &str) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare("SELECT DISTINCT subject FROM assertion WHERE layer = 'live' AND reader = ?1")?
        .query_map([reader], |r| r.get(0))?
        .collect()
}

/// Scopes where the latest reading of some kind by this reader read something.
pub fn scopes_read(conn: &Connection, reader: &str) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare(&format!(
        "{LATEST}
         SELECT DISTINCT scope FROM latest WHERE reader = ?1 AND completeness != 'none'"
    ))?
    .query_map([reader], |r| r.get(0))?
    .collect()
}

/// Whether a reading of this kind by this reader in an earlier run than `run_id` read
/// something in this scope.
pub fn read_before(
    conn: &Connection,
    reader: &str,
    scope: &str,
    kind: &str,
    run_id: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3
                          AND completeness != 'none' AND run_id != ?4)",
        params![reader, scope, kind, run_id],
        |r| r.get(0),
    )
}

/// What the journal says of a difference found where nobody could have known what was there
/// before: during the store's first check. It is recorded, and it is not a change.
pub const FIRST_READING: &str = "first reading of its place";
/// What the journal says of a difference found in a place read for the first time after the
/// store's first check: it is recorded, it is not a change, and it is told once.
pub const READ_FIRST: &str = "read for the first time";

/// Whether a reading of this kind by this reader in an earlier run than `run_id` read this
/// scope in full.
pub fn read_full_before(
    conn: &Connection,
    reader: &str,
    scope: &str,
    kind: &str,
    run_id: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3
                          AND completeness = 'full' AND run_id != ?4)",
        params![reader, scope, kind, run_id],
        |r| r.get(0),
    )
}

/// Whether this reader ever made a reading.
pub fn read_any(conn: &Connection, reader: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1)",
        [reader],
        |r| r.get(0),
    )
}

/// How far ahead of this Mac's clock a time may be and still be taken as now: clocks of two
/// sources differ by seconds, not by minutes.
pub const AHEAD_ALLOWED: i64 = 5 * 60;
/// Why a reading whose time is ahead of the clock has no age.
pub const AHEAD: &str = "its time is ahead of this Mac's clock, so how old it is is not known";

/// The age at `now` of what was read at `at`, both UTC seconds. A time ahead of the clock by
/// more than `AHEAD_ALLOWED` gives none: the clock was set back, or the time is wrong, and
/// what has no age is never taken as fresh. Every judgment of freshness goes through this.
pub fn age(at: i64, now: i64) -> Option<i64> {
    (at <= now + AHEAD_ALLOWED).then(|| (now - at).max(0))
}

/// When one reader last read a scope in full.
pub fn last_read(conn: &Connection, reader: &str, scope: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT MAX(observed_at) FROM coverage
         WHERE reader = ?1 AND scope = ?2 AND completeness = 'full'",
        params![reader, scope],
        |r| r.get(0),
    )
}

/// The last saved raw copy of this input, relative to the store's folder.
pub fn last_raw(conn: &Connection, reader: &str, input: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT path FROM raw_input WHERE reader = ?1 AND input = ?2",
        params![reader, input],
        |row| row.get(0),
    )
    .map(Some)
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        e => Err(e),
    })
}

pub fn set_raw(
    tx: &Transaction,
    reader: &str,
    input: &str,
    path: &str,
    run_id: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO raw_input (reader, input, path, run_id) VALUES (?1, ?2, ?3, ?4)",
        params![reader, input, path, run_id],
    )?;
    Ok(())
}

/// This Mac's id in the store, kept in `meta` from the store's first run, so that a new
/// name of the Mac does not make it another machine. macOS changes its local host name by
/// itself when another device on the network has it, and the owner can rename the Mac. A
/// store made before the id was kept takes the machine its latest readings are of. `name`
/// is the Mac's name now: it is kept beside the id, and it is what is shown.
pub fn this_mac(tx: &Connection, name: &str) -> rusqlite::Result<String> {
    let id = match held_mac(tx)? {
        Some((id, _)) => id,
        None => crate::covered::this_machine(tx)?.unwrap_or_else(|| format!("machine:{name}")),
    };
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ('machine', ?1), ('machine_name', ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![id, name],
    )?;
    Ok(id)
}

/// This Mac's id and its name at the latest run, as `this_mac` kept them.
pub fn held_mac(conn: &Connection) -> rusqlite::Result<Option<(String, String)>> {
    let get = |key: &str| {
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
            r.get::<_, String>(0)
        })
        .optional()
    };
    Ok(match (get("machine")?, get("machine_name")?) {
        (Some(id), Some(name)) => Some((id, name)),
        _ => None,
    })
}

pub fn journal_note(
    conn: &Connection,
    at: i64,
    run_id: &str,
    entry: &str,
    text: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO journal (at, run_id, entry, text) VALUES (?1, ?2, ?3, ?4)",
        params![at, run_id, entry, text],
    )?;
    Ok(())
}

/// One entry of the owner's word: `owner_said` with what was said and the reason, or
/// `owner_withdrew` with what had been said and how it was withdrawn; `kind` is how it was
/// given: app, agent or command.
#[allow(clippy::too_many_arguments)]
pub fn journal_owner(
    tx: &Transaction,
    at: i64,
    run_id: &str,
    entry: &str,
    entity: &str,
    said: &str,
    text: &str,
    via: &str,
) -> rusqlite::Result<()> {
    let (old, new) = if entry == "owner_said" {
        (None, Some(said))
    } else {
        (Some(said), None)
    };
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, kind, subject, old_value, new_value, text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![at, run_id, entry, via, entity, old, new, text],
    )?;
    Ok(())
}

/// One difference a reading found, with `text` when it is not a change: `FIRST_READING` or
/// `READ_FIRST`.
pub fn journal_event(
    tx: &Transaction,
    r: &Reading,
    e: &Event,
    text: Option<&str>,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, predicate,
                              old_value, new_value, text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            r.at,
            r.run_id,
            e.kind,
            r.reader,
            r.scope,
            r.kind,
            e.subject,
            e.predicate,
            e.old,
            e.new,
            text
        ],
    )?;
    Ok(())
}

/// One entry about the threat list: `threat_added` with the threat's name, `threat_gone`
/// with the name it had, or `threats_first_read` with how many entries the list held.
pub fn journal_threat(
    tx: &Transaction,
    at: i64,
    run_id: &str,
    entry: &str,
    source: &str,
    subject: Option<&str>,
    value: &str,
) -> rusqlite::Result<()> {
    let (old, new) = if entry == "threat_gone" {
        (Some(value), None)
    } else {
        (None, Some(value))
    };
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, reader, subject, old_value, new_value)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![at, run_id, entry, source, subject, old, new],
    )?;
    Ok(())
}

/// For tests: the work SQLite does, counted in steps of its virtual machine, so that a promise
/// that some work does not grow is pinned without the clock. The clock on a loaded machine runs
/// a reading several times longer for nothing; the steps of a statement are the same on every
/// machine for the same store, and a statement that looks through every row takes a step for
/// each.
///
/// Nothing in the code needs to change for it. Every connection opened on this thread while
/// `counted` runs gets SQLite's progress handler, called at every step (an interval of one),
/// through an automatic extension, which SQLite runs at every open. A connection opened on
/// another thread, or outside `counted`, is left as it was, so tests running side by side do
/// not count each other's work. The connections opened are counted the same way (`opened_by`).
#[cfg(test)]
pub mod steps {
    use rusqlite::ffi;
    use std::cell::Cell;
    use std::ffi::{c_char, c_int, c_void};

    thread_local! {
        static COUNTING: Cell<bool> = const { Cell::new(false) };
        static STEPS: Cell<u64> = const { Cell::new(0) };
        static OPENS: Cell<u64> = const { Cell::new(0) };
    }

    unsafe extern "C" fn step(_: *mut c_void) -> c_int {
        STEPS.with(|s| s.set(s.get() + 1));
        0
    }

    unsafe extern "C" fn opened(
        db: *mut ffi::sqlite3,
        _: *mut *mut c_char,
        _: *const ffi::sqlite3_api_routines,
    ) -> c_int {
        if COUNTING.with(Cell::get) {
            OPENS.with(|o| o.set(o.get() + 1));
            // SAFETY: `db` is the connection SQLite is opening, valid for this call.
            unsafe { ffi::sqlite3_progress_handler(db, 1, Some(step), std::ptr::null_mut()) };
        }
        ffi::SQLITE_OK
    }

    /// What `f` returns, and the steps SQLite took for it on the connections it opened.
    pub fn counted<T>(f: impl FnOnce() -> T) -> (T, u64) {
        static REGISTERED: std::sync::Once = std::sync::Once::new();
        REGISTERED.call_once(|| {
            // SAFETY: `opened` has the signature SQLite calls an automatic extension with.
            let rc = unsafe { ffi::sqlite3_auto_extension(Some(opened)) };
            assert_eq!(rc, ffi::SQLITE_OK);
        });
        STEPS.with(|s| s.set(0));
        COUNTING.with(|c| c.set(true));
        let out = f();
        COUNTING.with(|c| c.set(false));
        (out, STEPS.with(Cell::get))
    }

    /// What `f` returns, and how many connections it opened.
    pub fn opened_by<T>(f: impl FnOnce() -> T) -> (T, u64) {
        OPENS.with(|o| o.set(0));
        let (out, _) = counted(f);
        (out, OPENS.with(Cell::get))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod unread;
    mod wal;

    #[test]
    fn the_schema_holds_no_quoted_text_that_the_comparison_would_change() {
        // `normal` takes out `--` comments and makes blank space one. A quoted string or name
        // holding `--`, a line break or a run of blank space would be changed by it, and two
        // schemas that differ there would compare equal. Read as SQLite reads quotes.
        let sql = schema();
        let mut chars = sql.chars().peekable();
        let mut quoted: Option<(char, String)> = None;
        while let Some(c) = chars.next() {
            match &mut quoted {
                Some((q, text)) if c == *q && chars.peek() != Some(q) => {
                    assert!(
                        !text.contains("--")
                            && !text.contains("  ")
                            && !text.contains(['\n', '\t', '\r']),
                        "{text:?}"
                    );
                    quoted = None;
                }
                Some((q, text)) => {
                    if c == *q {
                        chars.next();
                    }
                    text.push(c);
                }
                None if c == '-' && chars.peek() == Some(&'-') => {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                None if c == '\'' || c == '"' => quoted = Some((c, String::new())),
                None => {}
            }
        }
        assert!(quoted.is_none());
    }

    #[test]
    fn a_store_made_from_empty_is_accepted_by_its_own_check_and_compares_equal() {
        let dir = crate::common::Scratch::new("made-equal");
        let path = dir.join("store.db");
        drop(open_or_make(&path).unwrap());
        let conn = open_read_only(&path).unwrap();
        assert_eq!(differs(expected(), &shape(&conn).unwrap()), None);
        assert!(is_id(&id(&conn).unwrap()));
        // Made once: a second open finds it and makes nothing.
        let first = std::fs::read(&path).unwrap();
        drop(open_or_make(&path).unwrap());
        assert_eq!(
            id(&open_read_only(&path).unwrap()).unwrap(),
            id(&conn).unwrap()
        );
        assert_eq!(std::fs::read(&path).unwrap().len(), first.len());
        // Nothing of the making is left beside it, and its `-wal` and `-shm` are there.
        let (names, _) = as_left(&path);
        let names: Vec<_> = names.iter().map(|n| n.to_str().unwrap()).collect();
        assert_eq!(names, ["store.db", "store.db-shm", "store.db-wal"]);
    }

    #[test]
    fn a_store_whose_schema_differs_only_in_comments_and_layout_is_accepted() {
        // A comment or the layout of the schema's source is not a change of format: a store
        // made by a build whose source said the same in other lines is still a store of it.
        let dir = crate::common::Scratch::new("layout");
        let path = dir.join("store.db");
        drop(open_or_make(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "PRAGMA writable_schema = ON;
                 UPDATE sqlite_master SET sql = replace(replace(sql, '(', '( -- a note
                    '), ' ', '   ') WHERE name = 'meta';",
            )
            .unwrap();
        let conn = open(&path).unwrap();
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'meta'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            sql.contains("note\n") && sql.contains("TABLE   meta"),
            "{sql}"
        );
    }

    #[test]
    fn a_store_made_while_a_file_came_to_the_path_leaves_that_file_as_it_is() {
        // Another command can put its store at the path between the look and the link: the
        // link then finds it, and the store made here is dropped, not put in its place.
        let dir = crate::common::Scratch::new("raced");
        let path = dir.join("store.db");
        std::fs::write(&path, b"another command's store").unwrap();
        make(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"another command's store");
        let beside: Vec<_> = std::fs::read_dir(&*dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(beside, [std::ffi::OsString::from("store.db")]);
    }

    #[test]
    fn a_store_that_holds_a_table_sqlite_made_beyond_the_format_is_refused() {
        // SQLite's own objects are compared too: `ANALYZE` adds `sqlite_stat1`, which changes
        // how every query of the store is planned.
        let dir = crate::common::Scratch::new("analyzed");
        let path = dir.join("store.db");
        drop(open_or_make(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .execute_batch("ANALYZE")
            .unwrap();
        let said = open(&path).err().unwrap().to_string();
        assert!(said.contains("it holds a table sqlite_stat1"), "{said}");
    }

    /// A store made from empty and then changed by `sql`, as something other than Immunity Core
    /// would change it, with its `-wal` and `-shm` beside it as a writer leaves them.
    fn changed(sql: &str) -> (crate::common::Scratch, std::path::PathBuf) {
        let dir = crate::common::Scratch::new("changed");
        let path = dir.join("store.db");
        drop(open_or_make(&path).unwrap());
        writer(&path)
            .unwrap()
            .execute_batch(&format!("PRAGMA foreign_keys = OFF; {sql}"))
            .unwrap();
        (dir, path)
    }

    /// The names in the folder of `path`, and the bytes of the store's file and of its `-wal`.
    fn as_left(path: &Path) -> (BTreeSet<std::ffi::OsString>, [Option<Vec<u8>>; 2]) {
        let names = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        let [wal, _] = beside(path);
        (names, [path, &wal].map(|f| std::fs::read(f).ok()))
    }

    /// Every way a command opens a store, to write, to read, in one read access and to make one
    /// where no file is, refuses the file at `path` in the same words, saying each of `said`, and
    /// leaves it and its `-wal` byte for byte as they were, with nothing made or taken away
    /// beside them, under the outcome `code`. The words.
    fn refused(path: &Path, code: Code, said: &[&str]) -> String {
        let before = as_left(path);
        type Opens = fn(&Path) -> Result<(), Outcome>;
        let ways: [(&str, Opens); 4] = [
            ("open", |p| open(p).map(drop)),
            ("open_read_only", |p| open_read_only(p).map(drop)),
            ("read", |p| read(p, |_| Ok(()))),
            ("open_or_make", |p| open_or_make(p).map(drop)),
        ];
        let words: Vec<String> = ways
            .iter()
            .map(|(way, opened)| {
                let refusal = opened(path).err().unwrap_or_else(|| panic!("{way}"));
                assert_eq!(refusal.code, code, "{way}: {refusal}");
                let words = refusal.to_string();
                for s in said {
                    assert!(words.contains(s), "{way}: {words}");
                }
                assert!(
                    as_left(path) == before,
                    "{way}: the store or its files changed"
                );
                words
            })
            .collect();
        assert!(words.iter().all(|w| *w == words[0]), "{words:#?}");
        words[0].clone()
    }

    #[test]
    fn a_store_that_lacks_a_table_a_column_or_its_id_or_holds_one_too_many_fails_the_check() {
        // A store of this format holds exactly the schema this build makes, and its id; none is
        // made again, empty, in a store that lost it.
        for damage in [
            "DROP TABLE finding",
            "DROP TABLE threat",
            "ALTER TABLE threat DROP COLUMN vendor",
            "ALTER TABLE finding ADD COLUMN extra TEXT",
            "CREATE TABLE extra (a TEXT)",
            "DROP INDEX journal_run",
            "DROP INDEX journal_run; CREATE INDEX journal_run ON journal (run_id)",
            // The same columns, without the reference a row of it must keep.
            "ALTER TABLE coverage_lack RENAME TO old;
             CREATE TABLE coverage_lack (coverage INTEGER NOT NULL, what TEXT NOT NULL, name TEXT);
             DROP TABLE old;
             CREATE INDEX coverage_lack_of ON coverage_lack (coverage);",
            // A trigger of the format's name that no longer keeps the journal from shrinking.
            "DROP TRIGGER journal_no_delete;
             CREATE TRIGGER journal_no_delete BEFORE DELETE ON journal BEGIN SELECT 1; END;",
            "DELETE FROM meta WHERE key = 'store_id'",
        ] {
            let (_dir, path) = changed(damage);
            refused(&path, Code::Damaged, &["is damaged", START_OVER]);
        }
    }

    #[test]
    fn a_store_without_any_one_table_of_its_schema_fails_the_check() {
        // Driven by the schema itself, so a table added later is covered. Without `meta` the
        // store names no format; without any other table it is damaged.
        let tables: Vec<&str> = expected()
            .keys()
            .filter_map(|object| object.strip_prefix("table "))
            .filter(|name| !name.starts_with("sqlite_"))
            .collect();
        assert!(tables.len() > 40, "{tables:?}");
        for table in tables {
            let (_dir, path) = changed(&format!("DROP TABLE {table}"));
            let (code, said) = match table {
                "meta" => (Code::UnknownFormat, "does not name exactly one format"),
                _ => (Code::Damaged, "is damaged"),
            };
            refused(&path, code, &[said, START_OVER]);
        }
    }

    #[test]
    fn a_store_whose_table_differs_only_in_a_check_a_unique_without_rowid_a_collation_or_autoincrement_fails_the_check()
     {
        // The comparison is of each object's text as SQLite keeps it, so what lives only there is
        // compared too. Each table is made again with the one difference and its rows.
        for (table, made) in [
            // Without the CHECK that a threat gone has a run that saw it go.
            (
                "threat",
                "CREATE TABLE threat (source TEXT NOT NULL, id TEXT NOT NULL, vendor TEXT NOT NULL,
                 product TEXT NOT NULL, name TEXT NOT NULL, date_added TEXT NOT NULL,
                 first_run TEXT NOT NULL, first_seen_at INTEGER NOT NULL, gone_at INTEGER,
                 gone_run TEXT, PRIMARY KEY (source, id))",
            ),
            // Without the UNIQUE of a basis' strength.
            (
                "basis_kind",
                "CREATE TABLE basis_kind (name TEXT PRIMARY KEY, strength INTEGER NOT NULL)",
            ),
            (
                "raw_input",
                "CREATE TABLE raw_input (reader TEXT NOT NULL, input TEXT NOT NULL,
                 path TEXT NOT NULL, run_id TEXT NOT NULL, PRIMARY KEY (reader, input)) WITHOUT ROWID",
            ),
            (
                "coverage_kind",
                "CREATE TABLE coverage_kind (name TEXT COLLATE NOCASE PRIMARY KEY)",
            ),
            (
                "feed_reading",
                "CREATE TABLE feed_reading (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 source TEXT NOT NULL, run_id TEXT NOT NULL, at INTEGER NOT NULL,
                 outcome TEXT NOT NULL CHECK (outcome IN ('read', 'unchanged', 'failed')),
                 reason TEXT, etag TEXT, sha256 TEXT, raw_path TEXT, entries INTEGER,
                 CHECK ((outcome = 'failed') = (reason IS NOT NULL)))",
            ),
        ] {
            let (_dir, path) = changed(&format!(
                "PRAGMA legacy_alter_table = ON;
                 ALTER TABLE {table} RENAME TO old_{table};
                 {made};
                 INSERT INTO {table} SELECT * FROM old_{table};
                 DROP TABLE old_{table};"
            ));
            refused(&path, Code::Damaged, &["is damaged", START_OVER]);
        }
    }

    #[test]
    fn a_store_whose_id_or_format_has_another_form_fails_the_check() {
        let no_id = (Code::Damaged, "it has no id of the form");
        let unknown = (
            Code::UnknownFormat,
            "names a format this version does not know",
        );
        for (damage, (code, said)) in [
            ("UPDATE meta SET value = ' ' WHERE key = 'store_id'", no_id),
            ("UPDATE meta SET value = 'x' WHERE key = 'store_id'", no_id),
            (
                "UPDATE meta SET value = upper(value) || '' WHERE key = 'store_id'",
                no_id,
            ),
            (
                "UPDATE meta SET value = substr(value, 2) WHERE key = 'store_id'",
                no_id,
            ),
            // Two rows of the format, in a `meta` made again without its key: the one that names
            // a newer format is not taken for the store's.
            (
                "ALTER TABLE meta RENAME TO old_meta;
                 CREATE TABLE meta (key TEXT, value TEXT NOT NULL);
                 INSERT INTO meta SELECT * FROM old_meta;
                 DROP TABLE old_meta;
                 INSERT INTO meta VALUES ('format_version', '11');",
                (Code::UnknownFormat, "does not name exactly one format"),
            ),
            (
                "UPDATE meta SET value = '07' WHERE key = 'format_version'",
                unknown,
            ),
            (
                "UPDATE meta SET value = ' 7' WHERE key = 'format_version'",
                unknown,
            ),
        ] {
            let (_dir, path) = changed(damage);
            refused(&path, code, &[said, START_OVER]);
        }
    }

    #[test]
    fn a_store_of_another_format_fails_the_check_and_an_older_or_a_newer_one_is_told_as_another_build_s()
     {
        // An older or a newer format is the outcome every command words once for a person
        // (`text::error`); a format that is no number is shown as the check words it.
        for (version, code, said, what_to_do) in [
            (
                "9",
                Code::OlderFormat,
                "is from an older format (9)",
                START_OVER,
            ),
            (
                "5",
                Code::OlderFormat,
                "is from an older format (5)",
                START_OVER,
            ),
            (
                "11",
                Code::NewerFormat,
                "is from a newer format (11)",
                "Use the version of Immunity Core that made it",
            ),
            (
                "six",
                Code::UnknownFormat,
                "names a format this version does not know",
                START_OVER,
            ),
        ] {
            let (_dir, path) = changed(&format!(
                "UPDATE meta SET value = '{version}' WHERE key = 'format_version'"
            ));
            refused(&path, code, &[said, what_to_do]);
        }
    }

    #[test]
    fn a_file_that_exists_is_never_given_a_schema_and_fails_the_check() {
        // A store is made only where no file was. A store whose objects were taken out of
        // `sqlite_master` keeps its pages; a 0-byte file and a file that is not SQLite hold
        // nothing of a store. Each is refused as it is, and none is made a store under a new id.
        let (_dir, path) = changed("PRAGMA writable_schema = ON; DELETE FROM sqlite_master;");
        refused(
            &path,
            Code::NotAStore,
            &[
                "is an SQLite file that holds no tables, not a store",
                NOT_A_STORE,
            ],
        );
        // The store's files go with it.
        for file in beside(&path) {
            std::fs::remove_file(file).unwrap();
        }
        std::fs::write(&path, b"").unwrap();
        refused(
            &path,
            Code::NotAStore,
            &["is an empty file, not a store", NOT_A_STORE],
        );
        std::fs::write(&path, b"invented notes, not a database\n").unwrap();
        refused(
            &path,
            Code::NotAStore,
            &["is not a store: it is not an SQLite file", NOT_A_STORE],
        );
    }

    #[test]
    fn a_time_more_than_a_few_minutes_ahead_of_the_clock_has_no_age_and_a_little_ahead_is_now() {
        // Two clocks differ by seconds; a reading dated later than that is not fresh forever.
        let now = 2_000_000_000;
        assert_eq!(age(now - 90, now), Some(90));
        assert_eq!(age(now + 60, now), Some(0));
        assert_eq!(age(now + AHEAD_ALLOWED, now), Some(0));
        assert_eq!(age(now + AHEAD_ALLOWED + 1, now), None);
    }

    // --- Folding the history of readings, on invented stores. ---

    const MAC: &str = "machine:mac";
    const PROFILES: &str = "shell profiles of zsh and bash";
    const BREW: &str = "brew packages";

    /// What a reading said: its completeness, and its reason and cause when not full.
    #[derive(Clone, Copy)]
    struct Said {
        completeness: &'static str,
        reason: Option<&'static str>,
        cause: Option<Cause>,
        lack: Option<&'static str>,
    }

    const FULL: Said = Said {
        completeness: "full",
        reason: None,
        cause: None,
        lack: None,
    };

    fn failed(reason: &'static str) -> Said {
        Said {
            completeness: "none",
            reason: Some(reason),
            cause: Some(Cause::Failed),
            lack: None,
        }
    }

    fn partial(reason: &'static str) -> Said {
        Said {
            completeness: "partial",
            reason: Some(reason),
            cause: Some(Cause::NotGiven),
            lack: None,
        }
    }

    /// An invented store and the runs made on it, one a minute.
    struct Kept {
        dir: std::path::PathBuf,
        conn: Connection,
        runs: i64,
        /// Seconds the clock is off by for the next run's readings, as a clock set back is.
        skew: i64,
    }

    impl Kept {
        fn new(tag: &str) -> Kept {
            let dir = std::env::temp_dir().join(format!(
                "immunity-fold-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let conn = open_or_make(&dir.join("store.db")).unwrap();
            Kept {
                dir,
                conn,
                runs: 0,
                skew: 0,
            }
        }

        /// One run that writes these readings, `(reader, scope, kind, said)`: a full run with
        /// its start and end in the journal, or a watcher's reading with neither.
        fn run(&mut self, full: bool, readings: &[(&str, &str, &str, Said)]) -> String {
            self.runs += 1;
            let at = 1_900_000_000 + self.runs * 60;
            let run_id = if full {
                format!("{at}-000000000")
            } else {
                format!("watch-{at}-000000000")
            };
            if full {
                journal_note(&self.conn, at, &run_id, "run_started", "").unwrap();
            }
            let tx = self.conn.transaction().unwrap();
            for (reader, scope, kind, said) in readings {
                put_entity(&tx, scope).unwrap();
                let r = Reading {
                    reader,
                    scope,
                    kind,
                    run_id: &run_id,
                    at: at + self.skew,
                    observed_at: at + self.skew,
                };
                let gap = Gap {
                    cause: said.cause,
                    lacks: said
                        .lack
                        .map(|l| vec![Lack::new(l, None)])
                        .unwrap_or_default(),
                    ..Gap::default()
                };
                put_coverage(&tx, &r, said.completeness, said.reason, &gap).unwrap();
            }
            tx.commit().unwrap();
            if full {
                journal_note(&self.conn, at, &run_id, "run_finished", "").unwrap();
            }
            run_id
        }

        fn fold(&self) -> Folded {
            fold(&self.conn).unwrap()
        }

        fn rows(&self) -> i64 {
            self.conn
                .query_row("SELECT COUNT(*) FROM coverage", [], |r| r.get(0))
                .unwrap()
        }

        /// The readings of one reader, scope and kind, oldest first: completeness, reason, run
        /// and time.
        fn history(&self, scope: &str, kind: &str) -> Vec<(String, Option<String>, String, i64)> {
            self.conn
                .prepare(
                    "SELECT completeness, reason, run_id, observed_at FROM coverage
                     WHERE scope = ?1 AND kind = ?2 ORDER BY id",
                )
                .unwrap()
                .query_map(params![scope, kind], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect()
        }
    }

    impl Drop for Kept {
        fn drop(&mut self) {
            crate::common::remove(&self.dir);
        }
    }

    /// A deterministic sequence of readings for a history, so that a failing case can be read
    /// again: each step a number below `n`.
    fn steps(seed: u64, count: usize, n: u64) -> Vec<u64> {
        let mut x = seed;
        (0..count)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (x >> 33) % n
            })
            .collect()
    }

    #[test]
    fn unchanged_readings_beyond_the_runs_kept_whole_add_no_rows() {
        // The bound itself: a Mac read every hour for a year holds no more readings than one
        // read for a day, once nothing changes.
        let mut k = Kept::new("bound");
        let readings = [
            ("brew", MAC, BREW, FULL),
            ("watched-places", MAC, PROFILES, FULL),
            ("tailnet", MAC, "tailnet peers", failed("switched off")),
        ];
        let mut after = Vec::new();
        for i in 0..(RUNS_KEPT + 40) {
            k.run(true, &readings);
            // Watchers' readings between the runs, of the watched places alone.
            if i % 3 == 0 {
                k.run(false, &readings[1..2]);
            }
            k.fold();
            after.push(k.rows());
        }
        // The runs kept whole hold a watcher's reading every third run, so the count repeats
        // every three runs and never grows.
        let late = &after[after.len() - 30..];
        assert!(late.windows(4).all(|w| w[0] == w[3]), "{after:?}");
        // Each reading of the runs kept whole, and the first and the last of what is older.
        let most = *late.iter().max().unwrap();
        assert!(most <= 3 * (RUNS_KEPT + 2) + (RUNS_KEPT / 3 + 3), "{most}");
    }

    #[test]
    fn a_failure_ends_a_run_of_unchanged_readings_and_a_reading_after_it_starts_a_new_one() {
        let mut k = Kept::new("failure");
        let mut said = Vec::new();
        said.extend([FULL; 5]);
        said.extend([failed("permission denied"); 4]);
        said.push(failed("no such file"));
        said.extend([FULL; 5]);
        for s in &said {
            k.run(true, &[("watched-places", MAC, PROFILES, *s)]);
        }
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("brew", MAC, BREW, FULL)]);
        }
        assert!(k.fold().removed > 0);
        let kept: Vec<(String, Option<String>)> = k
            .history(MAC, PROFILES)
            .into_iter()
            .map(|(c, r, _, _)| (c, r))
            .collect();
        let full = ("full".to_string(), None);
        let denied = ("none".to_string(), Some("permission denied".to_string()));
        let missing = ("none".to_string(), Some("no such file".to_string()));
        assert_eq!(
            kept,
            vec![
                full.clone(),
                full.clone(),
                denied.clone(),
                denied,
                missing,
                full.clone(),
                full
            ]
        );
    }

    #[test]
    fn a_change_of_completeness_reason_or_cause_ends_a_run_of_unchanged_readings() {
        let mut k = Kept::new("reason");
        let lacking = Said {
            lack: Some("software of a package manager this version does not read"),
            ..partial("one")
        };
        // Each run differs from the one before it in one of these alone.
        let none = Said {
            completeness: "none",
            ..partial("one")
        };
        for s in [partial("one"); 3]
            .into_iter()
            .chain([none; 3])
            .chain([failed("one"); 3])
            .chain([failed("two"); 3])
            .chain([lacking; 3])
        {
            k.run(true, &[("brew", MAC, BREW, s)]);
        }
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("watched-places", MAC, PROFILES, FULL)]);
        }
        assert_eq!(k.fold().removed, 5);
        let left: Vec<_> = k.history(MAC, BREW).into_iter().map(|h| h.3).collect();
        let at = |run: i64| 1_900_000_000 + run * 60;
        assert_eq!(
            left,
            [1, 3, 4, 6, 7, 9, 10, 12, 13, 15].map(at),
            "the first and the last of each run"
        );
        // What has no reader goes with the readings taken out, and stays with those kept, the
        // latest among them.
        let lacks: i64 = k
            .conn
            .query_row(
                "SELECT COUNT(*) FROM coverage_lack l JOIN coverage c ON c.id = l.coverage
                 WHERE c.kind = ?1",
                [BREW],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(lacks, 2);
    }

    #[test]
    fn folding_never_turns_a_failed_or_partial_reading_into_a_full_one_nor_moves_a_time() {
        // Over invented histories: what each reading said, in order and with consecutive
        // repeats taken as one, is the same before and after; so are the first and the last
        // time of each repeat.
        let said = [FULL, failed("a"), failed("b"), partial("c")];
        for seed in 1..40 {
            let mut k = Kept::new("histories");
            // Long runs of one outcome, as on a real Mac, and now and then a clock set back
            // by up to three runs.
            for step in steps(seed, 60, 12) {
                let s = said[(step / 3).min(3) as usize];
                k.skew = if step % 4 == 0 {
                    -(step as i64 * 15)
                } else {
                    0
                };
                k.run(true, &[("watched-places", MAC, PROFILES, s)]);
            }
            k.skew = 0;
            for _ in 0..RUNS_KEPT {
                k.run(true, &[("brew", MAC, BREW, FULL)]);
            }
            // A run of repeats ends where what was said changes, or where the time goes back.
            let runs = |h: Vec<(String, Option<String>, String, i64)>| {
                let mut out: Vec<(String, Option<String>, i64, i64)> = Vec::new();
                for (c, r, _, at) in h {
                    match out.last_mut() {
                        Some(last) if last.0 == c && last.1 == r && at >= last.3 => last.3 = at,
                        _ => out.push((c, r, at, at)),
                    }
                }
                out
            };
            let before = runs(k.history(MAC, PROFILES));
            k.fold();
            let after = k.history(MAC, PROFILES);
            assert!(after.len() <= 2 * before.len(), "seed {seed}");
            assert_eq!(runs(after), before, "seed {seed}");
        }
    }

    #[test]
    fn every_answer_the_store_gives_about_coverage_is_the_same_after_folding() {
        // The latest reading of each reader, scope and kind is the freshness every answer
        // uses: when it was taken, when it was last full, since when it fails, whether a
        // place was read before. A stale or uncovered answer stays so, a fresh one stays fresh.
        let mut k = Kept::new("answers");
        let server = "machine:web-1";
        let visit = crate::servers::VISIT;
        let mut first = None;
        for i in 0..(RUNS_KEPT + 30) {
            let visited = match i {
                0..10 => FULL,
                10..14 => failed("timed out"),
                14..16 => failed("refused"),
                _ => failed("timed out"),
            };
            let shell = if i < 12 { FULL } else { partial("one file") };
            let run = k.run(
                true,
                &[
                    (crate::servers::READER, server, visit, visited),
                    ("watched-places", MAC, PROFILES, shell),
                    ("resolver", MAC, "machines under several names", FULL),
                ],
            );
            first.get_or_insert(run);
        }
        let answers = |k: &Kept| {
            let c = &k.conn;
            let latest: Vec<_> = crate::view::latest_coverage(c)
                .unwrap()
                .into_iter()
                .map(|l| {
                    (
                        l.reader,
                        l.scope,
                        l.kind,
                        l.completeness,
                        l.reason,
                        l.at,
                        l.last_full,
                        l.cause,
                    )
                })
                .collect();
            let problems =
                crate::status::problems(c, &crate::view::latest_coverage(c).unwrap()).unwrap();
            let unreached: Vec<_> = problems
                .unreached
                .iter()
                .map(|u| (u.scope.clone(), u.since, u.reason.clone()))
                .collect();
            let run = "the next run";
            (
                latest,
                unreached,
                last_read(c, crate::servers::READER, server).unwrap(),
                read_before(c, "watched-places", MAC, PROFILES, run).unwrap(),
                read_full_before(c, "watched-places", MAC, PROFILES, run).unwrap(),
                read_full_before(c, crate::servers::READER, server, visit, run).unwrap(),
                scopes_read(c, crate::servers::READER).unwrap(),
                c.query_row(&format!("{LATEST} SELECT COUNT(*) FROM latest"), [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
                // The run that first read each place, which the journal's baselines go by.
                c.query_row(
                    "SELECT run_id FROM coverage WHERE reader = 'watched-places'
                       AND completeness != 'none' ORDER BY id LIMIT 1",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap(),
            )
        };
        let before = answers(&k);
        assert!(k.fold().removed > 0);
        assert_eq!(answers(&k), before);
        // Since when the server fails is the first failure after the last full visit.
        assert_eq!(before.1[0].1, 1_900_000_000 + 11 * 60);
        assert_eq!(before.8, first.unwrap());
    }

    #[test]
    fn readings_of_two_readers_of_one_place_are_folded_each_in_its_own_history() {
        // Freshness is told per reader, scope and kind: one reader's readings never end a run
        // of another's, nor stand for its first or its latest.
        let mut k = Kept::new("readers");
        for _ in 0..6 {
            k.run(
                true,
                &[("brew", MAC, BREW, FULL), ("another", MAC, BREW, FULL)],
            );
        }
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("watched-places", MAC, PROFILES, FULL)]);
        }
        assert_eq!(k.fold().removed, 8);
        let each: Vec<(String, i64, i64)> = k
            .conn
            .prepare(
                "SELECT reader, MIN(observed_at), MAX(observed_at) FROM coverage
                 WHERE kind = ?1 GROUP BY reader ORDER BY reader",
            )
            .unwrap()
            .query_map([BREW], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let at = |run: i64| 1_900_000_000 + run * 60;
        assert_eq!(
            each,
            [
                ("another".to_string(), at(1), at(6)),
                ("brew".to_string(), at(1), at(6))
            ]
        );
    }

    #[test]
    fn folding_never_lowers_a_time_an_answer_reads_when_times_go_back() {
        // A server's reading is dated by its sweep, and any reading by a clock that can go
        // back: times need not grow with the row id. A reading dated before the one before it
        // starts a run of its own, so the latest and the earliest time of each are kept.
        let mut k = Kept::new("time");
        let server = "machine:web-1";
        for t in [100, 300, 200, 210, 220] {
            k.runs += 1;
            let run_id = format!("{}-000000000", 1_900_000_000 + k.runs * 60);
            journal_note(&k.conn, t, &run_id, "run_started", "").unwrap();
            let tx = k.conn.transaction().unwrap();
            put_entity(&tx, server).unwrap();
            let r = Reading {
                reader: crate::servers::READER,
                scope: server,
                kind: "system packages",
                run_id: &run_id,
                at: t,
                observed_at: t,
            };
            put_coverage(&tx, &r, "full", None, &Gap::default()).unwrap();
            tx.commit().unwrap();
            journal_note(&k.conn, t, &run_id, "run_finished", "").unwrap();
        }
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("brew", MAC, BREW, FULL)]);
        }
        // The owner said the server was retired at 150: the reading at 300 contradicts it.
        let tx = k.conn.transaction().unwrap();
        crate::owner::say(
            &tx,
            server,
            &[server.to_string()],
            "retired",
            "moved",
            crate::findings::Via::Command,
            150,
            "owner-1",
        )
        .unwrap();
        tx.commit().unwrap();
        let answers = |k: &Kept| {
            let last_full = crate::view::latest_coverage(&k.conn)
                .unwrap()
                .into_iter()
                .find(|l| l.scope == server)
                .unwrap()
                .last_full;
            let seen = crate::owner::standing(&k.conn).unwrap()[0].contradiction();
            (
                last_read(&k.conn, crate::servers::READER, server).unwrap(),
                last_full,
                seen,
            )
        };
        let before = answers(&k);
        assert_eq!((before.0, before.1), (Some(300), Some(300)));
        assert_eq!(k.fold().removed, 1);
        assert_eq!(answers(&k), before);
        let left: Vec<i64> = k
            .history(server, "system packages")
            .into_iter()
            .map(|h| h.3)
            .collect();
        assert_eq!(left, [100, 300, 200, 220]);
    }

    #[test]
    fn a_fold_beside_a_reader_that_holds_the_store_folds_and_the_reader_keeps_what_it_read() {
        let mut k = Kept::new("busy");
        for _ in 0..(RUNS_KEPT + 5) {
            k.run(true, &[("brew", MAC, BREW, FULL)]);
        }
        let rows = k.rows();
        let reader = Connection::open(k.dir.join("store.db")).unwrap();
        let held = reader.unchecked_transaction().unwrap();
        let count = |c: &Connection| -> i64 {
            c.query_row("SELECT COUNT(*) FROM coverage", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count(&held), rows);
        tidy(&k.conn);
        assert_eq!((k.rows(), count(&held)), (rows - 3, rows));
    }

    #[test]
    fn only_a_file_a_quarter_or_more_free_is_rewritten() {
        // Rewriting the file takes as long as the store is large and shuts readers out
        // meanwhile: the few pages a run frees in the ordinary way stay free for the next run.
        assert!(!worth_giving_back(0, 0));
        assert!(!worth_giving_back(0, 100));
        assert!(!worth_giving_back(24, 100));
        assert!(worth_giving_back(25, 100));
        assert!(worth_giving_back(57_000, 57_861));
    }

    #[test]
    fn a_run_that_leaves_little_free_keeps_its_free_pages_for_the_rows_written_next() {
        let mut k = Kept::new("free-little");
        let scopes: Vec<String> = (0..40).map(|i| format!("machine:m{i}")).collect();
        let readings: Vec<(&str, &str, &str, Said)> = scopes
            .iter()
            .map(|s| ("brew", s.as_str(), BREW, FULL))
            .collect();
        for _ in 0..RUNS_KEPT {
            k.run(true, &readings);
        }
        // A few pages freed, as by the readings an ordinary run folds.
        k.conn
            .execute_batch(
                "CREATE TABLE spare (v TEXT);
                 WITH RECURSIVE n (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100)
                 INSERT INTO spare SELECT hex(randomblob(100)) FROM n;
                 DROP TABLE spare;",
            )
            .unwrap();
        let (free, pages) = free_pages(&k.conn).unwrap();
        assert!(
            free > 0 && !worth_giving_back(free, pages),
            "{free} of {pages}"
        );
        tidy(&k.conn);
        assert_eq!(free_pages(&k.conn).unwrap(), (free, pages));
    }

    #[test]
    fn space_given_back_beside_a_reader_reaches_the_file_by_a_later_run() {
        // The vacuum after a fold goes through beside a reader, and the reader's older state
        // keeps the checkpoint from copying it into the file. The next run folds almost
        // nothing, and its checkpoint cuts the file.
        let mut k = Kept::new("free-later");
        let scopes: Vec<String> = (0..40).map(|i| format!("machine:m{i}")).collect();
        let readings: Vec<(&str, &str, &str, Said)> = scopes
            .iter()
            .map(|s| ("brew", s.as_str(), BREW, FULL))
            .collect();
        for _ in 0..(RUNS_KEPT + 200) {
            k.run(true, &readings);
        }
        let path = k.dir.join("store.db");
        let size = || std::fs::metadata(&path).unwrap().len();
        let before = size();
        k.fold();
        let reader = Connection::open(&path).unwrap();
        reader
            .execute_batch("BEGIN; SELECT COUNT(*) FROM coverage;")
            .unwrap();
        tidy(&k.conn);
        assert_eq!(size(), before);
        reader.execute_batch("COMMIT").unwrap();
        drop(reader);
        k.run(true, &readings);
        tidy(&k.conn);
        assert!(size() * 3 < before, "{} bytes of {before}", size());
    }

    #[test]
    fn the_runs_kept_whole_and_the_latest_finished_keep_every_reading_they_made() {
        // The changes page and `immunity status` ask what each of these runs read: a run in the
        // middle of unchanged readings still read them, and is never shown as having read
        // nothing or everything.
        let mut k = Kept::new("window");
        let readings = [
            ("brew", MAC, BREW, failed("no output")),
            ("watched-places", MAC, PROFILES, FULL),
        ];
        let mut runs = Vec::new();
        for _ in 0..(RUNS_KEPT + 10) {
            runs.push(k.run(true, &readings));
        }
        // Runs that died before they finished, after the latest one that finished.
        let finished = runs.last().unwrap().clone();
        for _ in 0..(RUNS_KEPT + 5) {
            k.runs += 1;
            let at = 1_900_000_000 + k.runs * 60;
            let run_id = format!("{at}-000000000");
            journal_note(&k.conn, at, &run_id, "run_started", "").unwrap();
            let tx = k.conn.transaction().unwrap();
            for (reader, scope, kind, said) in &readings {
                let r = Reading {
                    reader,
                    scope,
                    kind,
                    run_id: &run_id,
                    at,
                    observed_at: at,
                };
                put_coverage(
                    &tx,
                    &r,
                    said.completeness,
                    said.reason,
                    &Gap::when(said.cause),
                )
                .unwrap();
            }
            tx.commit().unwrap();
            runs.push(run_id);
        }
        let per_run = |k: &Kept, run: &str| {
            let t = totals(&k.conn, run).unwrap();
            (t.partial, t.none, t.machines_unread, t.not_repeated)
        };
        let kept: Vec<&String> = runs[runs.len() - RUNS_KEPT as usize..]
            .iter()
            .chain([&finished])
            .collect();
        let before: Vec<_> = kept.iter().map(|r| per_run(&k, r)).collect();
        assert!(k.fold().removed > 0);
        let after: Vec<_> = kept.iter().map(|r| per_run(&k, r)).collect();
        assert_eq!(after, before);
        assert!(before.iter().all(|t| t.1 == 1), "{before:?}");
    }

    #[test]
    fn a_place_read_before_and_not_in_a_run_is_not_repeated_unless_what_holds_it_is_gone() {
        // `located_on` decides it: a checkout whose only one was retracted is gone; one with a
        // live one again is not, nor is a machine, which has none.
        let mut k = Kept::new("not-repeated");
        let (gone, back) = ("checkout:machine:mac/gone", "checkout:machine:mac/back");
        let read = |scope| {
            (
                crate::lockfiles::READER,
                scope,
                crate::lockfiles::KIND,
                FULL,
            )
        };
        let server = (
            crate::servers::READER,
            "machine:web-1",
            crate::servers::PACKAGES,
            FULL,
        );
        k.run(true, &[read(gone), read(back), server]);
        for (layer, subject) in [("retracted", gone), ("retracted", back), ("live", back)] {
            k.conn
                .execute(
                    "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                            source_ref, basis, observed_at, run_id, retracted_at)
                     VALUES (?1, ?2, 'located_on', ?3, 'checkouts', ?2, ?4, '', ?5, 1, 'r1',
                             CASE WHEN ?1 = 'retracted' THEN 2 END)",
                    params![
                        layer,
                        subject,
                        MAC,
                        crate::lockfiles::KIND,
                        crate::lockfiles::BASIS
                    ],
                )
                .unwrap();
        }
        let run = k.run(true, &[("watched-places", MAC, PROFILES, FULL)]);
        assert_eq!(totals(&k.conn, &run).unwrap().not_repeated, 2);
    }

    #[test]
    fn nothing_is_folded_before_any_run_journaled_nor_from_the_runs_kept_whole() {
        let mut k = Kept::new("young");
        for _ in 0..5 {
            k.run(false, &[("watched-places", MAC, PROFILES, FULL)]);
        }
        assert_eq!(
            k.fold(),
            Folded {
                removed: 0,
                rows: 5
            }
        );
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("watched-places", MAC, PROFILES, FULL)]);
        }
        // The watcher's readings before the first run are older than every run kept whole.
        assert_eq!(k.fold().removed, 3);
        assert_eq!(k.fold().removed, 0);
    }

    #[test]
    fn a_store_kept_whole_by_an_earlier_build_is_folded_and_its_file_gives_the_space_back() {
        let mut k = Kept::new("earlier");
        let readings: Vec<(&str, String, &str, Said)> = (0..40)
            .map(|i| {
                (
                    "watched-places",
                    format!("file:mac/f{i}"),
                    crate::watched::CONTENT,
                    FULL,
                )
            })
            .collect();
        let readings: Vec<(&str, &str, &str, Said)> = readings
            .iter()
            .map(|(r, s, kind, said)| (*r, s.as_str(), *kind, *said))
            .collect();
        for _ in 0..(RUNS_KEPT + 200) {
            k.run(true, &readings);
        }
        let path = k.dir.join("store.db");
        let size = || std::fs::metadata(&path).unwrap().len();
        let before = size();
        tidy(&k.conn);
        assert!(size() * 3 < before, "{} then {before}", size());
        assert_eq!(k.rows(), 40 * (RUNS_KEPT + 2));
    }

    #[test]
    fn a_store_held_by_another_process_when_a_read_access_reads_is_store_busy_exit_4() {
        // In write-ahead mode only a connection that holds the file itself, as SQLite's
        // exclusive locking mode does, keeps a reader out; whichever read meets it, the error
        // is told by the one mapping.
        let dir = crate::common::Scratch::new("read-busy");
        let path = dir.join("store.db");
        drop(open_or_make(&path).unwrap());
        let holder = Connection::open(&path).unwrap();
        holder
            .execute_batch("PRAGMA locking_mode = EXCLUSIVE; BEGIN EXCLUSIVE")
            .unwrap();
        let refused = read(&path, |c| Ok(id(c)?)).unwrap_err();
        assert_eq!(
            (refused.code, refused.exit()),
            (Code::StoreBusy, 4),
            "{refused}"
        );
    }

    #[test]
    fn a_pipe_or_a_link_to_a_device_in_place_of_a_lock_file_is_an_error_and_never_holds_a_status() {
        let dir = crate::common::Scratch::new("store-held-refused");
        let [pipe, zero, ..] = crate::open::tests::refusals(&dir);
        for path in [pipe, zero] {
            let held = crate::open::tests::within(move || held(&path).is_err());
            assert_eq!(held, Some(true));
        }
    }
}
