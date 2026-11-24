//! How an access to the store ended: one mapping, for every command and the watcher.
//!
//! An access ends in a skip (another holds the store or a lock, so it is asked again), a refusal
//! (no store, or a file this build does not read), a failure of the store (it cannot be written,
//! the disk is full, the system failed a read) or a failure of the work. Which one is decided by
//! SQLite's primary and extended result codes, the refusal `store::check` returns, the locks and
//! the type `std::io::Error`, never by the words of a message. The list is closed, and each
//! outcome has one code, one exit code and one wording.
//!
//! Adopted: SQLite's codes, read as its documentation reads them (the primary code is the low 8
//! bits of the extended one; `SQLITE_LOCKED` is a conflict inside one connection that waiting
//! does not end, so a failure and not a skip), and a skip as a kind apart from a failure, as
//! systemd's `ExecCondition=` keeps it. Immunity Core's own: the four kinds over those sources.

use crate::contract::v1;
use std::error::Error;

/// What an outcome is, for whoever acts on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Another process holds the store or a lock: nothing was done, and it is asked again.
    Skip,
    /// The store is not there, or is a file this build does not read: it is left as it is.
    Refusal,
    /// The store is there and this build's, and the system failed to read or write it.
    StoreFailed,
    /// Anything else: the work itself failed.
    Failed,
}

/// The closed list of outcomes of a failed access, by the word the contract gives it
/// (`Error.outcome`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// `SQLITE_BUSY` and its extended codes past the busy timeout, a hot journal among them.
    StoreBusy,
    /// The run lock, still held after its wait.
    RunLockHeld,
    /// The lock on the downloads: another full check runs.
    CheckRunning,
    /// The watcher's lock: another watcher runs.
    WatchRunning,
    NoStore,
    /// A file that is not an SQLite file, or holds no table: `SQLITE_NOTADB` among them.
    NotAStore,
    OlderFormat,
    NewerFormat,
    /// A file that names no format, or one this build does not know the form of.
    UnknownFormat,
    /// A store of this format whose schema or id is not as the format makes it; `SQLITE_CORRUPT`.
    Damaged,
    /// `SQLITE_READONLY_ROLLBACK`: a journal to roll back in a folder this process cannot write.
    HotJournal,
    /// `SQLITE_READONLY` and its other extended codes, and `SQLITE_PERM`.
    NotWritable,
    /// `SQLITE_READONLY_DBMOVED`, and a store replaced while it was read.
    Moved,
    /// `SQLITE_FULL`.
    DiskFull,
    /// `SQLITE_IOERR` and its extended codes, and an `std::io::Error` met on the store.
    Io,
    /// `SQLITE_CANTOPEN`.
    CannotOpen,
    /// The store's folder could not be made.
    Folder,
    /// Anything else, `SQLITE_LOCKED` included.
    Failed,
}

impl Code {
    /// The word the contract gives it.
    pub fn literal(self) -> &'static str {
        match self {
            Code::StoreBusy => "store_busy",
            Code::RunLockHeld => "run_lock_held",
            Code::CheckRunning => "check_running",
            Code::WatchRunning => "watch_running",
            Code::NoStore => "no_store",
            Code::NotAStore => "not_a_store",
            Code::OlderFormat => "older_format",
            Code::NewerFormat => "newer_format",
            Code::UnknownFormat => "unknown_format",
            Code::Damaged => "damaged",
            Code::HotJournal => "hot_journal",
            Code::NotWritable => "not_writable",
            Code::Moved => "moved",
            Code::DiskFull => "disk_full",
            Code::Io => "io",
            Code::CannotOpen => "cannot_open",
            Code::Folder => "folder",
            Code::Failed => "failed",
        }
    }

    pub fn kind(self) -> Kind {
        match self {
            Code::StoreBusy | Code::RunLockHeld | Code::CheckRunning | Code::WatchRunning => {
                Kind::Skip
            }
            Code::NoStore
            | Code::NotAStore
            | Code::OlderFormat
            | Code::NewerFormat
            | Code::UnknownFormat
            | Code::Damaged => Kind::Refusal,
            Code::HotJournal
            | Code::NotWritable
            | Code::Moved
            | Code::DiskFull
            | Code::Io
            | Code::CannotOpen
            | Code::Folder => Kind::StoreFailed,
            Code::Failed => Kind::Failed,
        }
    }

    /// What happened, in the core's own words, with what was done after "; nothing was ". A
    /// failure of the work is worded by its command (`Outcome::error`).
    fn words(self) -> &'static str {
        match self {
            Code::StoreBusy => {
                "another process held the store for longer than five seconds; nothing was done"
            }
            Code::RunLockHeld => {
                "another check or command is writing to this store; nothing was done"
            }
            Code::CheckRunning => "another check is running on this store; nothing was done",
            Code::WatchRunning => "another watcher is running on this store; nothing was done",
            _ => "the store cannot be read; nothing was changed",
        }
    }
}

/// How one access to the store ended.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub kind: Kind,
    pub code: Code,
    /// What the source said: SQLite's or the system's message, or the store's refusal in full.
    /// Data, never one of the core's sentences.
    pub detail: String,
}

impl Outcome {
    pub fn new(code: Code, detail: impl Into<String>) -> Outcome {
        Outcome {
            kind: code.kind(),
            code,
            detail: detail.into(),
        }
    }

    /// The exit code of the contract: 4 for a skip, 5 for another watcher, 3 for a refusal or a
    /// failure of the store, 1 for a failure of the work.
    pub fn exit(&self) -> u8 {
        match self.kind {
            Kind::Skip if self.code == Code::WatchRunning => crate::watch::EXIT_WATCHING,
            Kind::Skip => crate::EXIT_RUN_IN_PROGRESS,
            Kind::Refusal | Kind::StoreFailed => crate::EXIT_STORE,
            Kind::Failed => 1,
        }
    }

    /// The failure of command `op`, with `example`. Its `code` is the contract's word for the
    /// kind, as every command gave it before `outcome` was added: `run_in_progress` for a skip
    /// (`watch_in_progress` for another watcher), `store_unreadable` for a refusal or a failure
    /// of the store, `command_failed` for a failure of the work.
    pub fn error(&self, op: &str, example: &str) -> v1::Error {
        let code = match self.kind {
            Kind::Skip if self.code == Code::WatchRunning => "watch_in_progress",
            Kind::Skip => "run_in_progress",
            Kind::Refusal | Kind::StoreFailed => "store_unreadable",
            Kind::Failed => "command_failed",
        };
        let message = match self.kind {
            Kind::Failed => format!("immunity {op} could not finish"),
            _ => self.code.words().to_string(),
        };
        let mut error = crate::answer::error(code, &message, example, &self.detail);
        error.outcome = Some(self.code.literal().to_string());
        error
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.detail.is_empty() {
            true => f.write_str(self.code.words()),
            false => f.write_str(&self.detail),
        }
    }
}

impl Error for Outcome {}

impl From<rusqlite::Error> for Outcome {
    fn from(e: rusqlite::Error) -> Outcome {
        of(&e)
    }
}

impl From<Box<dyn Error>> for Outcome {
    fn from(e: Box<dyn Error>) -> Outcome {
        of(&*e)
    }
}

/// The outcome of an error met on the store. An `Outcome` already made passes as it is.
pub fn of(e: &(dyn Error + 'static)) -> Outcome {
    if let Some(outcome) = e.downcast_ref::<Outcome>() {
        return outcome.clone();
    }
    if let Some(sqlite) = e.downcast_ref::<rusqlite::Error>() {
        return of_sqlite(sqlite);
    }
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        return Outcome::new(Code::Io, io.to_string());
    }
    Outcome::new(Code::Failed, e.to_string())
}

/// By SQLite's extended code where one names the case, else by its primary code, the low 8 bits.
fn of_sqlite(e: &rusqlite::Error) -> Outcome {
    use rusqlite::ffi;
    let Some(extended) = e.sqlite_error().map(|f| f.extended_code) else {
        return Outcome::new(Code::Failed, e.to_string());
    };
    let code = match extended {
        ffi::SQLITE_READONLY_ROLLBACK => Code::HotJournal,
        ffi::SQLITE_READONLY_DBMOVED => Code::Moved,
        _ => match extended & 0xff {
            ffi::SQLITE_BUSY => Code::StoreBusy,
            ffi::SQLITE_NOTADB => Code::NotAStore,
            ffi::SQLITE_CORRUPT => Code::Damaged,
            ffi::SQLITE_READONLY | ffi::SQLITE_PERM => Code::NotWritable,
            ffi::SQLITE_FULL => Code::DiskFull,
            ffi::SQLITE_IOERR => Code::Io,
            ffi::SQLITE_CANTOPEN => Code::CannotOpen,
            _ => Code::Failed,
        },
    };
    Outcome::new(code, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, ffi};
    use std::os::unix::fs::PermissionsExt;

    /// An error as SQLite gives it, for a cause no test can make in a temporary folder.
    fn sqlite(extended: i32) -> Outcome {
        of(&rusqlite::Error::SqliteFailure(
            ffi::Error::new(extended),
            None,
        ))
    }

    #[test]
    fn every_outcome_of_the_closed_list_has_its_kind_exit_and_code_and_none_comes_from_words() {
        let dir = crate::common::Scratch::new("outcome-table");
        // Busy: another connection holds the store, and the reader does not wait.
        let path = dir.join("held.db");
        drop(crate::store::open_or_make(&path).unwrap());
        let holder = Connection::open(&path).unwrap();
        holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let reader = Connection::open(&path).unwrap();
        reader.busy_timeout(std::time::Duration::ZERO).unwrap();
        let busy = || {
            reader
                .query_row("SELECT 1 FROM meta", [], |_| Ok(()))
                .unwrap_err()
        };
        // Locked: a connection drops a table one of its own statements is still reading.
        let mem = Connection::open_in_memory().unwrap();
        mem.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1)")
            .unwrap();
        let mut read = mem.prepare("SELECT x FROM t").unwrap();
        let mut rows = read.query([]).unwrap();
        rows.next().unwrap();
        let locked = mem.execute_batch("DROP TABLE t").unwrap_err();
        let missing = mem.execute_batch("SELECT * FROM nowhere").unwrap_err();
        // Not a store: a file that is not SQLite's.
        let notes = dir.join("notes.db");
        std::fs::write(&notes, "invented notes, not a database\n").unwrap();
        // Older: a store whose format is a number below this build's.
        let older = dir.join("older.db");
        drop(crate::store::open_or_make(&older).unwrap());
        Connection::open(&older)
            .unwrap()
            .execute(
                "UPDATE meta SET value = '5' WHERE key = 'format_version'",
                [],
            )
            .unwrap();
        // A store in a folder that cannot be written, written to: its journal cannot be made.
        let shut = dir.join("shut");
        std::fs::create_dir(&shut).unwrap();
        let writer = crate::store::open_or_make(&shut.join("store.db")).unwrap();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o555)).unwrap();
        let unwritable = writer
            .execute_batch("BEGIN IMMEDIATE; DELETE FROM watcher; COMMIT")
            .unwrap_err();
        let gone = std::fs::File::open(dir.join("no folder")).unwrap_err();
        let words: Box<dyn Error> = "database is locked".into();
        let held = Outcome::new(Code::RunLockHeld, "");
        let skip = |o: Outcome, c| (o, c, Kind::Skip, 4, "run_in_progress");
        let refused = |o: Outcome, c| (o, c, Kind::Refusal, 3, "store_unreadable");
        let store = |o: Outcome, c| (o, c, Kind::StoreFailed, 3, "store_unreadable");
        let work = |o: Outcome| (o, Code::Failed, Kind::Failed, 1, "command_failed");
        let rows = [
            ("busy", skip(of(&busy()), Code::StoreBusy)),
            (
                "busy, boxed",
                skip(Box::<dyn Error>::from(busy()).into(), Code::StoreBusy),
            ),
            ("run lock", skip(held.clone(), Code::RunLockHeld)),
            (
                "an outcome passes as it is",
                skip(of(&held), Code::RunLockHeld),
            ),
            (
                "downloads",
                skip(Outcome::new(Code::CheckRunning, ""), Code::CheckRunning),
            ),
            (
                "watcher",
                (
                    Outcome::new(Code::WatchRunning, ""),
                    Code::WatchRunning,
                    Kind::Skip,
                    5,
                    "watch_in_progress",
                ),
            ),
            (
                "no store",
                refused(
                    crate::store::open(&dir.join("none.db")).unwrap_err(),
                    Code::NoStore,
                ),
            ),
            (
                "not a store",
                refused(
                    crate::store::open_read_only(&notes).unwrap_err(),
                    Code::NotAStore,
                ),
            ),
            (
                "NOTADB",
                refused(sqlite(ffi::SQLITE_NOTADB), Code::NotAStore),
            ),
            (
                "older",
                refused(
                    crate::store::open_read_only(&older).unwrap_err(),
                    Code::OlderFormat,
                ),
            ),
            (
                "CORRUPT",
                refused(sqlite(ffi::SQLITE_CORRUPT_INDEX), Code::Damaged),
            ),
            (
                "hot journal",
                store(sqlite(ffi::SQLITE_READONLY_ROLLBACK), Code::HotJournal),
            ),
            (
                "folder not writable",
                store(of(&unwritable), Code::NotWritable),
            ),
            (
                "READONLY",
                store(sqlite(ffi::SQLITE_READONLY), Code::NotWritable),
            ),
            ("PERM", store(sqlite(ffi::SQLITE_PERM), Code::NotWritable)),
            (
                "moved",
                store(sqlite(ffi::SQLITE_READONLY_DBMOVED), Code::Moved),
            ),
            ("disk full", store(sqlite(ffi::SQLITE_FULL), Code::DiskFull)),
            ("IOERR", store(sqlite(ffi::SQLITE_IOERR_READ), Code::Io)),
            ("the system", store(of(&gone), Code::Io)),
            (
                "CANTOPEN",
                store(sqlite(ffi::SQLITE_CANTOPEN), Code::CannotOpen),
            ),
            (
                "folder",
                store(Outcome::new(Code::Folder, "x"), Code::Folder),
            ),
            ("LOCKED", work(of(&locked))),
            ("an error of the work", work(of(&missing))),
            ("the words of busy", work(words.into())),
        ];
        for (row, (got, code, kind, exit, contract)) in rows {
            assert_eq!(
                (got.code, got.kind, got.exit()),
                (code, kind, exit),
                "{row}: {got}"
            );
            let error = got.error("status", "immunity status --json");
            assert_eq!(error.code, contract, "{row}");
            assert_eq!(error.outcome.as_deref(), Some(code.literal()), "{row}");
        }
    }

    #[test]
    fn each_word_of_the_closed_list_is_its_own_and_the_source_s_words_are_only_the_detail() {
        use Code::*;
        let all = [
            StoreBusy,
            RunLockHeld,
            CheckRunning,
            WatchRunning,
            NoStore,
            NotAStore,
            OlderFormat,
            NewerFormat,
            UnknownFormat,
            Damaged,
            HotJournal,
            NotWritable,
            Moved,
            DiskFull,
            Io,
            CannotOpen,
            Folder,
            Failed,
        ];
        let words: std::collections::BTreeSet<&str> = all.iter().map(|c| c.literal()).collect();
        assert_eq!(words.len(), all.len());
        // Each skip says what holds the store; a failure of the work names its command.
        let said = |c: Code| {
            Outcome::new(c, "what SQLite said")
                .error("matches", "")
                .message
        };
        let skips: std::collections::BTreeSet<String> =
            [StoreBusy, RunLockHeld, CheckRunning, WatchRunning]
                .map(said)
                .into();
        assert_eq!(skips.len(), 4);
        assert_eq!(said(Failed), "immunity matches could not finish");
        let e = Outcome::new(Io, "what SQLite said").error("status", "");
        assert_eq!(e.detail_text.as_deref(), Some("what SQLite said"));
        assert!(!e.message.contains("SQLite"));
    }
}
