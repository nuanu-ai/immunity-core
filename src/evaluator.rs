//! The evaluator: the watcher's reader of the event log, a thread of its own with its own
//! connection to the store, so that a reading of watched places or a sample of processes never
//! stands between a line of the log and its evaluation.
//!
//! It is woken by `kqueue` (`EVFILT_VNODE`, through `libc`) on the log's folder, for a file made
//! or deleted, and on the file the collector writes now, for a line written, and by a recovery
//! tick (`TICK`) behind them. It registers for a file before it reads that file to its end, so a
//! line written between its read and its wait wakes it. On a wake of the file it reads on in
//! that file; on a wake of the folder, a file gone or the tick, it looks at the whole log again.
//! Each whole line is parsed once and every rule of its kind evaluated on it (`events::Reader`).
//!
//! What it read is written in one transaction (`events::Reader::write`): a row of the record for
//! every match, how far the log was read, the counts, and for a rule that raises a finding, the
//! finding with its evidence and journal entry. A match is written at once, and under matches
//! that keep coming, writes are grouped by `GROUP`. With no match, how far it read is written
//! about once a second (`IDLE`), and nothing is written while nothing is read. Every
//! `--events-every` the write also concludes: the level's state, what the collector said,
//! whether file events are collected, and the coverage.
//!
//! Each write takes the run lock, as every writer of the store does, and opens the store under
//! it, so nothing is written outside the run lock and a store put in place of another under it
//! is the one written to, checked as every open checks it. A full check holds the store in one
//! transaction for its whole length, so waiting for its run lock costs nothing more than waiting
//! for SQLite's write lock would. While it waits it does not advance, and the watcher's loop,
//! which asks `stalled`, says so. A transaction that finds the store's frontier moved since it
//! read, by a full check's reading, writes nothing, takes the store's frontier and reads again,
//! so no line is judged twice or skipped.
//!
//! Each start of the thread is a new evaluator, by a random number (`Evaluator::id`), which every
//! write records with whether it has read every whole line it listed since that start and when it
//! wrote, and which the watcher's lock file names: `immunity matches` says the evaluator is
//! current only from these, never from the times of the log's files.
//!
//! What the watcher prints and records stays in its main thread: the evaluator tells it, through
//! a channel, a reading that failed or succeeded after one that did, that it has caught up with
//! the log once after its start, and what each conclusion took.

use crate::events;
use crate::store;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How often the evaluator looks at the log with no wake: it bounds how late a line is known when
/// a wake is lost, as a file made in the moment between a look and a registration, and the
/// promise for an event is one to two seconds. A look at a log that did not grow is a listing of
/// its folder.
pub const TICK: Duration = Duration::from_secs(1);
/// How long matches that keep coming are gathered before they are written. The first match of a
/// quiet spell is written at once. Measured on the prototype of this design with 3,000 lines a
/// second of which 100 matched: a line known 0.19 ms after it was written at the median and
/// 2.4 ms at the 95th percentile, and the writes took 0.6% of a core.
const GROUP: Duration = Duration::from_millis(5);
/// How long lines that matched nothing wait before how far they were read is written: an idle
/// Mac is not made to write at every line.
const IDLE: Duration = Duration::from_secs(1);
/// How many bytes of whole lines are read before they are written, matches or not: catching up
/// on a log left unread writes as it goes, so a stop loses little and an answer sees it move.
const BUDGET: u64 = 4 << 20;
/// How long a write waits for SQLite's write lock under the run lock, before it lets go of the
/// run lock for as long again and tries anew. No writer of Immunity Core holds the store without
/// the run lock, only a tool outside it can, for as long as it likes: a command meanwhile gets
/// the run lock between two tries, and the evaluator is behind, and says so, until it writes.
const BUSY: Duration = Duration::from_millis(100);

/// What the evaluator tells the watcher's loop.
pub enum Said {
    /// A reading failed, with why; `None` when one succeeded.
    Marked(Option<String>),
    /// It has read every whole line it listed, the first time since it started.
    CaughtUp,
    /// A conclusion, every `--events-every`, boxed: the level it carries is large.
    Concluded(Box<Read>),
}

/// What one conclusion of the evaluator came to: the program starts read since the conclusion
/// before, whether it changed the level's state, the level as it left it, when, and whether
/// whole lines of the log were left that it has not read yet.
pub struct Read {
    pub starts: i64,
    pub changed: bool,
    pub level: Option<events::Level>,
    pub at: i64,
    pub behind: bool,
}

/// What the evaluator and the watcher's loop share: whether it is to stop, when it last
/// advanced (it wrote, or found nothing left to write), since when it waits for the run lock and
/// since when it finds the store held, `0` when it does not, each in milliseconds since it started, plus one.
struct Shared {
    stop: AtomicBool,
    advanced: AtomicU64,
    waiting: AtomicU64,
    /// Since when, under the run lock, it finds the store held by a writer outside Immunity Core.
    held: AtomicU64,
    started: Instant,
}

impl Shared {
    fn now(&self) -> u64 {
        self.started.elapsed().as_millis() as u64 + 1
    }

    fn advance(&self) {
        self.advanced.store(self.now(), Ordering::SeqCst);
    }

    fn since(&self, at: &AtomicU64) -> Option<Duration> {
        let at = at.load(Ordering::SeqCst);
        (at > 0).then(|| Duration::from_millis(self.now().saturating_sub(at)))
    }
}

/// The evaluator's thread, for the watcher's loop.
pub struct Evaluator {
    handle: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
    id: i64,
}

impl Evaluator {
    /// Starts the evaluator of the log under `root` into the store at `store`, concluding every
    /// `every`. `tell` is how it tells the watcher's loop.
    pub fn start(
        store: PathBuf,
        root: PathBuf,
        every: Duration,
        tell: impl Fn(Said) -> bool + Send + 'static,
    ) -> std::io::Result<Evaluator> {
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            advanced: AtomicU64::new(1),
            waiting: AtomicU64::new(0),
            held: AtomicU64::new(0),
            started: Instant::now(),
        });
        let theirs = shared.clone();
        let mut bytes = [0u8; 8];
        // SAFETY: arc4random_buf(3) fills exactly the bytes it is given and cannot fail.
        unsafe { libc::arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len()) };
        // A number the store keeps as an integer: 63 bits, never negative.
        let id = (u64::from_ne_bytes(bytes) >> 1) as i64;
        let handle = std::thread::Builder::new()
            .name("evaluator".into())
            .spawn(move || run(&store, &root, every, id, &theirs, &tell))?;
        Ok(Evaluator {
            handle: Some(handle),
            shared,
            id,
        })
    }

    /// Which evaluator it is: random, new at each start, and recorded by each of its writes.
    pub fn id(&self) -> i64 {
        self.id
    }

    /// Whether it stalled: it has not advanced for three conclusions (`every`), or while it
    /// waits for the run lock, for longer than a full check may take (`background::LIMIT`),
    /// which holds that lock for as long as it runs.
    pub fn stalled(&self, every: Duration) -> bool {
        let s = &self.shared;
        match s.since(&s.waiting) {
            Some(waited) => waited >= crate::background::LIMIT,
            None => s.since(&s.advanced).is_some_and(|d| d > every * 3),
        }
    }

    /// Whether a writer outside Immunity Core has held the store for two conclusions (`every`):
    /// the store does not take what it reads, as two readings in a row that met a busy store.
    pub fn held(&self, every: Duration) -> bool {
        let s = &self.shared;
        s.since(&s.held).is_some_and(|d| d >= every * 2)
    }

    /// Whether its thread has ended.
    pub fn finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Asks it to stop and waits for it: it stops between two transactions, at its next wake,
    /// within `TICK` or one wait for the store's lock.
    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Evaluator {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The evaluator's loop, until it is asked to stop or `tell` says nobody listens.
fn run(
    store: &Path,
    root: &Path,
    every: Duration,
    id: i64,
    shared: &Shared,
    tell: &dyn Fn(Said) -> bool,
) {
    let mut failing: Option<String> = None;
    let mut say = |failed: Option<String>| -> bool {
        let changed = failed != failing;
        failing = failed.clone();
        !changed || tell(Said::Marked(failed))
    };
    let Ok(kq) = Kqueue::new() else {
        say(Some("the evaluator could not make a kqueue".into()));
        return;
    };
    // A store that cannot be opened is a failed reading, tried again at every tick.
    let mut reader = loop {
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        match open(store, root) {
            Ok(opened) => break opened,
            Err(why) => {
                if !say(Some(why)) {
                    return;
                }
                kq.wait(TICK);
            }
        }
    };
    reader.by_evaluator(id);
    let mut watch = Watched::default();
    let mut look = true;
    let mut caught_up = false;
    let mut last_write = Instant::now();
    let mut last_match: Option<Instant> = None;
    let mut last_conclusion: Option<Instant> = None;
    let (mut starts, mut state) = (0, None);
    while !shared.stop.load(Ordering::SeqCst) {
        let now = crate::now_secs();
        let due = last_conclusion.is_none_or(|t| t.elapsed() >= every);
        // A conclusion rests on a look at the whole log, and lines left by a budget are read on
        // in the order of the files, from a look.
        if look || due || reader.more() {
            reader.relist(now, BUDGET, |dir, file| watch.register(&kq, dir, file));
            look = false;
        } else if reader.read_on(now, BUDGET) {
            look = true;
            continue;
        }
        // A pass concludes once it reached the end of the log: one that stopped at its budget
        // writes what it read and reads on, and concludes when it is through.
        let conclude = due && !reader.more();
        let matched = reader.matched() > 0 && last_match.is_none_or(|t| t.elapsed() >= GROUP);
        let idle = reader.owed() && (last_write.elapsed() >= IDLE || reader.more());
        if (matched || idle || conclude) && !reader.holds_back() {
            let wrote = write(store, &mut reader, now, conclude, shared);
            let (out, level) = match wrote {
                Ok(Some(written)) => written,
                // Another reader read since: the store's frontier is taken and read on from.
                Ok(None) => {
                    look = true;
                    continue;
                }
                // What was read is read again from the store's frontier once it can be written.
                Err(why) => {
                    if !say(Some(why)) {
                        return;
                    }
                    reader.forget();
                    kq.wait(TICK);
                    look = true;
                    continue;
                }
            };
            last_write = Instant::now();
            if out.matches > 0 {
                last_match = Some(last_write);
            }
            if !say(out.failed.clone()) {
                return;
            }
            if out.caught_up && !caught_up && out.failed.is_none() {
                caught_up = true;
                if !tell(Said::CaughtUp) {
                    return;
                }
            }
            starts += out.starts;
            if conclude {
                last_conclusion = Some(last_write);
                let changed = state != Some(out.state);
                state = Some(out.state);
                let read = Read {
                    starts,
                    changed,
                    level,
                    at: now,
                    behind: !out.caught_up,
                };
                if !tell(Said::Concluded(Box::new(read))) {
                    return;
                }
                starts = 0;
            }
        }
        if !reader.owed() || last_write.elapsed() < IDLE {
            shared.advance();
        }
        if reader.more() {
            continue;
        }
        // Wake for the group of matches, the idle write or the conclusion, whichever is first.
        let mut wait = TICK;
        if reader.matched() > 0 {
            wait = wait.min(GROUP.saturating_sub(last_match.map_or(GROUP, |t| t.elapsed())));
        }
        if reader.owed() {
            wait = wait.min(IDLE.saturating_sub(last_write.elapsed()));
        }
        if let Some(t) = last_conclusion {
            wait = wait.min(every.saturating_sub(t.elapsed()));
        }
        match kq.wait(wait) {
            Woken::Nothing => look |= reader.matched() == 0 && !reader.owed(),
            Woken::File => {}
            Woken::Folder => look = true,
        }
    }
}

/// A reader of the log under `root` from where the store's frontier stands.
fn open(store: &Path, root: &Path) -> Result<events::Reader, String> {
    let conn = connect(store).map_err(|o| o.to_string())?;
    events::Reader::load(&conn, root).map_err(|e| e.to_string())
}

/// The store opened and checked against its schema, as every open of it is (`store::open`): a
/// store removed, put in place of another or emptied of its schema is refused and never made.
fn connect(store: &Path) -> Result<rusqlite::Connection, crate::outcome::Outcome> {
    let conn = store::open(store)?;
    conn.busy_timeout(BUSY)
        .map_err(crate::outcome::Outcome::from)?;
    Ok(conn)
}

/// Writes what `reader` read, in one transaction under the run lock, waited for in turns of
/// `store::LOCK_WAIT` for as long as it takes: a full check holds it, and the store, for its
/// whole length. The store is opened again for each write, under the lock, so a store put in
/// place of the one it read is the one it writes to, and checked. `None` when the store's
/// frontier moved since the reader began from it, which it then takes, or when the evaluator is
/// to stop. With `conclude`, also the level as the write left it.
fn write(
    store: &Path,
    reader: &mut events::Reader,
    now: i64,
    conclude: bool,
    shared: &Shared,
) -> Result<Option<(events::Outcome, Option<events::Level>)>, String> {
    let home = crate::home(store);
    let _ = shared
        .waiting
        .compare_exchange(0, shared.now(), Ordering::SeqCst, Ordering::SeqCst);
    let wrote = loop {
        if shared.stop.load(Ordering::SeqCst) {
            break Ok(None);
        }
        let _lock = match store::lock_run(&home) {
            Ok(Some(lock)) => lock,
            Ok(None) => continue,
            Err(e) => break Err(format!("the run lock: {e}")),
        };
        // Held by a tool outside Immunity Core, at the open, which seeds the vocabulary, or at
        // the transaction: the run lock is let go of for a while.
        match connect(store) {
            Ok(mut conn) => match conn.transaction() {
                Ok(tx) => {
                    shared.waiting.store(0, Ordering::SeqCst);
                    shared.held.store(0, Ordering::SeqCst);
                    break written(tx, reader, now, conclude).map_err(|e| e.to_string());
                }
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::DatabaseBusy => {}
                Err(e) => break Err(e.to_string()),
            },
            Err(o) if o.kind == crate::outcome::Kind::Skip => {}
            Err(o) => break Err(o.to_string()),
        }
        drop(_lock);
        let _ = shared
            .held
            .compare_exchange(0, shared.now(), Ordering::SeqCst, Ordering::SeqCst);
        std::thread::sleep(BUSY);
    };
    shared.waiting.store(0, Ordering::SeqCst);
    if wrote.is_err() {
        shared.held.store(0, Ordering::SeqCst);
    }
    wrote
}

/// `write` in `tx`, under the run lock: committed and taken as the frontier, or, when the
/// store's frontier moved, rolled back and the store's frontier taken. The Mac it writes about is
/// the one the store in hand names, read in the transaction, so a store put in place of another
/// is written about its own Mac.
fn written(
    tx: rusqlite::Transaction,
    reader: &mut events::Reader,
    now: i64,
    conclude: bool,
) -> rusqlite::Result<Option<(events::Outcome, Option<events::Level>)>> {
    let machine = &crate::this_machine_or_named(&tx)?;
    store::put_entity(&tx, machine)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let run_id = format!("{}{now}-{nanos:09}", events::RUN_PREFIX);
    let Some(out) = reader.write(&tx, &run_id, machine, now, conclude)? else {
        reader.reload(&tx)?;
        return Ok(None);
    };
    let level = match conclude {
        true => events::level(&tx, now)?,
        false => None,
    };
    tx.commit()?;
    reader.wrote();
    Ok(Some((out, level)))
}

/// What woke the evaluator.
enum Woken {
    Nothing,
    File,
    Folder,
}

/// A kqueue, closed when dropped.
struct Kqueue(OwnedFd);

impl Kqueue {
    fn new() -> std::io::Result<Kqueue> {
        // SAFETY: kqueue(2) takes nothing; a descriptor it returns is ours to own.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a descriptor just made and owned by nothing else.
        Ok(Kqueue(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Asks to be woken when `fd` changes as `fflags` says, until it is closed.
    fn add(&self, fd: &OwnedFd, fflags: u32) -> std::io::Result<()> {
        let change = libc::kevent {
            ident: fd.as_raw_fd() as usize,
            filter: libc::EVFILT_VNODE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: one change from a live structure, no events asked back.
        let r = unsafe {
            libc::kevent(
                self.0.as_raw_fd(),
                &change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Waits up to `timeout` for a wake.
    fn wait(&self, timeout: Duration) -> Woken {
        let ts = libc::timespec {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        };
        // SAFETY: a zeroed kevent is a valid value of a plain C structure.
        let mut events: [libc::kevent; 4] = unsafe { std::mem::zeroed() };
        // SAFETY: the buffer holds as many events as it says, and both outlive the call.
        let n = unsafe {
            libc::kevent(
                self.0.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                &ts,
            )
        };
        let fired = &events[..n.max(0) as usize];
        let gone = libc::NOTE_DELETE | libc::NOTE_RENAME;
        if fired
            .iter()
            .any(|e| e.udata.is_null() || e.fflags & gone != 0)
        {
            // The folder, or the file written now gone: a look at the whole log.
            return Woken::Folder;
        }
        match fired.is_empty() {
            true => Woken::Nothing,
            false => Woken::File,
        }
    }
}

/// What the evaluator is registered for: the log's folder and the file the collector writes
/// now, each by a descriptor opened only for events (`O_EVTONLY`), which keeps no volume busy.
#[derive(Default)]
struct Watched {
    folder: Option<OwnedFd>,
    file: Option<(String, OwnedFd)>,
}

impl Watched {
    /// Registers for the folder `dir` and for `file` in it, the file the collector writes now,
    /// as a look found them, before it reads them. A file that cannot be registered for is read
    /// at the tick.
    fn register(&mut self, kq: &Kqueue, dir: &Path, file: Option<&str>) {
        if self.folder.is_none()
            && let Some(fd) = evtonly(dir)
            && kq.add(&fd, libc::NOTE_WRITE).is_ok()
        {
            self.folder = Some(fd);
        }
        let same = matches!((&self.file, file), (Some((was, _)), Some(now)) if was == now);
        if same {
            return;
        }
        self.file = file.and_then(|name| {
            let fd = evtonly(&dir.join(name))?;
            let wanted =
                libc::NOTE_WRITE | libc::NOTE_EXTEND | libc::NOTE_DELETE | libc::NOTE_RENAME;
            // The file's registration carries a mark, so a wake tells it from the folder's.
            let change = libc::kevent {
                ident: fd.as_raw_fd() as usize,
                filter: libc::EVFILT_VNODE,
                flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: wanted,
                data: 0,
                udata: std::ptr::NonNull::<libc::c_void>::dangling().as_ptr(),
            };
            // SAFETY: one change from a live structure, no events asked back; the mark is never
            // read through.
            let r = unsafe {
                libc::kevent(
                    kq.0.as_raw_fd(),
                    &change,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };
            (r == 0).then(|| (name.to_string(), fd))
        });
    }
}

/// A descriptor of `path` opened only to be told of its changes.
fn evtonly(path: &Path) -> Option<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: the path ends in NUL and outlives the call; a descriptor returned is ours.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_EVTONLY) };
    // SAFETY: `fd` is a descriptor just opened and owned by nothing else.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// A program start the rule of high level that a search for passwords matches.
    const HIGH: &str = r#"{"schema_version":1,"version":7,"seq_num":1,"global_seq_num":1,"time":"2026-10-04T00:00:02.000002Z","process":{"executable":{"path":"/bin/zsh"}},"event":{"exec":{"args":["grep","-r","password","."],"cwd":{"path":"/Users/example"},"target":{"executable":{"path":"/usr/bin/grep"},"audit_token":{"pid":402,"euid":501},"ppid":401,"signing_id":"com.apple.grep","team_id":null,"is_platform_binary":true}}}}"#;
    const NAME: &str = "exec-20261004T000013-20261004T000000.jsonl";

    /// A store that knows its Mac, and a system root with the collector installed and an empty
    /// log file.
    fn scene(tag: &str) -> (crate::common::Scratch, PathBuf, PathBuf) {
        let dir = crate::common::Scratch::new(tag);
        let root = dir.join("root");
        std::fs::create_dir_all(root.join(events::LOG)).unwrap();
        let plist = root.join(events::PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        std::fs::write(root.join(events::LOG).join(NAME), "").unwrap();
        let store = dir.join("store.db");
        let conn = store::open_or_make(&store).unwrap();
        let mac = "INSERT INTO meta (key, value) VALUES ('machine', 'machine:mac'), ('machine_name', 'mac')";
        conn.execute_batch(mac).unwrap();
        (dir, root, store)
    }

    fn append(root: &Path, line: &str) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(root.join(events::LOG).join(NAME))
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn rows(store: &Path) -> i64 {
        let conn = store::open_read_only(store).unwrap();
        conn.query_row("SELECT COUNT(*) FROM rule_line", [], |r| r.get(0))
            .unwrap()
    }

    /// Starts an evaluator and waits for it to say it caught up.
    fn started(store: &Path, root: &Path) -> (Evaluator, mpsc::Receiver<Said>) {
        let (tx, rx) = mpsc::channel();
        let e = Evaluator::start(
            store.to_path_buf(),
            root.to_path_buf(),
            Duration::from_secs(10),
            move |said| tx.send(said).is_ok(),
        )
        .unwrap();
        loop {
            match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                Said::CaughtUp => return (e, rx),
                Said::Marked(Some(why)) => panic!("{why}"),
                _ => {}
            }
        }
    }

    #[test]
    fn a_backlog_past_the_budget_is_concluded_once_it_was_read_to_its_end_and_never_part_way() {
        // A conclusion says the log was read whole: a pass that stopped at its budget writes what
        // it read and reads on, and the conclusion that follows counts every line of the backlog.
        let (dir, root, store) = scene("evaluator-backlog");
        let mut conn = store::open(&store).unwrap();
        let tx = conn.transaction().unwrap();
        store::put_entity(&tx, "machine:mac").unwrap();
        events::read(&tx, "events-1", "machine:mac", &root, crate::now_secs()).unwrap();
        tx.commit().unwrap();
        let line = HIGH.replace("password", "nothing");
        let n = BUDGET as usize / line.len() + 100;
        let backlog: String = (1..=n)
            .map(|i| line.replace("_num\":1,", &format!("_num\":{i},")) + "\n")
            .collect();
        std::fs::write(root.join(events::LOG).join(NAME), backlog).unwrap();
        let (tx, rx) = mpsc::channel();
        let every = Duration::from_secs(10);
        let mut e = Evaluator::start(store.clone(), root.clone(), every, move |said| {
            tx.send(said).is_ok()
        })
        .unwrap();
        let read = loop {
            if let Said::Concluded(read) = rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                break read;
            }
        };
        assert_eq!((read.starts, read.behind), (n as i64, false));
        e.stop();
        drop(dir);
    }

    #[test]
    fn a_registration_made_before_a_read_is_woken_by_a_line_written_after_it() {
        // The evaluator registers for the file the collector writes, then reads it to its end,
        // then waits: a line written between the read and the wait wakes it at once, never only
        // at the tick. A file made in the folder wakes it as the folder.
        let (dir, root, _) = scene("evaluator-wake");
        let kq = Kqueue::new().unwrap();
        let mut watch = Watched::default();
        let folder = root.join(events::LOG);
        watch.register(&kq, &folder, Some(NAME));
        append(&root, HIGH);
        let t = Instant::now();
        assert!(matches!(kq.wait(Duration::from_secs(5)), Woken::File));
        assert!(t.elapsed() < Duration::from_secs(4));
        std::fs::write(
            folder.join("exec-20261004T000013-20261004T010000.jsonl"),
            "",
        )
        .unwrap();
        assert!(matches!(kq.wait(Duration::from_secs(5)), Woken::Folder));
        // Nothing written: the wait lasts its time and says so.
        assert!(matches!(kq.wait(Duration::from_millis(50)), Woken::Nothing));
        drop(dir);
    }

    #[test]
    fn a_match_is_in_the_store_within_the_promise_of_its_line_and_the_evaluator_stops_when_asked() {
        // A line is known within the tick at most; with the wake, in milliseconds, even in a log
        // whose file the collector has not written a line to yet. Asked
        // to stop, the thread ends between two transactions and is joined.
        let (dir, root, store) = scene("evaluator-match");
        let (mut e, _rx) = started(&store, &root);
        assert_eq!(rows(&store), 0);
        let t = Instant::now();
        append(&root, HIGH);
        // Half the tick: a row that waited for the tick, and not for the wake, is late.
        while rows(&store) == 0 {
            assert!(t.elapsed() < TICK / 2, "no row after {:?}", t.elapsed());
            std::thread::sleep(Duration::from_millis(5));
        }
        println!("a match recorded {:?} after its line", t.elapsed());
        let t = Instant::now();
        e.stop();
        assert!(e.finished());
        assert!(
            t.elapsed() < TICK + Duration::from_secs(1),
            "{:?}",
            t.elapsed()
        );
        drop(dir);
    }

    #[test]
    fn lines_that_match_nothing_are_written_as_read_within_about_a_second_not_at_the_conclusion() {
        // How far it read is written about once a second (`IDLE`) while lines come that match
        // nothing, so an answer does not take the evaluator for one that stalled.
        let (dir, root, store) = scene("evaluator-idle");
        let (mut e, _rx) = started(&store, &root);
        let offset = || -> i64 {
            let conn = store::open_read_only(&store).unwrap();
            conn.query_row("SELECT COALESCE(MAX(offset), 0) FROM event_file", [], |r| {
                r.get(0)
            })
            .unwrap()
        };
        let before = offset();
        append(&root, &HIGH.replace("password", "nothing"));
        let t = Instant::now();
        while offset() == before {
            assert!(
                t.elapsed() < IDLE * 3,
                "not written after {:?}",
                t.elapsed()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(rows(&store), 0);
        e.stop();
        drop(dir);
    }

    #[test]
    fn a_command_under_the_run_lock_is_never_refused_while_the_evaluator_writes() {
        // The evaluator holds the run lock for one write at a time, milliseconds each, so a
        // command waiting for it, `LOCK_WAIT` at most, is never refused while lines come.
        let (dir, root, store) = scene("evaluator-run-lock");
        let (mut e, _rx) = started(&store, &root);
        for n in 0..200 {
            append(
                &root,
                &HIGH.replace(r#""seq_num":1"#, &format!(r#""seq_num":{}"#, n + 2)),
            );
            let wrote = store::write::<_, Box<dyn std::error::Error>>(
                &store,
                store::LOCK_WAIT,
                store::open,
                |tx| {
                    tx.execute(
                        "INSERT OR REPLACE INTO meta (key, value) VALUES ('example', ?1)",
                        [n],
                    )?;
                    Ok(())
                },
            );
            assert!(wrote.is_ok(), "{n}: {:?}", wrote.err());
        }
        e.stop();
        assert!(rows(&store) > 0);
        drop(dir);
    }

    #[test]
    fn the_evaluator_writes_nothing_while_another_holds_the_run_lock_and_writes_once_it_is_let_go()
    {
        // Nothing is written to the store outside the run lock: a full check, which holds it for
        // its whole length, never has a write of the evaluator inside it, so the rows a check
        // keeps are those of its own run (`store::kept_from`). Meanwhile the evaluator waits,
        // and says so.
        let (dir, root, store) = scene("evaluator-held");
        let (mut e, _rx) = started(&store, &root);
        let held = store::lock_run(&crate::home(&store)).unwrap().unwrap();
        append(&root, HIGH);
        let t = Instant::now();
        while e.shared.since(&e.shared.waiting).is_none() {
            assert!(t.elapsed() < Duration::from_secs(5), "it never waited");
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(rows(&store), 0);
        drop(held);
        let t = Instant::now();
        while rows(&store) == 0 {
            assert!(
                t.elapsed() < store::LOCK_WAIT * 2,
                "no row after the lock was let go"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        e.stop();
        drop(dir);
    }

    #[test]
    fn a_finding_is_about_the_mac_of_the_store_written_to_also_a_store_put_in_place_of_another() {
        // The Mac a finding is about is read in the transaction that writes it: a store put in
        // place of the one the evaluator started on, of another Mac, is written about its own.
        let (dir, root, store) = scene("evaluator-swap");
        let (mut e, _rx) = started(&store, &root);
        let held = store::lock_run(&crate::home(&store)).unwrap().unwrap();
        let fresh = dir.join("fresh.db");
        let old = rusqlite::Connection::open(&store).unwrap();
        old.execute("VACUUM INTO ?1", [fresh.to_str().unwrap()])
            .unwrap();
        let new = rusqlite::Connection::open(&fresh).unwrap();
        // `VACUUM INTO` writes a file in the rollback journal's mode.
        new.pragma_update(None, "journal_mode", "wal").unwrap();
        new.execute(
            "UPDATE meta SET value = 'machine:willow' WHERE key = 'machine'",
            [],
        )
        .unwrap();
        drop(new);
        old.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        drop(old);
        std::fs::rename(&fresh, &store).unwrap();
        drop(held);
        append(&root, HIGH);
        let t = Instant::now();
        let about = || -> Option<String> {
            let conn = store::open_read_only(&store).ok()?;
            conn.query_row("SELECT about FROM finding", [], |r| r.get(0))
                .ok()
        };
        while about().is_none() {
            assert!(t.elapsed() < Duration::from_secs(5), "no finding");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(about().as_deref(), Some("machine:willow"));
        e.stop();
        drop(dir);
    }

    #[test]
    fn an_evaluator_that_has_not_advanced_for_three_conclusions_or_waited_past_a_check_is_stalled()
    {
        let every = Duration::from_secs(10);
        let ago = |d: Duration| Instant::now().checked_sub(d).unwrap();
        let of = |started: Instant, advanced: Duration, waiting: Option<Duration>| {
            let shared = Arc::new(Shared {
                stop: AtomicBool::new(false),
                advanced: AtomicU64::new(advanced.as_millis() as u64 + 1),
                waiting: AtomicU64::new(waiting.map_or(0, |w| w.as_millis() as u64 + 1)),
                held: AtomicU64::new(0),
                started,
            });
            Evaluator {
                handle: None,
                shared,
                id: 1,
            }
        };
        let start = ago(Duration::from_secs(4000));
        // It advanced 29 seconds ago, then 31.
        assert!(!of(start, Duration::from_secs(3971), None).stalled(every));
        assert!(of(start, Duration::from_secs(3969), None).stalled(every));
        // It waits for the run lock: stalled only past the time a check may take.
        let limit = crate::background::LIMIT.as_secs();
        let waiting = |s: u64| Some(Duration::from_secs(4000 - s));
        assert!(!of(start, Duration::ZERO, waiting(limit - 60)).stalled(every));
        assert!(of(start, Duration::ZERO, waiting(limit + 60)).stalled(every));
    }
}
