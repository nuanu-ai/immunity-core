//! Samples of this user's processes and their internet connections, and the one rule over
//! them. This is the level of access without administrator rights in `docs/how-it-works.md`:
//! nothing here asks for a permission. A sample says what is running at one moment. It is not an
//! event: Apple's Endpoint Security names the start of a program `exec`, and a sample never
//! sees that moment, so nothing here carries an Endpoint Security event name. The fields are
//! named after the Elastic Common Schema: `process.pid`, `process.start`,
//! `process.parent.pid`, `process.executable`, `process.interactive`,
//! `process.code_signature`, `destination.ip`, `destination.port`, `network.transport`.
//!
//! The calls are the system's own: libproc (`libproc.h`, `sys/proc_info.h`) and sysctl
//! (`sys/sysctl.h`), through `libc` where it declares them. Where it does not, the declaration
//! is below, copied from `sys/proc_info.h` of the macOS SDK with its line, and its size is
//! checked at build time against the SDK's `sizeof` and at each call against what the kernel
//! says it wrote. No tool is run.
//!
//! A command line is read into memory only for a program the interpreter table names, to decide
//! one literal. It is kept only for a process the rule may fire on, an interpreter given code
//! and detached, and for one connected to an address on the indicator list, and only with its
//! secrets cut as the arguments of a published rule's evidence are (`secrets::Args`). Every
//! other command line is dropped there. The environment is never read.
//!
//! What is kept: a small table of the processes the rule is tracking and one of connections
//! that matched an indicator, see `SCHEMA`, both trimmed of what has been gone for `KEEP`.
//! A process is not an entity with a lifecycle: it lives for minutes or days, and the facts
//! and their lifecycle are for what the owner has. A process with a stable identity belongs in
//! a table of events, which is not built; these tables are its first rough form, for two rules.
//! A finding a sample raises rests on a journal entry `sampled`, one per raise, naming the
//! program, the process's identity and what was derived, and what the sample read of the
//! process: its command line cut, its folder, its parent and the leaders of its session and
//! group, and for a connection its port and transport (`sampled`), so the finding still says what
//! ran once the process has ended.
//! Each sample's coverage is one row per kind, replaced at every sample: a sample every
//! thirty seconds would otherwise outgrow every other reading's history.

use crate::codesign;
use crate::findings::Observed;
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsString, c_int, c_void};
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Part of the store's schema (`store::schema`). One row per process the rule is tracking: an
/// interpreter given code on its command line whose parent was gone or was launchd when a
/// sample saw it.
pub const SCHEMA: &str = "
CREATE TABLE tracked_process (
    pid            INTEGER NOT NULL,  -- process.pid
    start          INTEGER NOT NULL,  -- process.start, microseconds since the epoch
    executable     TEXT NOT NULL,     -- process.executable
    interpreter    TEXT NOT NULL,     -- the kind in the interpreter table
    shape          TEXT NOT NULL,     -- what the rule derived from the command line
    -- process.interactive: some sample saw it with a controlling terminal.
    interactive    INTEGER NOT NULL,
    code_signature TEXT,              -- who signed the executable, as `signed_by` says it
    first_seen_at  INTEGER NOT NULL,
    first_seen_run TEXT NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    last_seen_run  TEXT NOT NULL,
    PRIMARY KEY (pid, start)
);
-- A connection of a process to an address on the indicator list, once per process and
-- indicator, so that a connection that stays raises its finding once.
CREATE TABLE matched_connection (
    pid           INTEGER NOT NULL,
    start         INTEGER NOT NULL,
    indicator     TEXT NOT NULL,     -- the STIX comparison it matched
    executable    TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    PRIMARY KEY (pid, start, indicator)
);
-- The latest sample, for the status: when, and how many processes and connections it read.
CREATE TABLE last_sample (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    at          INTEGER NOT NULL,
    processes   INTEGER NOT NULL,
    connections INTEGER NOT NULL
);
";

/// The coverage kinds of a sample, vocabulary applied on every open that may write.
pub const KINDS: &str = "
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('running programs of this user, sampled'),
    ('internet connections of this user''s programs, sampled');
";

/// The reader's name in coverage and the journal.
pub const READER: &str = "processes";
/// The coverage kinds of a sample.
pub const PROGRAMS_KIND: &str = "running programs of this user, sampled";
pub const CONNECTIONS_KIND: &str = "internet connections of this user's programs, sampled";
/// How the run id of a sample begins.
pub const RUN_PREFIX: &str = "sample-";
/// How long a process, or its matched connection, is kept after the last sample that saw it.
pub const KEEP: i64 = 24 * 60 * 60;

/// The one literal derived from a command line.
pub const INLINE_CODE: &str = "interpreter given code on its command line";

/// What the rule is told, and the kind of its findings.
pub const DETACHED_INLINE: &str = "interpreter running code from its command line, detached";

/// Two samples must see a process at least this far apart before the rule fires, so that it
/// fires on a process that stays running.
pub const MIN_APART: i64 = 60;

/// What every sample says it cannot see.
pub const CANNOT_SEE: [&str; 8] = [
    "the arguments and connections of other users' processes",
    "processes that started and ended between two samples",
    "connections opened and closed between two samples",
    "UDP sockets without a connected peer",
    "the names behind addresses: no name resolution is seen",
    "who started a process",
    "an interpreter running under another program's name, such as an application run as node",
    "an agent session outside a terminal: its detached children are not told apart from others",
];

/// The level of access a sample is taken at.
pub const LEVEL: &str = "samples without administrator rights";

/// A kind of interpreter and how it is given code on its command line. This is data: a new
/// interpreter is one more row, and nothing here is a rule about one product.
pub struct Interpreter {
    pub kind: &'static str,
    /// The executable's file name, lower case, with a version at its end taken off:
    /// `python3.12` and `Python` are `python`.
    pub names: &'static [&'static str],
    /// Options that take code: a short one also inside a cluster, as in `-lc`; a long one
    /// also as `--eval=…`.
    pub inline: &'static [&'static str],
    /// Options that take a value, so that the value is not taken for a script.
    pub with_value: &'static [&'static str],
    /// A word that, as the first argument that is not an option, means code follows.
    pub subcommand: Option<&'static str>,
}

/// The interpreters seen running on developers' Macs, and nothing else. Their ATT&CK
/// sub-techniques of Command and Scripting Interpreter (T1059): JavaScript (.007) for node,
/// bun and deno, Python (.006), Unix Shell (.004), AppleScript (.002); Ruby and Perl have
/// none of their own.
pub const INTERPRETERS: [Interpreter; 7] = [
    Interpreter {
        kind: "node",
        names: &["node", "bun"],
        inline: &["-e", "--eval", "-p", "--print"],
        with_value: &[
            "-r",
            "--require",
            "--import",
            "--loader",
            "--experimental-loader",
            "-C",
            "--conditions",
            "--input-type",
            "--preload",
        ],
        subcommand: None,
    },
    Interpreter {
        kind: "deno",
        names: &["deno"],
        inline: &[],
        with_value: &[],
        subcommand: Some("eval"),
    },
    Interpreter {
        kind: "python",
        names: &["python"],
        inline: &["-c"],
        with_value: &["-W", "-X"],
        subcommand: None,
    },
    Interpreter {
        kind: "ruby",
        names: &["ruby"],
        inline: &["-e"],
        with_value: &["-r", "-I", "-C", "-E"],
        subcommand: None,
    },
    Interpreter {
        kind: "perl",
        names: &["perl"],
        inline: &["-e", "-E"],
        with_value: &["-I", "-M", "-m"],
        subcommand: None,
    },
    Interpreter {
        kind: "shell",
        names: &["sh", "bash", "zsh", "dash", "ksh"],
        inline: &["-c"],
        with_value: &["-o"],
        subcommand: None,
    },
    Interpreter {
        kind: "osascript",
        names: &["osascript"],
        inline: &["-e"],
        with_value: &["-l", "-s"],
        subcommand: None,
    },
];

/// The interpreter a file name names, if any.
pub fn interpreter(file_name: &str) -> Option<&'static Interpreter> {
    let lower = file_name.to_ascii_lowercase();
    let name = lower.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.iter().find(|i| i.names.contains(&name))
}

/// Whether these arguments, the first one being the program's own name, give the interpreter
/// code. Options are read as getopt reads them, up to the first argument that is not an
/// option: what follows a script's path belongs to the script. An option with a value that
/// the table does not list ends the reading early, so code after it is not seen.
pub fn inline_code(i: &Interpreter, args: &[String]) -> bool {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--" || a == "-" || !a.starts_with('-') {
            return i.subcommand == Some(a.as_str());
        }
        if let Some(long) = a.strip_prefix("--") {
            let name = format!("--{}", long.split('=').next().unwrap_or_default());
            if i.inline.contains(&name.as_str()) {
                return true;
            }
            if i.with_value.contains(&name.as_str()) && !long.contains('=') {
                it.next();
            }
            continue;
        }
        // A cluster of short options: each letter is one, until one that takes a value,
        // which takes the rest of the cluster or else the next argument.
        let letters: Vec<char> = a.chars().skip(1).collect();
        for (n, c) in letters.iter().enumerate() {
            let flag = format!("-{c}");
            if i.inline.contains(&flag.as_str()) {
                return true;
            }
            if i.with_value.contains(&flag.as_str()) {
                if n + 1 == letters.len() {
                    it.next();
                }
                break;
            }
        }
    }
    false
}

/// One process as the reading of the system gives it, before anything is derived.
pub struct Seen {
    pub pid: i32,
    /// Microseconds since the epoch. With the pid it is the identity: a pid reused after a
    /// process ends is another process.
    pub start: i64,
    pub parent: i32,
    /// `None` when the file is gone and nothing else said where it was.
    pub executable: Option<String>,
    /// The kernel's short name, to recognise an interpreter whose file is gone.
    pub name: String,
    /// It has a controlling terminal.
    pub terminal: bool,
    /// Its arguments, read only for an interpreter, and dropped once the shape is derived but
    /// for a process the rule may fire on. `None` for an interpreter whose arguments could not
    /// be read.
    pub args: Option<Vec<String>>,
    /// Read only for an interpreter given code.
    pub around: Around,
}

/// What a process ran in and belongs to, as the system still says once its parent is gone.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Around {
    pub working_directory: Option<String>,
    pub session: Option<Leader>,
    pub group: Option<Leader>,
}

/// The leader of a process's session or group, when it is another process and still runs.
#[derive(Clone, Debug, PartialEq)]
pub struct Leader {
    pub pid: i32,
    pub executable: String,
}

/// One internet socket of a process, with a remote end.
#[derive(Clone, Debug, PartialEq)]
pub struct Connection {
    pub pid: i32,
    pub start: i64,
    /// `tcp` or `udp`; `None` only when a reading from JSON does not give one.
    pub transport: Option<&'static str>,
    /// The TCP state in the header's words, `connected` for UDP.
    pub state: &'static str,
    /// Canonical: an IPv4 address mapped into IPv6 is that IPv4 address.
    pub address: IpAddr,
    /// `None` only when a reading from JSON gives none that fits.
    pub port: Option<u16>,
}

/// What one reading of the system gave.
pub struct Reading {
    pub at: i64,
    pub processes: Vec<Seen>,
    pub connections: Vec<Connection>,
    /// The pids of other users' processes, launchd among them: listed, not read.
    pub other_users: Vec<i32>,
    /// Processes of this user that could not be read.
    pub unreadable: usize,
    /// Processes that ended between the list and their reading.
    pub ended: usize,
    pub sockets_unreadable: usize,
    /// This process's own arguments did not read as it was started with, so no process's
    /// arguments are taken: see `layout_known`.
    pub arguments_layout_unknown: bool,
}

/// A process as the rule reads it: from its command line the derived literal, and for one the
/// rule may fire on the command line cut.
pub struct Process {
    pub pid: i32,
    pub start: i64,
    pub executable: Option<String>,
    pub terminal: bool,
    /// Its parent was launchd or was gone.
    pub detached: bool,
    pub interpreter: Option<&'static Interpreter>,
    /// `Some(INLINE_CODE)` when its arguments gave it code, `None` when they did not;
    /// for an interpreter whose arguments could not be read, see `args_unreadable`.
    pub shape: Option<&'static str>,
    /// Its arguments with their secrets cut, in the store's form, for a detached interpreter
    /// given code and an interpreter connected to a listed address only.
    pub args: Option<Vec<String>>,
    pub around: Around,
    /// Its parent, for a process connected to a listed address, when the parent is another
    /// process of this user in the same reading with a known executable.
    pub parent: Option<Leader>,
}

pub struct Sample {
    pub at: i64,
    pub processes: Vec<Process>,
    pub connections: Vec<Connection>,
    pub other_users: usize,
    pub unreadable: usize,
    pub ended: usize,
    pub sockets_unreadable: usize,
    pub args_unreadable: usize,
    pub arguments_layout_unknown: bool,
}

/// Derives what the rules read from a reading. Every command line in it is dropped but that of a
/// detached interpreter given code and of a process in `listed`, connected to a listed address,
/// which are kept cut. A process in `listed` keeps its parent too.
pub fn derive(r: Reading, listed: &HashSet<(i32, i64)>) -> Sample {
    let alive: HashSet<i32> = r
        .processes
        .iter()
        .map(|p| p.pid)
        .chain(r.other_users.iter().copied())
        .collect();
    // Launchd and other users' processes are not read, so they are no one's parent here. A
    // process with the parent's pid that started after the child bears a pid used again: the
    // parent has ended, and there is none.
    let mut parents: HashMap<i32, Leader> = r
        .processes
        .iter()
        .filter(|p| listed.contains(&(p.pid, p.start)))
        .filter_map(|p| {
            let q = r
                .processes
                .iter()
                .find(|q| q.pid == p.parent && q.start <= p.start)?;
            let executable = q.executable.clone()?;
            Some((
                p.pid,
                Leader {
                    pid: q.pid,
                    executable,
                },
            ))
        })
        .collect();
    let mut args_unreadable = 0;
    let processes = r
        .processes
        .into_iter()
        .map(|p| {
            let file_name = p
                .executable
                .as_deref()
                .and_then(|e| e.rsplit('/').next())
                .unwrap_or(&p.name);
            let kind = interpreter(file_name);
            let args = p.args.filter(|_| !r.arguments_layout_unknown);
            let shape = match (kind, &args) {
                (Some(i), Some(args)) => inline_code(i, args).then_some(INLINE_CODE),
                (Some(_), None) => {
                    args_unreadable += 1;
                    None
                }
                _ => None,
            };
            let detached = p.parent == 1 || !alive.contains(&p.parent);
            let kept = detached && shape.is_some() || listed.contains(&(p.pid, p.start));
            Process {
                pid: p.pid,
                start: p.start,
                executable: p.executable,
                terminal: p.terminal,
                detached,
                interpreter: kind,
                shape,
                // Cut as a published rule's evidence is cut where it is kept (`events::keep`).
                args: args
                    .filter(|_| kept)
                    .map(|a| crate::secrets::Args::raw(&a).store()),
                around: p.around,
                parent: parents.remove(&p.pid),
            }
        })
        .collect();
    Sample {
        at: r.at,
        processes,
        connections: r.connections,
        other_users: r.other_users.len(),
        unreadable: r.unreadable,
        ended: r.ended,
        sockets_unreadable: r.sockets_unreadable,
        args_unreadable,
        arguments_layout_unknown: r.arguments_layout_unknown,
    }
}

/// The connections to any of these addresses, compared in canonical form. The port is not
/// compared: an indicator names an address.
pub fn connections_to<'a>(all: &'a [Connection], addresses: &[IpAddr]) -> Vec<&'a Connection> {
    let wanted: HashSet<IpAddr> = addresses.iter().map(IpAddr::to_canonical).collect();
    all.iter().filter(|c| wanted.contains(&c.address)).collect()
}

/// A file by its path, device, inode, size, and modification and change times.
type FileKey = (String, u64, u64, u64, i64, i64, i64, i64);

/// Who signed an executable, looked up once per file: the key is the path with the file's
/// device, inode, size and times, so a file replaced in place is looked up again. A lookup
/// costs about one to two milliseconds; only tracked processes are looked up.
#[derive(Default)]
pub struct Signers {
    known: HashMap<FileKey, Option<String>>,
    pub looked_up: usize,
}

impl Signers {
    pub fn of(&mut self, path: &str) -> Option<String> {
        let m = std::fs::metadata(path).ok()?;
        let key = (
            path.to_string(),
            m.dev(),
            m.ino(),
            m.size(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        );
        self.known
            .entry(key)
            .or_insert_with(|| {
                self.looked_up += 1;
                codesign::Code::at(Path::new(path))
                    .ok()
                    .and_then(|c| c.signer())
            })
            .clone()
    }
}

/// A tracked process as the rule reads it.
struct Tracked {
    interactive: bool,
    first: i64,
    last: i64,
}

/// The rule: seen in two samples at least `MIN_APART` apart, and never with a terminal.
fn fires(t: &Tracked) -> bool {
    !t.interactive && t.last - t.first >= MIN_APART
}

/// What one sample did, in counts.
pub struct Report {
    pub sample: Sample,
    pub took_ms: u128,
    pub tracked_new: usize,
    pub tracked_again: usize,
    /// Connections to an address on the indicator list.
    pub matched: usize,
    pub findings_opened: usize,
}

/// Where a sample is recorded: its run id, this machine, the home folder, and the store's
/// folder, where the indicator list the last run read is kept.
pub struct At<'a> {
    pub run_id: &'a str,
    pub machine: &'a str,
    pub home: &'a Path,
    pub folder: &'a Path,
}

/// Records a sample: the processes the rule tracks, the connections that match the indicator
/// list, the sample's coverage, and the findings. The watcher calls this on a timer; `immunity
/// sample` calls it once.
pub fn take(
    tx: &Transaction,
    w: &At,
    reading: Reading,
    took: Instant,
    signers: &mut Signers,
) -> Result<Report, Box<dyn std::error::Error>> {
    let addresses = listed_addresses(tx, w.folder)?;
    let listed = connections_to(&reading.connections, &addresses)
        .iter()
        .map(|c| (c.pid, c.start))
        .collect();
    let sample = derive(reading, &listed);
    let took_ms = took.elapsed().as_millis();
    let at = sample.at;
    let (mut tracked_new, mut tracked_again, mut seen) = (0, 0, Vec::new());
    // An executable inside a folder macOS asks permission for is not looked at to learn who
    // signed it: the watcher would touch that folder at every sample. The folders are named
    // in the sample's coverage. The kernel gives the executable's real path.
    let real_home = std::fs::canonicalize(w.home).unwrap_or_else(|_| w.home.to_path_buf());
    let mut guarded = std::collections::BTreeSet::new();
    for p in &sample.processes {
        let (Some(i), Some(shape), Some(path), true) =
            (p.interpreter, p.shape, &p.executable, p.detached)
        else {
            continue;
        };
        let inside = guarded_folder(path, w.home, &real_home);
        if let Some(g) = &inside {
            guarded.insert(g.clone());
        }
        let before: Option<Tracked> = tx
            .query_row(
                "SELECT interactive, first_seen_at, last_seen_at FROM tracked_process
                 WHERE pid = ?1 AND start = ?2",
                params![p.pid, p.start],
                |r| {
                    Ok(Tracked {
                        interactive: r.get(0)?,
                        first: r.get(1)?,
                        last: r.get(2)?,
                    })
                },
            )
            .optional()?;
        let after = match &before {
            Some(t) => {
                tracked_again += 1;
                tx.execute(
                    "UPDATE tracked_process SET last_seen_at = ?3, last_seen_run = ?4,
                            interactive = interactive OR ?5
                     WHERE pid = ?1 AND start = ?2",
                    params![p.pid, p.start, at, w.run_id, p.terminal],
                )?;
                Tracked {
                    interactive: t.interactive || p.terminal,
                    first: t.first,
                    last: at,
                }
            }
            None => {
                tracked_new += 1;
                tx.execute(
                    "INSERT INTO tracked_process (pid, start, executable, interpreter, shape,
                         interactive, code_signature, first_seen_at, first_seen_run,
                         last_seen_at, last_seen_run)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?8, ?9)",
                    params![
                        p.pid,
                        p.start,
                        path,
                        i.kind,
                        shape,
                        p.terminal,
                        if inside.is_some() {
                            None
                        } else {
                            signers.of(path)
                        },
                        at,
                        w.run_id
                    ],
                )?;
                Tracked {
                    interactive: p.terminal,
                    first: at,
                    last: at,
                }
            }
        };
        // Raised once per process: when it first meets the rule.
        if fires(&after) && !before.as_ref().is_some_and(fires) {
            let file = program(w, path);
            let note = sampled(p, |exe| {
                signer(exe, w.home, &real_home, &mut guarded, signers)
            });
            basis(tx, w, at, DETACHED_INLINE, &file, None, shape, note)?;
            seen.push(observed(DETACHED_INLINE, file));
        }
    }
    let matched = match_connections(tx, w, &sample, &addresses, &mut seen, |exe| {
        signer(exe, w.home, &real_home, &mut guarded, signers)
    })?;
    // What has been gone for a day is no longer kept.
    tx.execute(
        "DELETE FROM tracked_process WHERE last_seen_at < ?1",
        [at - KEEP],
    )?;
    tx.execute(
        "DELETE FROM matched_connection WHERE last_seen_at < ?1",
        [at - KEEP],
    )?;
    cover(tx, w, &sample, &guarded)?;
    let findings_opened = crate::findings::detect(tx, w.run_id, at, &seen)?;
    Ok(Report {
        sample,
        took_ms,
        tracked_new,
        tracked_again,
        matched,
        findings_opened,
    })
}

/// The program's file as the store names it: under the home folder relative to it.
fn program(w: &At, path: &str) -> String {
    let shown = path
        .strip_prefix(&format!("{}/", w.home.display()))
        .unwrap_or(path);
    format!("file:{}/{shown}", w.machine)
}

fn observed(kind: &str, file: String) -> Observed {
    Observed {
        change: "new",
        place: kind.to_string(),
        file,
    }
}

/// The folder macOS asks permission for that holds `path`, named under the home folder as HOME
/// gives it: the kernel names an executable by its real path.
fn guarded_folder(path: &str, home: &Path, real_home: &Path) -> Option<PathBuf> {
    crate::guarded::folder_of(Path::new(path), home).or_else(|| {
        crate::guarded::folder_of(Path::new(path), real_home)
            .map(|g| home.join(g.strip_prefix(real_home).unwrap_or(&g)))
    })
}

/// Who signed the executable of a leader or a parent, looked at as a tracked process's is: one
/// inside a folder macOS asks permission for is not, and the folder is named in coverage.
fn signer(
    exe: &str,
    home: &Path,
    real_home: &Path,
    guarded: &mut std::collections::BTreeSet<PathBuf>,
    signers: &mut Signers,
) -> Option<String> {
    match guarded_folder(exe, home, real_home) {
        Some(g) => {
            guarded.insert(g);
            None
        }
        None => signers.of(exe),
    }
}

/// What the entry `sampled` of a process holds: its identity, its command line as `derive` cut
/// it, its folder, and its parent and the leaders of its session and group with who signed them,
/// each where the sample has it. Nothing in it is bounded here: the arguments are bounded by the
/// cut, which withholds whole a command line longer than `secrets::LINE_CAP`, and the paths by
/// the buffers the kernel fills.
fn sampled(p: &Process, mut signed: impl FnMut(&str) -> Option<String>) -> Value {
    let mut leader = |l: &Option<Leader>| {
        l.as_ref().map(|l| {
            json!({ "pid": l.pid, "executable": l.executable, "signed_by": signed(&l.executable) })
        })
    };
    json!({
        "pid": p.pid,
        "start": p.start,
        "args": p.args,
        "working_directory": p.around.working_directory,
        "session_leader": leader(&p.around.session),
        "process_group_leader": leader(&p.around.group),
        "parent": leader(&p.parent),
    })
}

/// What the latest journal entry `sampled` of `kind` that a finding rests on keeps, as `sampled`
/// wrote it, with what was derived or matched, the entry's value, as `value`; `None` when it
/// rests on none, or the entry's text is not a JSON object.
pub fn sampled_note(
    conn: &rusqlite::Connection,
    finding: &str,
    kind: &str,
) -> rusqlite::Result<Option<Value>> {
    let entry: Option<(Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT j.text, j.new_value FROM finding_basis b JOIN journal j ON j.seq = b.journal
             WHERE b.finding = ?1 AND j.entry = 'sampled' AND j.kind = ?2
             ORDER BY j.seq DESC LIMIT 1",
            // Only this kind's entry: a process of the same program that matched an indicator
            // in the same sample as a detached script has one too, linked by its subject.
            params![finding, kind],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((Some(text), value)) = entry else {
        return Ok(None);
    };
    let Ok(Value::Object(mut note)) = serde_json::from_str(&text) else {
        return Ok(None);
    };
    note.insert("value".to_string(), json!(value));
    Ok(Some(Value::Object(note)))
}

/// When a sample last saw the process a finding's entry `sampled` names, by its pid and start,
/// tracked or connected to a listed address, and whether that was the latest sample: `None` once
/// neither is kept (`KEEP`), or the entry does not name it. A sample that did not see it says
/// nothing of whether it ended: a process is not a fact with a lifecycle.
pub fn last_seen(
    conn: &rusqlite::Connection,
    note: &Value,
) -> rusqlite::Result<Option<(i64, bool)>> {
    let (Some(pid), Some(start)) = (note["pid"].as_i64(), note["start"].as_i64()) else {
        return Ok(None);
    };
    let (at, latest): (Option<i64>, Option<bool>) = conn.query_row(
        "SELECT MAX(at), MAX(at) = (SELECT at FROM last_sample WHERE id = 1) FROM (
             SELECT last_seen_at AS at FROM tracked_process WHERE pid = ?1 AND start = ?2
             UNION ALL
             SELECT last_seen_at FROM matched_connection WHERE pid = ?1 AND start = ?2)",
        params![pid, start],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(at.map(|at| (at, latest == Some(true))))
}

/// The journal entry a raise rests on: the program, what was derived or matched, and in `text`
/// what the raise keeps of the process, its identity at least.
#[allow(clippy::too_many_arguments)]
fn basis(
    tx: &Transaction,
    w: &At,
    at: i64,
    kind: &str,
    file: &str,
    predicate: Option<&str>,
    value: &str,
    text: Value,
) -> rusqlite::Result<()> {
    crate::store::put_entity(tx, file)?;
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, predicate,
                              new_value, text)
         VALUES (?1, ?2, 'sampled', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            at,
            w.run_id,
            READER,
            w.machine,
            kind,
            file,
            predicate,
            value,
            text.to_string()
        ],
    )?;
    Ok(())
}

/// The addresses of the `ipv4-addr:value` indicators of the list the last run read, from its
/// saved copy; none when there is no list or it cannot be read now. A `domain-name:value`
/// indicator is not matched: a sample has addresses, not names, and names are not resolved.
fn listed_addresses(tx: &Transaction, folder: &Path) -> rusqlite::Result<Vec<IpAddr>> {
    use crate::indicators;
    Ok(indicators::last_list(tx, folder)?
        .iter()
        .flat_map(|l| &l.matched)
        .filter(|i| i.kind == indicators::IPV4)
        .filter_map(|i| i.value.parse().ok())
        .collect())
}

/// Connections to a listed address, each raised once per process and indicator, its entry
/// `sampled` keeping what the sample read of the process and the connection's port and
/// transport. Returns how many connections matched.
fn match_connections(
    tx: &Transaction,
    w: &At,
    sample: &Sample,
    addresses: &[IpAddr],
    seen: &mut Vec<Observed>,
    mut signed: impl FnMut(&str) -> Option<String>,
) -> rusqlite::Result<usize> {
    use crate::indicators::{self, IPV4, Indicator};
    // Indicators: the list's addresses are matched against the sample's connections here. Of a
    // process's sockets to one address the first in a fixed order is kept, whatever order the
    // sample read them in: the lowest port, then tcp before udp.
    let mut found = connections_to(&sample.connections, addresses);
    found.sort_by_key(|c| (c.pid, c.start, c.address, c.port, c.transport));
    for c in &found {
        let Some(p) = sample
            .processes
            .iter()
            .find(|p| p.pid == c.pid && p.start == c.start)
        else {
            continue;
        };
        let Some(path) = &p.executable else {
            continue;
        };
        let literal = Indicator {
            kind: IPV4,
            value: c.address.to_string(),
        }
        .literal();
        let new = tx.execute(
            "INSERT INTO matched_connection (pid, start, indicator, executable, first_seen_at,
                                            last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT (pid, start, indicator) DO NOTHING",
            params![c.pid, c.start, literal, path, sample.at],
        )? == 1;
        if new {
            let file = program(w, path);
            let mut note = sampled(p, &mut signed);
            note["port"] = json!(c.port);
            note["transport"] = json!(c.transport);
            basis(
                tx,
                w,
                sample.at,
                indicators::MATCHED,
                &file,
                Some("matches_indicator"),
                &literal,
                note,
            )?;
            seen.push(observed(indicators::MATCHED, file));
        } else {
            tx.execute(
                "UPDATE matched_connection SET last_seen_at = ?4
                 WHERE pid = ?1 AND start = ?2 AND indicator = ?3",
                params![c.pid, c.start, literal, sample.at],
            )?;
        }
    }
    Ok(found.len())
}

/// The sample's coverage, one row per kind, in place of the one before, and the counts the
/// status shows. A program or a socket that could not be read makes its kind partial.
fn cover(
    tx: &Transaction,
    w: &At,
    s: &Sample,
    guarded: &std::collections::BTreeSet<PathBuf>,
) -> rusqlite::Result<()> {
    use crate::store::{Cause, Gap, Reading as Covered};
    // What the latest sample did not look into, while there is any.
    tx.execute(
        "DELETE FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3",
        params![READER, w.machine, crate::guarded::KIND],
    )?;
    if !guarded.is_empty() {
        let shown: Vec<String> = guarded
            .iter()
            .map(|g| crate::guarded::shown(g, w.home))
            .collect();
        let reason = format!("{}{}", crate::guarded::NOT_LOOKED_INTO, shown.join(", "));
        let reading = Covered {
            reader: READER,
            scope: w.machine,
            kind: crate::guarded::KIND,
            run_id: w.run_id,
            at: s.at,
            observed_at: s.at,
        };
        crate::store::put_coverage(
            tx,
            &reading,
            "none",
            Some(&reason),
            &Gap::of(Cause::NotGiven),
        )?;
    }
    let layout = s.arguments_layout_unknown.then_some(LAYOUT_UNKNOWN);
    let kinds = [
        (PROGRAMS_KIND, s.unreadable, "programs", layout),
        (CONNECTIONS_KIND, s.sockets_unreadable, "sockets", None),
    ];
    for (kind, failed, why, also) in kinds {
        tx.execute(
            "DELETE FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3",
            params![READER, w.machine, kind],
        )?;
        let reading = Covered {
            reader: READER,
            scope: w.machine,
            kind,
            run_id: w.run_id,
            at: s.at,
            observed_at: s.at,
        };
        let counted = (failed > 0).then(|| format!("{why} that could not be read: {failed}"));
        let reasons: Vec<String> = also
            .map(str::to_string)
            .into_iter()
            .chain(counted)
            .collect();
        if reasons.is_empty() {
            crate::store::put_coverage(tx, &reading, "full", None, &Gap::default())?;
        } else {
            let reason = reasons.join("; ");
            crate::store::put_coverage(
                tx,
                &reading,
                "partial",
                Some(&reason),
                &Gap::of(Cause::Failed),
            )?;
        }
    }
    tx.execute(
        "INSERT INTO last_sample (id, at, processes, connections) VALUES (1, ?1, ?2, ?3)
         ON CONFLICT (id) DO UPDATE SET at = excluded.at, processes = excluded.processes,
             connections = excluded.connections",
        params![s.at, s.processes.len() as i64, s.connections.len() as i64],
    )?;
    Ok(())
}

/// How many programs the latest sample read, or `None` when no sample was taken here.
pub fn last_sampled(conn: &rusqlite::Connection) -> rusqlite::Result<Option<i64>> {
    Ok(last_sample(conn)?.map(|(_, programs, _)| programs))
}

/// When the latest sample was taken, and how many programs and connections it read.
pub fn last_sample(conn: &rusqlite::Connection) -> rusqlite::Result<Option<(i64, i64, i64)>> {
    conn.query_row(
        "SELECT at, processes, connections FROM last_sample WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
}

impl Report {
    /// The contract's `Sample`: counts only, never a command line.
    pub fn message(&self) -> crate::contract::v1::Sample {
        use crate::contract::v1;
        let s = &self.sample;
        let n = |x: usize| x as u64;
        let inline: Vec<&Process> = s.processes.iter().filter(|p| p.shape.is_some()).collect();
        v1::Sample {
            format: 1,
            level: LEVEL.to_string(),
            at: s.at,
            took_ms: u64::try_from(self.took_ms).unwrap_or(u64::MAX),
            processes: Some(v1::SampleProcesses {
                read: n(s.processes.len()),
                unreadable: n(s.unreadable),
                ended_while_read: n(s.ended),
                other_users: n(s.other_users),
            }),
            interpreters: Some(v1::SampleInterpreters {
                seen: n(s
                    .processes
                    .iter()
                    .filter(|p| p.interpreter.is_some())
                    .count()),
                arguments_unreadable: n(s.args_unreadable),
                inline_code: n(inline.len()),
                inline_code_detached: n(inline.iter().filter(|p| p.detached).count()),
            }),
            connections: Some(v1::SampleConnections {
                read: n(s.connections.len()),
                matched_indicators: n(self.matched),
                unreadable: n(s.sockets_unreadable),
            }),
            tracked_new: n(self.tracked_new),
            tracked_again: n(self.tracked_again),
            findings_opened: n(self.findings_opened),
            rule_kind: DETACHED_INLINE.to_string(),
            rule_min_apart_seconds: MIN_APART as u64,
            cannot_see: CANNOT_SEE.iter().map(|c| c.to_string()).collect(),
            ..Default::default()
        }
    }
}

// ---- A reading made of invented processes, for the promise tests: the same path as a reading
// of the system from `derive` on. ----

impl Reading {
    /// A reading from JSON in the shape of `Reading`.
    pub fn from_json(text: &str) -> Result<Reading, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let int = |v: &Value, k: &str| v[k].as_i64().ok_or(format!("{k} is not a number"));
        let count = |k: &str| v[k].as_u64().unwrap_or_default() as usize;
        let leader = |l: &Value| {
            Some(Leader {
                pid: l["pid"].as_i64()? as i32,
                executable: l["executable"].as_str()?.to_string(),
            })
        };
        let mut processes = Vec::new();
        for p in v["processes"].as_array().ok_or("no processes")? {
            processes.push(Seen {
                pid: int(p, "pid")? as i32,
                start: int(p, "start")?,
                parent: int(p, "parent")? as i32,
                executable: p["executable"].as_str().map(str::to_string),
                name: p["name"].as_str().unwrap_or_default().to_string(),
                terminal: p["terminal"].as_bool().unwrap_or_default(),
                args: p["args"].as_array().map(|a| {
                    a.iter()
                        .map(|s| s.as_str().unwrap_or_default().to_string())
                        .collect()
                }),
                around: Around {
                    working_directory: p["working_directory"].as_str().map(str::to_string),
                    session: leader(&p["session_leader"]),
                    group: leader(&p["group_leader"]),
                },
            });
        }
        let mut connections = Vec::new();
        for c in v["connections"].as_array().into_iter().flatten() {
            let address: IpAddr = c["address"]
                .as_str()
                .and_then(|a| a.parse().ok())
                .ok_or("an address is not one")?;
            connections.push(Connection {
                pid: int(c, "pid")? as i32,
                start: int(c, "start")?,
                transport: ["tcp", "udp"].into_iter().find(|t| c["transport"] == *t),
                state: "established",
                address: address.to_canonical(),
                port: c["port"].as_u64().and_then(|p| u16::try_from(p).ok()),
            });
        }
        Ok(Reading {
            at: int(&v, "at")?,
            processes,
            connections,
            other_users: v["other_users"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p.as_i64().map(|p| p as i32))
                .collect(),
            unreadable: count("unreadable"),
            ended: count("ended"),
            sockets_unreadable: count("sockets_unreadable"),
            arguments_layout_unknown: v["arguments_layout_unknown"].as_bool() == Some(true),
        })
    }
}

// ---- The reading of the system. ----

/// `PROC_ALL_PIDS` and `PROC_UID_ONLY`, `sys/proc_info.h` lines 51 and 54: every pid, and
/// the pids of one effective user.
const PROC_ALL_PIDS: u32 = 1;
const PROC_UID_ONLY: u32 = 4;
/// `PROC_FLAG_CONTROLT`, line 110: "Has a controlling terminal".
const PROC_FLAG_CONTROLT: u32 = 0x80;
/// `PROC_PIDFDSOCKETINFO`, line 777.
const PROC_PIDFDSOCKETINFO: c_int = 3;
/// `SOCKINFO_IN` and `SOCKINFO_TCP`, lines 529 and 530.
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
/// `INI_IPV4` and `INI_IPV6`, lines 366 and 367.
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
/// `TSI_S_CLOSED` to `TSI_S_TIME_WAIT`, lines 414 to 424, in order.
const TCP_STATES: [&str; 11] = [
    "closed",
    "listen",
    "syn sent",
    "syn received",
    "established",
    "close wait",
    "fin wait 1",
    "closing",
    "last ack",
    "fin wait 2",
    "time wait",
];

/// `struct proc_fileinfo`, line 248.
#[repr(C)]
struct ProcFileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

/// `struct sockbuf_info`, line 517.
#[repr(C)]
struct SockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

/// `struct in_sockinfo`, line 374. The two address unions are 16 bytes: `in4in6_addr` keeps
/// an IPv4 address in its last four, `in6_addr` is the whole.
#[repr(C)]
struct InSockinfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: [u8; 16],
    insi_laddr: [u8; 16],
    insi_v4: u8,
    insi_v6: [u32; 3],
}

/// `struct tcp_sockinfo`, line 427.
#[repr(C)]
struct TcpSockinfo {
    tcpsi_ini: InSockinfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

/// The union `soi_proto`: only the two members read here are named; its size is that of the
/// largest member, 528 bytes in the SDK.
#[repr(C)]
union SoiProto {
    pri_in: std::mem::ManuallyDrop<InSockinfo>,
    pri_tcp: std::mem::ManuallyDrop<TcpSockinfo>,
    size: [u64; 66],
}

/// `struct socket_info`, line 538.
#[repr(C)]
struct SocketInfo {
    soi_stat: libc::vinfo_stat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: i32,
    rfu_1: u32,
    soi_proto: SoiProto,
}

/// `struct socket_fdinfo`, line 569.
#[repr(C)]
struct SocketFdinfo {
    pfi: ProcFileinfo,
    psi: SocketInfo,
}

// The SDK's own sizes and offsets, as clang gives them for these headers: a declaration that
// does not match does not build.
const _: () = {
    assert!(size_of::<SocketFdinfo>() == 792);
    assert!(size_of::<SocketInfo>() == 768);
    assert!(size_of::<InSockinfo>() == 80);
    assert!(size_of::<TcpSockinfo>() == 120);
    assert!(offset_of!(SocketFdinfo, psi) == 24);
    assert!(offset_of!(SocketInfo, soi_family) == 160);
    assert!(offset_of!(SocketInfo, soi_kind) == 232);
    assert!(offset_of!(SocketInfo, soi_proto) == 240);
    assert!(offset_of!(InSockinfo, insi_vflag) == 24);
    assert!(offset_of!(InSockinfo, insi_faddr) == 32);
    assert!(offset_of!(TcpSockinfo, tcpsi_state) == 80);
};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The pids `proc_listpids` gives for a kind of list; it returns bytes.
fn pids(kind: u32, arg: u32) -> Vec<i32> {
    // SAFETY: with no buffer the call returns the size it needs.
    let need = unsafe { libc::proc_listpids(kind, arg, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Vec::new();
    }
    // Room for processes started since the size was given.
    let mut buf = vec![0i32; need as usize / 4 + 256];
    let size = (buf.len() * 4) as c_int;
    // SAFETY: the buffer is valid for `size` bytes.
    let got = unsafe { libc::proc_listpids(kind, arg, buf.as_mut_ptr().cast(), size) };
    buf.truncate(got.max(0) as usize / 4);
    buf.retain(|&p| p > 0);
    buf
}

/// The executable's path, as the kernel gives it.
fn path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is valid for its length.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

/// The folder a process runs in, `pvi_cdir` of `PROC_PIDVNODEPATHINFO`; `None` when it cannot be
/// read or the kernel gives no path.
fn working_directory(pid: i32) -> Option<String> {
    // SAFETY: all-zero is a valid value of this plain C structure.
    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let want = size_of::<libc::proc_vnodepathinfo>() as c_int;
    // SAFETY: `info` is valid for `want` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            (&mut info as *mut libc::proc_vnodepathinfo).cast(),
            want,
        )
    };
    let path = c_name(info.pvi_cdir.vip_path.as_flattened());
    (n == want && !path.is_empty()).then_some(path)
}

/// The leader of a process's session or group, by the id the kernel gives for it, when it is
/// another process than launchd and still runs. The kernel gives no new process a pid that a
/// session or a group still bears (`forkproc` in XNU's `kern_fork.c`), so a process with that
/// pid is the leader.
fn leader(pid: i32, id: i32) -> Option<Leader> {
    if id <= 1 || id == pid {
        return None;
    }
    path(id).map(|executable| Leader {
        pid: id,
        executable,
    })
}

/// `kern.argmax`: the largest argument area, the buffer `KERN_PROCARGS2` needs.
fn argmax() -> usize {
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut value: c_int = 0;
    let mut size = size_of::<c_int>();
    // SAFETY: `value` is valid for `size` bytes.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut value as *mut c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if r == 0 && value > 0 {
        value as usize
    } else {
        1 << 20
    }
}

/// The area `KERN_PROCARGS2` gives: the argument count as an `int`, the path the program was
/// started by, then the arguments, then the environment, each ending in a zero byte. The path
/// with its zero byte is padded with zero bytes to a multiple of eight, as the kernel aligns it
/// to a pointer. No system function parses it; this is the layout Apple's `ps` reads, except
/// that `ps` skips every zero byte after the path, so an empty first argument would read as
/// padding there. An empty argument is a string of length zero. Exactly the count of strings
/// after the padding are taken, and the environment is never read. Only zero bytes are skipped
/// as padding, and no further than that multiple, so on a kernel that pads less no argument
/// loses its first bytes. No system function parses
/// this area, so a later kernel could lay it out otherwise and shift every argument without a
/// word: each reading first reads its own process's arguments through this code and checks them
/// against the ones it was started with (`layout_known`), and takes no arguments when they
/// differ.
fn parse_procargs(b: &[u8]) -> Option<(String, Vec<String>)> {
    let argc = i32::from_ne_bytes(b.get(..4)?.try_into().ok()?);
    let rest = &b[4..];
    let end = rest.iter().position(|&c| c == 0)?;
    let exec = String::from_utf8_lossy(&rest[..end]).into_owned();
    let pad = (end + 1).next_multiple_of(8) - (end + 1);
    let rest = &rest[end + 1..];
    let zeros = rest.iter().take(pad).take_while(|&&c| c == 0).count();
    let mut rest = &rest[zeros..];
    let mut args = Vec::new();
    for _ in 0..argc.max(0) {
        let end = rest.iter().position(|&c| c == 0)?;
        args.push(String::from_utf8_lossy(&rest[..end]).into_owned());
        rest = &rest[end + 1..];
    }
    Some((exec, args))
}

/// Why no process's arguments are taken in a reading.
const LAYOUT_UNKNOWN: &str = "arguments not read: this program's own arguments, read from the \
     kernel's argument area, are not the ones it was started with, so that area's layout is not \
     the one this build knows";

/// Whether this process's own arguments, as `arguments` read them, are the ones it was started
/// with. When they are not, the layout `parse_procargs` reads is not the kernel's.
fn layout_known(read: Option<(String, Vec<String>)>, own: impl Iterator<Item = OsString>) -> bool {
    let own: Vec<String> = own.map(|a| a.to_string_lossy().into_owned()).collect();
    read.is_some_and(|(_, args)| args == own)
}

/// Where a process's executable is: where the kernel says, or else, when its file is gone, the
/// absolute path it was started by.
fn where_from(kernel: Option<String>, started_by: String) -> Option<String> {
    kernel.or(Some(started_by).filter(|p| p.starts_with('/')))
}

/// A process's start path and arguments. The bytes read are zeroed before the buffer is used
/// again or dropped.
fn arguments(pid: i32, buf: &mut [u8]) -> Option<(String, Vec<String>)> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = buf.len();
    // SAFETY: the buffer is valid for `size` bytes; the call writes at most that and says how
    // much it wrote.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    let read = buf.get_mut(..size.min(buf.len()))?;
    let out = if r == 0 { parse_procargs(read) } else { None };
    read.fill(0);
    out
}

fn c_name(raw: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = raw
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The internet sockets of a process that have a remote end. Returns them and how many sockets
/// could not be read.
fn sockets(pid: i32, start: i64) -> (Vec<Connection>, usize) {
    let fd_size = size_of::<libc::proc_fdinfo>();
    // SAFETY: with no buffer the call returns the size it needs.
    let need =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return (Vec::new(), 0);
    }
    let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(need as usize / fd_size + 32);
    let size = (fds.capacity() * fd_size) as c_int;
    // SAFETY: the buffer is valid for `size` bytes, and the call says how many it wrote.
    let got =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), size) };
    // SAFETY: the kernel wrote `got` bytes of whole entries.
    unsafe { fds.set_len(got.max(0) as usize / fd_size) };
    let (mut out, mut failed) = (Vec::new(), 0);
    for fd in fds
        .iter()
        .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
    {
        // SAFETY: all-zero is a valid value of these plain C structures.
        let mut info: SocketFdinfo = unsafe { std::mem::zeroed() };
        let want = size_of::<SocketFdinfo>() as c_int;
        // SAFETY: `info` is valid for `want` bytes.
        let n = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDSOCKETINFO,
                (&mut info as *mut SocketFdinfo).cast::<c_void>(),
                want,
            )
        };
        if n != want {
            // A socket closed since the list is not a failure.
            failed += usize::from(errno() != libc::EBADF);
            continue;
        }
        if let Some(c) = connection(&info.psi, pid, start) {
            out.push(c);
        }
    }
    (out, failed)
}

/// The remote end of an internet socket, if it has one.
fn connection(s: &SocketInfo, pid: i32, start: i64) -> Option<Connection> {
    if ![libc::AF_INET, libc::AF_INET6].contains(&s.soi_family) {
        return None;
    }
    // SAFETY: both kinds begin with an `in_sockinfo`, which the kernel filled for them.
    let (ini, state) = match s.soi_kind {
        SOCKINFO_TCP => {
            let tcp = unsafe { &s.soi_proto.pri_tcp };
            let state = usize::try_from(tcp.tcpsi_state).ok();
            (
                &tcp.tcpsi_ini,
                state.and_then(|s| TCP_STATES.get(s)).copied()?,
            )
        }
        SOCKINFO_IN if s.soi_protocol == libc::IPPROTO_UDP => {
            (unsafe { &*s.soi_proto.pri_in }, "connected")
        }
        _ => return None,
    };
    // The port is kept in network order in the low 16 bits.
    let port = u16::from_be(ini.insi_fport as u16);
    let address = if ini.insi_vflag & INI_IPV4 != 0 {
        let a: [u8; 4] = ini.insi_faddr[12..].try_into().ok()?;
        IpAddr::V4(Ipv4Addr::from(a))
    } else if ini.insi_vflag & INI_IPV6 != 0 {
        IpAddr::V6(Ipv6Addr::from(ini.insi_faddr)).to_canonical()
    } else {
        return None;
    };
    (port != 0 && !address.is_unspecified()).then_some(Connection {
        pid,
        start,
        transport: Some(if s.soi_kind == SOCKINFO_TCP {
            "tcp"
        } else {
            "udp"
        }),
        state,
        address,
        port: Some(port),
    })
}

/// Reads this user's processes and their internet sockets now.
pub fn read_system(at: i64) -> Reading {
    // SAFETY: plain calls without arguments.
    let uid = unsafe { libc::geteuid() };
    let mine: HashSet<i32> = pids(PROC_UID_ONLY, uid).into_iter().collect();
    let all = pids(PROC_ALL_PIDS, 0);
    let mut r = Reading {
        at,
        processes: Vec::new(),
        connections: Vec::new(),
        other_users: all.iter().filter(|p| !mine.contains(p)).copied().collect(),
        unreadable: 0,
        ended: 0,
        sockets_unreadable: 0,
        arguments_layout_unknown: false,
    };
    let mut buf = vec![0u8; argmax()];
    let own = arguments(std::process::id() as i32, &mut buf);
    r.arguments_layout_unknown = !layout_known(own, std::env::args_os());
    for pid in mine {
        // SAFETY: all-zero is a valid `proc_bsdinfo`.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let want = size_of::<libc::proc_bsdinfo>() as c_int;
        // SAFETY: `info` is valid for `want` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                want,
            )
        };
        if n != want {
            if errno() == libc::ESRCH {
                r.ended += 1;
            } else {
                r.unreadable += 1;
            }
            continue;
        }
        let start = info.pbi_start_tvsec as i64 * 1_000_000 + info.pbi_start_tvusec as i64;
        let name = c_name(&info.pbi_comm);
        let mut executable = path(pid);
        let file_name = executable
            .as_deref()
            .and_then(|e| e.rsplit('/').next())
            .unwrap_or(&name);
        let kind = interpreter(file_name);
        let args = if kind.is_some() {
            arguments(pid, &mut buf).map(|(exec, args)| {
                executable = where_from(executable.take(), exec);
                args
            })
        } else {
            None
        };
        let given_code = kind
            .zip(args.as_deref())
            .is_some_and(|(i, a)| inline_code(i, a));
        let around = if given_code {
            // SAFETY: a plain call; it fails with -1 for a process that has ended.
            let sid = unsafe { libc::getsid(pid) };
            Around {
                working_directory: working_directory(pid),
                session: leader(pid, sid),
                group: leader(pid, info.pbi_pgid as i32),
            }
        } else {
            Around::default()
        };
        let (connections, failed) = sockets(pid, start);
        r.connections.extend(connections);
        r.sockets_unreadable += failed;
        r.processes.push(Seen {
            pid,
            start,
            parent: info.pbi_ppid as i32,
            executable,
            name,
            terminal: info.pbi_flags & PROC_FLAG_CONTROLT != 0,
            args,
            around,
        });
    }
    r
}

#[cfg(test)]
mod tests;
