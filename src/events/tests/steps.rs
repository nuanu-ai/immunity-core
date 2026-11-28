//! Promises of the evaluator's reading of the log in steps (`Reader`): what it read written as it
//! goes, a budget of bytes at a time, with what one reading of the same log concludes.

use super::*;

const NOW: i64 = 1_791_090_000;
/// The rule of high level a search for passwords matches, which raises a finding.
const HIGH: &str = "53b1b378-9b06-4992-b972-dde6e423d2b4";

/// A log file of one run of the collector, started at `hour`.
fn named(hour: u32) -> String {
    format!("exec-20261004T000013-20261004T{hour:02}0000.jsonl")
}

/// A program start that the rule `HIGH` matches.
fn high(seq: u64) -> String {
    exec(seq, OBJECT)
        .replace(
            r#"["git","status","--short"]"#,
            r#"["grep","-r","password","."]"#,
        )
        .replace("/usr/bin/git", "/usr/bin/grep")
        + "\n"
}

/// A program start no shipped rule of high level matches.
fn plain(seq: u64) -> String {
    exec(seq, OBJECT) + "\n"
}

/// A store of its own that holds this Mac, and a whole reading of an empty log an hour before
/// `NOW`, so that a step has a conclusion to leave standing.
fn store(tag: &str) -> (crate::common::Scratch, Connection) {
    let (dir, mut conn) = fresh(tag);
    reading(&mut conn, &installed(&format!("{tag}-empty")), NOW - 3600);
    (dir, conn)
}

/// A store of its own that holds this Mac and no reading of the event level.
fn fresh(tag: &str) -> (crate::common::Scratch, Connection) {
    let dir = crate::common::Scratch::new(tag);
    let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
    let mac =
        "INSERT INTO meta (key, value) VALUES ('machine', 'machine:mac'), ('machine_name', 'mac')";
    conn.execute_batch(mac).unwrap();
    (dir, conn)
}

fn rolled_back(conn: &mut Connection, root: &Path, now: i64) -> Outcome {
    read_in(conn, root, now, false)
}

/// One write of what `r` read since its last, as the evaluator writes it; `commit` false rolls it
/// back, as a write that met a busy store or was killed.
fn write(conn: &mut Connection, r: &mut Reader, now: i64, conclude: bool, commit: bool) -> Outcome {
    let tx = conn.transaction().unwrap();
    crate::store::put_entity(&tx, "machine:mac").unwrap();
    let out = r
        .write(&tx, "events-1", "machine:mac", now, conclude)
        .unwrap();
    let out = out.expect("no other reader read meanwhile");
    if commit {
        tx.commit().unwrap();
        r.wrote();
    } else {
        drop(tx);
        r.reload(conn).unwrap();
    }
    out
}

/// The steps of one catch-up, each of `budget` bytes of whole lines and each committed, the last
/// one concluding, until no line is left: how many writes there were. A reader with no conclusion
/// in the store holds back until it has read every line, as the evaluator does.
fn stepped(conn: &mut Connection, root: &Path, now: i64, budget: u64) -> usize {
    let mut r = Reader::load(conn, root).unwrap();
    let mut n = 0;
    for _ in 0..1000 {
        r.relist(now, budget, |_, _| {});
        if r.holds_back() {
            continue;
        }
        let more = r.more();
        write(conn, &mut r, now, !more, true);
        n += 1;
        if !more {
            return n;
        }
    }
    panic!("a catch-up on a log of a few lines did not end in a thousand reads");
}

/// One step of `r` of `budget` bytes, committed; it concludes when no line is left.
fn step(conn: &mut Connection, r: &mut Reader, now: i64, budget: u64) -> Outcome {
    r.relist(now, budget, |_, _| {});
    let more = r.more();
    write(conn, r, now, !more, true)
}

/// A budget of one byte: a step takes one whole line.
const LINE: u64 = 1;

/// Every row a query gives, each with the query.
fn rows(conn: &Connection, sql: &str) -> Vec<String> {
    let mut stmt = conn.prepare(sql).unwrap();
    let n = stmt.column_count();
    let got = stmt.query_map([], |r| {
        (0..n)
            .map(|i| r.get::<_, rusqlite::types::Value>(i))
            .collect::<rusqlite::Result<Vec<_>>>()
    });
    got.unwrap()
        .map(|r| format!("{sql}: {:?}", r.unwrap()))
        .collect()
}

/// What a store concludes of the log: the places, the sums of the counts, the matches by rule,
/// the findings with their evidence and lines, the numbering, the markers, what arrives, the
/// level's row and the coverage.
fn concluded(conn: &Connection) -> Vec<String> {
    [
        "SELECT name, inode, offset FROM event_file ORDER BY name",
        "SELECT SUM(starts), SUM(lost), SUM(unknown_gaps), SUM(unreadable), SUM(other),
                SUM(removed_cap), SUM(removed_unread) FROM event_count",
        "SELECT SUM(files), SUM(files_lost), SUM(files_unknown_gaps), SUM(files_unreadable)
         FROM event_count",
        "SELECT rule, SUM(matches) FROM rule_match GROUP BY rule ORDER BY rule",
        "SELECT finding, matches FROM rule_finding ORDER BY finding",
        "SELECT finding, args FROM rule_evidence ORDER BY finding, rowid",
        "SELECT f.name, f.inode, r.offset, r.rule, r.finding
         FROM rule_line r JOIN event_file f ON f.id = r.file ORDER BY r.seq",
        "SELECT id, state FROM finding ORDER BY id",
        "SELECT state, written, last_seq, version, said, counted FROM event_level",
        "SELECT last_create, last_rename FROM event_files",
        "SELECT pending FROM event_marks",
        "SELECT kind, keep, kept, filled, stopped, quiet, quiet_from FROM event_arrival
         ORDER BY 1, 2",
        "SELECT kind, completeness, reason, cause FROM coverage WHERE reader = 'events'
         ORDER BY kind",
    ]
    .iter()
    .flat_map(|sql| rows(conn, sql))
    .collect()
}

/// A backlog of four log files and a note of one deleted unread, as a watcher that fell behind
/// meets it: matches, a gap in the numbering, a marker of the filter, lines that cannot be
/// read, a line split at the turn of a file, a restart, file events, and the file being
/// written, with a line not yet finished.
fn backlog(tag: &str) -> crate::common::Scratch {
    let root = installed(tag);
    let marker = "{\"unreadable\":true}\n";
    let file = |seq| created(seq, "/Users/example/a") + "\n";
    let first = high(1) + &plain(3) + marker + &file(1) + "{\"schema_version\":1,";
    write_at(&root, &named(0), &first, NOW - 400);
    let second = plain(6) + "not a line of eslogger\n" + &high(7);
    write_at(&root, &named(1), &second, NOW - 300);
    write_at(&root, &named(2), &(plain(2) + &file(2)), NOW - 200);
    let writing = high(3) + &kept_start(4, NOW - 100, true, false) + "{\"schema";
    write_at(&root, &named(3), &writing, NOW - 100);
    let gone = "exec-20261003T230013-20261003T230000.jsonl";
    let note = format!("{} {gone} 100 cap\n", NOW - 500);
    std::fs::write(root.join(LOG).join(REMOVED), note).unwrap();
    root
}

#[test]
fn a_backlog_read_in_steps_gives_the_matches_counts_losses_and_places_of_one_reading() {
    // An evaluator that fell behind reads a budget at a time and commits each, so that what it
    // read is kept whatever stops it. What it concludes is what one reading of the same log
    // does: the same rows of the record in the same order, the same counts and places.
    let root = backlog("steps-same");
    let (_once_dir, mut once) = store("steps-once");
    let (_steps_dir, mut steps) = store("steps-steps");
    reading(&mut once, &root, NOW);
    assert!(stepped(&mut steps, &root, NOW, LINE) > 4);
    assert_eq!(concluded(&steps), concluded(&once));
    // Not an agreement on nothing: the backlog holds what each count is for.
    let l = level(&steps, NOW).unwrap().unwrap();
    let t = &l.last_day;
    assert_eq!(
        (t.starts, t.lost, t.unknown_gaps, t.unreadable),
        (7, 2, 1, 3)
    );
    assert_eq!((t.removed_cap, t.removed_unread), (1, 1));
    assert_eq!(l.matches_last_day[HIGH], 3);
    assert_eq!(l.files.last_day.files, 2);
    assert_eq!(told(&l.arrivals), ["-", "0", "-"]);
    let recorded = rows(
        &steps,
        "SELECT rule FROM rule_line WHERE rule LIKE '%53b1b378%'",
    );
    assert_eq!(recorded.len(), 3);
}

#[test]
fn losses_counted_since_a_check_or_over_the_day_are_the_same_for_many_rows_of_a_catch_up_as_for_one()
 {
    // A loss holds this Mac in part from the reading that counted it until a full check that
    // began after it has finished, told by the order of the rows; the day counts by their
    // stamps, and rows older than two days are deleted. A catch-up writes as it goes.
    let root = backlog("steps-since");
    let (_once_dir, mut once) = store("steps-since-once");
    let (_steps_dir, mut steps) = store("steps-since-steps");
    reading(&mut once, &root, NOW);
    stepped(&mut steps, &root, NOW, LINE);
    let losses = |conn: &Connection, now: i64| {
        let l = level(conn, now).unwrap().unwrap();
        (l.lost_since_check(), l.since_check, l.last_day, l.files)
    };
    let said = |conn: &Connection, now: i64| format!("{:?}", losses(conn, now));
    assert!(losses(&steps, NOW).0);
    assert_eq!(said(&steps, NOW), said(&once, NOW));
    // A full check begins after the catch-up, reads the log and finishes.
    for conn in [&mut once, &mut steps] {
        crate::store::journal_note(conn, NOW + 10, "check", "run_started", "").unwrap();
        reading(conn, &root, NOW + 10);
        crate::store::journal_note(conn, NOW + 60, "check", "run_finished", "").unwrap();
    }
    assert_eq!(said(&steps, NOW + 60), said(&once, NOW + 60));
    // Two days on, the catch-up's rows are gone in both.
    let later = NOW + KEEP + 1;
    reading(&mut once, &root, later);
    stepped(&mut steps, &root, later, LINE);
    assert!(!losses(&steps, later).0);
    assert_eq!(said(&steps, later), said(&once, later));
}

#[test]
fn rows_of_counts_are_written_in_place_by_ten_seconds_and_never_across_the_start_of_a_check() {
    // What the readers read in ten seconds is one row, written in place, but a row begun before
    // a full check started takes nothing read after it: a loss read after the check began is in a
    // row ordered after its start, whatever the clock says, so the check that finishes holds this
    // Mac in part for it. The next ten seconds begin a row of their own.
    let root = installed("steps-row-seam");
    write_at(&root, &named(0), &plain(1), NOW - 100);
    let (_dir, mut conn) = store("steps-row-seam-store");
    let mut r = Reader::load(&conn, &root).unwrap();
    step(&mut conn, &mut r, NOW, LINE);
    crate::store::journal_note(&conn, NOW, "check", "run_started", "").unwrap();
    // Two program starts lost, read in the same ten seconds as the row before.
    write_at(&root, &named(0), &plain(4), NOW - 50);
    step(&mut conn, &mut r, NOW + 1, LINE);
    write_at(&root, &named(0), &plain(5), NOW - 40);
    step(&mut conn, &mut r, NOW + 2, LINE);
    crate::store::journal_note(&conn, NOW + 3, "check", "run_finished", "").unwrap();
    write_at(&root, &named(0), &plain(6), NOW - 30);
    step(&mut conn, &mut r, NOW + 10, LINE);
    // A clock set back into the ten seconds of a row before the latest begins a row: a row once
    // left behind is never written again.
    write_at(&root, &named(0), &plain(7), NOW - 20);
    step(&mut conn, &mut r, NOW + 20, LINE);
    write_at(&root, &named(0), &plain(8), NOW - 10);
    step(&mut conn, &mut r, NOW + 12, LINE);
    let counted: Vec<(i64, i64)> = conn
        .prepare("SELECT starts, lost FROM event_count ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(counted, [(1, 0), (2, 2), (1, 0), (1, 0), (1, 0)]);
    let l = level(&conn, NOW + 10).unwrap().unwrap();
    assert!(l.lost_since_check(), "{:?}", l.since_check);
    // The running totals hold every count whatever the rows: 6 starts, 2 lost.
    let t = totals(&conn).unwrap();
    assert_eq!((t[0], t[1]), (6, 2));
}

#[test]
fn after_a_step_commits_a_later_step_that_is_rolled_back_or_fails_loses_only_itself() {
    // A write that is rolled back, by a busy store or a kill before its commit, leaves neither
    // its rows of the record nor how far it read; the next reads the same lines again, so each
    // is judged once.
    let root = installed("steps-lose-one");
    for (hour, line) in [(0, high(1)), (1, high(2)), (2, plain(3)), (3, plain(4))] {
        write_at(
            &root,
            &named(hour),
            &line,
            NOW - 400 + 100 * i64::from(hour),
        );
    }
    let (_dir, mut conn) = store("steps-lose-one-store");
    let places = |conn: &Connection| rows(conn, "SELECT name, offset FROM event_file ORDER BY 1");
    let record = |conn: &Connection| rows(conn, "SELECT seq, offset, rule FROM rule_line");
    let mut r = Reader::load(&conn, &root).unwrap();
    assert_eq!(step(&mut conn, &mut r, NOW, LINE).starts, 1);
    let first = (places(&conn), record(&conn));
    assert_eq!((first.0.len(), first.1.len()), (1, 1));
    // The next step is rolled back: it leaves nothing, and the reader takes the store's frontier.
    r.relist(NOW, LINE, |_, _| {});
    assert_eq!(write(&mut conn, &mut r, NOW, false, false).starts, 1);
    assert_eq!((places(&conn), record(&conn)), first);
    // The step after it reads the same line again, and its match is recorded once.
    assert_eq!(step(&mut conn, &mut r, NOW + 10, LINE).starts, 1);
    assert_eq!(places(&conn).len(), 2);
    assert_eq!(record(&conn).len(), 2);
    // A step that fails on a format it does not know takes nothing as read; what came before
    // it stands.
    let unknown = plain(3).replace(r#""schema_version":1"#, r#""schema_version":99"#);
    std::fs::write(root.join(LOG).join(named(2)), unknown).unwrap();
    let failed = step(&mut conn, &mut r, NOW + 20, LINE);
    assert_eq!((failed.state, failed.starts), (FAILED, 0));
    assert_eq!(places(&conn).len(), 2);
    // Once it can be read, the next steps read it and what is left, and every start once.
    std::fs::write(root.join(LOG).join(named(2)), plain(3)).unwrap();
    stepped(&mut conn, &root, NOW + 30, LINE);
    let l = level(&conn, NOW + 30).unwrap().unwrap();
    let t = &l.last_day;
    assert_eq!((t.starts, t.lost, t.unknown_gaps), (4, 0, 0));
    assert_eq!(l.matches_last_day[HIGH], 2);
    assert_eq!(record(&conn).len(), 2);
}

#[test]
fn a_reader_that_finds_the_store_read_on_by_another_writes_nothing_and_reads_from_there() {
    // A full check and the watcher's evaluator can both read the log. A write that finds the
    // store's frontier moved since its reader began writes nothing; the reader takes the store's
    // frontier and reads on from it, so no line is judged twice or skipped.
    let root = installed("steps-two-readers");
    write_at(&root, &named(0), &(high(1) + &plain(2)), NOW - 100);
    let (_dir, mut conn) = store("steps-two-readers-store");
    let mut evaluator = Reader::load(&conn, &root).unwrap();
    evaluator.relist(NOW, u64::MAX, |_, _| {});
    // A full check reads the same lines first and commits.
    reading(&mut conn, &root, NOW);
    let tx = conn.transaction().unwrap();
    assert!(
        evaluator
            .write(&tx, "events-2", "machine:mac", NOW, false)
            .unwrap()
            .is_none()
    );
    drop(tx);
    evaluator.reload(&conn).unwrap();
    write_at(&root, &named(0), &high(3), NOW - 50);
    assert_eq!(step(&mut conn, &mut evaluator, NOW + 1, u64::MAX).starts, 1);
    let l = level(&conn, NOW + 1).unwrap().unwrap();
    assert_eq!((l.last_day.starts, l.matches_last_day[HIGH]), (3, 2));
    assert_eq!(rows(&conn, "SELECT seq FROM rule_line").len(), 2);
}

#[test]
fn a_full_check_reads_every_file_in_its_one_reading_and_keeps_nothing_of_it_when_it_fails() {
    // The full check reads the log inside its own transaction, all of it: nothing it read is
    // kept unless the check commits, its rows of the record among it.
    let root = installed("steps-check");
    for hour in 0..3 {
        write_at(
            &root,
            &named(hour),
            &high(u64::from(hour) + 1),
            NOW - 300 + i64::from(hour),
        );
    }
    let (_dir, mut conn) = fresh("steps-check-store");
    assert_eq!(rolled_back(&mut conn, &root, NOW).starts, 3);
    assert!(rows(&conn, "SELECT name FROM event_file").is_empty());
    assert!(rows(&conn, "SELECT at FROM event_count").is_empty());
    assert!(rows(&conn, "SELECT seq FROM rule_line").is_empty());
    assert_eq!(reading(&mut conn, &root, NOW).starts, 3);
    assert_eq!(rows(&conn, "SELECT name FROM event_file").len(), 3);
    assert_eq!(rows(&conn, "SELECT at FROM event_count").len(), 1);
    assert_eq!(rows(&conn, "SELECT seq FROM rule_line").len(), 3);
}

/// What the status concludes of the event level at `now`: the headline and its reasons, this
/// Mac's state, and the level's state, the time of its reading and its coverage rows.
type Concluded = (i32, Vec<i32>, i32, String, i64, Vec<String>);

fn concluded_at(conn: &Connection, dir: &Path, now: i64) -> Concluded {
    let st = crate::status::state(conn, dir, now).unwrap();
    let store = dir.join("store.db");
    let m = crate::status::message(Some(conn), Some(&st), false, &store, now).unwrap();
    let l = level(conn, now).unwrap().unwrap();
    let coverage = "SELECT kind, completeness, reason, cause FROM coverage
                    WHERE reader = 'events' ORDER BY kind";
    let mac = m.this_mac.map_or(0, |t| t.state);
    let because = m.headline_because;
    (
        m.headline,
        because,
        mac,
        l.state,
        l.read_at,
        rows(conn, coverage),
    )
}

#[test]
fn a_step_with_log_left_leaves_the_conclusion_of_the_last_whole_reading_standing() {
    // No false calm while lines are left unread. The last whole reading found the collector
    // silent; five files arrive, the third with a start a high rule matches. Until the step that
    // reads the last line, the status says what that reading concluded: the state, the time of
    // the reading, the coverage, this Mac and the headline.
    let root = installed("steps-standing");
    let (dir, mut conn) = store("steps-standing-store");
    crate::store::journal_note(&conn, NOW - 60, "check", "run_started", "").unwrap();
    crate::store::journal_note(&conn, NOW - 30, "check", "run_finished", "").unwrap();
    for hour in 0..5 {
        let start = if hour == 2 {
            high(3)
        } else {
            plain(u64::from(hour) + 1)
        };
        write_at(
            &root,
            &named(hour),
            &start,
            NOW - 500 + 100 * i64::from(hour),
        );
    }
    let before = concluded_at(&conn, &dir, NOW);
    assert_eq!(before.3, SILENT);
    let level_said = crate::contract::v1::HeadlineBecause::EventLevel as i32;
    assert!(before.1.contains(&level_said), "{before:?}");
    let mut r = Reader::load(&conn, &root).unwrap();
    for _ in 0..2 {
        assert!(!step(&mut conn, &mut r, NOW, LINE).caught_up);
        assert_eq!(concluded_at(&conn, &dir, NOW), before);
    }
    // The third file's match is a finding at once: louder, never calmer.
    step(&mut conn, &mut r, NOW, LINE);
    let third = concluded_at(&conn, &dir, NOW);
    let needs = crate::contract::v1::Headline::NeedsALook as i32;
    assert_eq!(third.0, needs);
    assert_eq!(
        (&third.3, third.4, &third.5),
        (&before.3, before.4, &before.5)
    );
    step(&mut conn, &mut r, NOW, LINE);
    assert!(step(&mut conn, &mut r, NOW, LINE).caught_up);
    let after = concluded_at(&conn, &dir, NOW);
    assert_eq!((after.3.as_str(), after.4), (RUNNING, NOW));
}

#[test]
fn a_store_with_no_reading_of_the_level_is_written_only_once_its_log_is_read_whole() {
    // With no conclusion of an earlier reading to leave standing, nothing is written of part of
    // the log: the reader holds back until it has read every line, and its first write is whole.
    let root = installed("steps-first");
    for hour in 0..3 {
        let at = NOW - 300 + i64::from(hour);
        write_at(&root, &named(hour), &plain(u64::from(hour) + 1), at);
    }
    let (_dir, mut conn) = fresh("steps-first-store");
    assert_eq!(stepped(&mut conn, &root, NOW, LINE), 1);
    assert_eq!(rows(&conn, "SELECT name FROM event_file").len(), 3);
}

#[test]
fn between_two_steps_the_status_says_no_more_than_the_last_whole_reading() {
    // A step that read the second of three files, with the whole backlog present, leaves the
    // state, the time and the coverage of the reading of the first standing, and what arrives.
    // The losses it counted are said at once, which is louder; the coverage of the day says
    // them from the step that concludes.
    let root = installed("steps-between");
    write_at(&root, &named(0), &plain(1), NOW - 3600);
    let (dir, mut conn) = store("steps-between-store");
    reading(&mut conn, &root, NOW - 3590);
    let before = concluded_at(&conn, &dir, NOW);
    let told_before = told(&arrivals(&conn).unwrap());
    write_at(&root, &named(1), &plain(5), NOW - 200);
    write_at(&root, &named(2), &plain(6), NOW - 100);
    let mut r = Reader::load(&conn, &root).unwrap();
    assert!(!step(&mut conn, &mut r, NOW, LINE).caught_up);
    let between = concluded_at(&conn, &dir, NOW);
    assert_eq!(
        (&between.3, between.4, &between.5),
        (&before.3, before.4, &before.5)
    );
    assert!(
        before.1.iter().all(|b| between.1.contains(b)),
        "{before:?} {between:?}"
    );
    assert_eq!(told(&arrivals(&conn).unwrap()), told_before);
    assert_eq!(rows(&conn, "SELECT name FROM event_file").len(), 2);
    let l = level(&conn, NOW).unwrap().unwrap();
    assert!(l.lost_since_check() && l.last_day.lost == 3);
    step(&mut conn, &mut r, NOW, LINE);
    let after = concluded_at(&conn, &dir, NOW);
    assert_eq!(after.4, NOW);
    assert!(after.5.iter().any(|r| r.contains("partial")), "{after:?}");
}

#[test]
fn a_newer_file_takes_over_as_the_one_being_written_within_a_catch_up() {
    // The file being written moves on with a rotation during a catch-up, and after a full check
    // read between two steps: the lines of the newer file say what arrives, as in one reading of
    // the log as it ends. The older file's lines keep who each process is; the newer file's do
    // not.
    let kept = |seq, at| kept_start(seq, at, true, false);
    for check in [false, true] {
        let root = installed(&format!("steps-rotation-{check}"));
        write_at(&root, &named(0), &plain(1), NOW - 300);
        write_at(&root, &named(1), &kept(2, NOW - 200), NOW - 200);
        let (_dir, mut conn) = store(&format!("steps-rotation-{check}-store"));
        let mut r = Reader::load(&conn, &root).unwrap();
        step(&mut conn, &mut r, NOW, LINE);
        if check {
            reading(&mut conn, &root, NOW);
            r.reload(&conn).unwrap();
        } else {
            write_at(&root, &named(1), &kept(3, NOW - 150), NOW - 150);
        }
        write_at(&root, &named(2), &plain(4), NOW - 100);
        for _ in 0..5 {
            step(&mut conn, &mut r, NOW, LINE);
        }
        assert!(!r.more());
        let (_once_dir, mut once) = store(&format!("steps-rotation-{check}-once"));
        reading(&mut once, &root, NOW);
        let said = told(&arrivals(&conn).unwrap());
        assert_eq!(said, told(&arrivals(&once).unwrap()), "{check}");
        assert_ne!(said, ["-", "0", "-"]);
    }
}

#[test]
fn a_file_emptied_and_written_again_is_another_file_and_its_lines_are_read_from_its_start() {
    // A file emptied on the same inode keeps no place past its end, nor the rows of the record on
    // its earlier lines: once it holds lines again, as many bytes as before, they are read, and
    // the rows that went raise the mark a caller of `immunity matches` is told by.
    let root = installed("steps-emptied");
    write_at(&root, &named(0), &(high(1) + &plain(2)), NOW - 300);
    write_at(&root, &named(1), &plain(3), NOW - 200);
    let (_dir, mut conn) = store("steps-emptied-store");
    reading(&mut conn, &root, NOW - 150);
    let went: i64 = conn
        .query_row("SELECT MAX(seq) FROM rule_line", [], |r| r.get(0))
        .unwrap();
    let first = root.join(LOG).join(named(0));
    let emptied = std::fs::OpenOptions::new()
        .write(true)
        .open(&first)
        .unwrap();
    emptied.set_len(0).unwrap();
    write_at(&root, &named(1), &plain(4), NOW - 120);
    write_at(&root, &named(2), &plain(5), NOW - 110);
    reading(&mut conn, &root, NOW - 100);
    assert_eq!(marks(&conn).unwrap().1, went);
    assert!(rows(&conn, "SELECT seq FROM rule_line").is_empty());
    write_at(&root, &named(0), &(plain(6) + &plain(7)), NOW - 90);
    stepped(&mut conn, &root, NOW + 10, LINE);
    let l = level(&conn, NOW + 10).unwrap().unwrap();
    assert_eq!(l.last_day.starts, 7);
}

#[test]
fn an_empty_file_s_deletion_loses_nothing() {
    // An empty file holds no line to read: deleted later, it was not deleted unread, as after
    // one reading of the log.
    let root = installed("steps-empty");
    write_at(&root, &named(0), &plain(1), NOW - 300);
    write_at(&root, &named(1), "", NOW - 250);
    write_at(&root, &named(2), &plain(2), NOW - 200);
    let (_dir, mut conn) = store("steps-empty-store");
    stepped(&mut conn, &root, NOW, LINE);
    std::fs::remove_file(root.join(LOG).join(named(1))).unwrap();
    let note = format!("{} {} 0 cap\n", NOW + 5, named(1));
    std::fs::write(root.join(LOG).join(REMOVED), note).unwrap();
    reading(&mut conn, &root, NOW + 10);
    let t = level(&conn, NOW + 10).unwrap().unwrap().last_day;
    assert_eq!((t.removed_cap, t.removed_unread), (1, 0));
}

#[test]
fn whether_file_events_are_collected_stays_as_the_last_conclusion_said_until_the_next() {
    // A step with log left neither drops a file-event gap that holds this Mac in part because
    // the record of file events went, nor lets file rules watch because it came: the status
    // and the rules judged say what the last conclusion said until the next.
    let collects = r#"["/usr/bin/eslogger","exec","create","rename"]"#;
    for had in [true, false] {
        let root = installed(&format!("steps-collects-{had}"));
        let record = root.join(COLLECTS);
        std::fs::create_dir_all(record.parent().unwrap()).unwrap();
        let swap = |on: bool| match on {
            true => std::fs::write(&record, collects).unwrap(),
            false => std::fs::remove_file(&record).unwrap(),
        };
        if had {
            swap(true);
        }
        // One file event of three is lost.
        let files = created(1, "/Users/example/a") + "\n" + &created(3, "/Users/example/b") + "\n";
        write_at(&root, &named(0), &(plain(1) + &files), NOW - 3600);
        let (dir, mut conn) = fresh(&format!("steps-collects-{had}-store"));
        reading(&mut conn, &root, NOW - 3590);
        swap(!had);
        write_at(&root, &named(1), &plain(2), NOW - 200);
        write_at(&root, &named(2), &plain(3), NOW - 100);
        let said = |conn: &Connection| {
            let l = level(conn, NOW).unwrap().unwrap();
            let rules = crate::status::rules_now(Some(&l));
            let partly = rules.judged == crate::contract::v1::Judged::Part as i32;
            let status = concluded_at(conn, &dir, NOW);
            let files = format!("{:?}", message(&l).file_events);
            (
                l.lost_since_check(),
                partly,
                format!("{rules:?}"),
                status,
                files,
            )
        };
        let before = said(&conn);
        assert_eq!((before.0, before.1), (had, had));
        let mut r = Reader::load(&conn, &root).unwrap();
        assert!(!step(&mut conn, &mut r, NOW, LINE).caught_up);
        assert_eq!(said(&conn), before, "{had}");
        assert!(step(&mut conn, &mut r, NOW, LINE).caught_up);
        let after = said(&conn);
        assert_eq!((after.0, after.1), (!had, !had));
    }
}

#[test]
fn after_a_downgrade_only_the_file_being_written_tells_what_arrives_whichever_step_reads_it() {
    // No false calm after a downgrade. The earlier collector's file sorts first and is read
    // first; the later collector's file, written before, after it. Once the file being written
    // has been read, the later collector's file is the only one with bytes left, and still says
    // nothing of what arrives, as in one reading.
    let now = NOW;
    let earlier = "exec-20261004T00.jsonl";
    let later = "exec-20261004T000013-20261004T000000.jsonl";
    let kept = kept_start(1, now - 100, true, false);
    let old_file = created(1, "/Users/example/a") + "\n";
    let kept_file = old_file.replace(
        r#"{"executable":{"path":"/usr/bin/curl"}}"#,
        r#"{"executable":{"path":"/usr/bin/curl"},"audit_token":{"pid":402,"pidversion":9402},"start_time":"2026-10-04T00:00:01.900000Z","signing_id":"com.example.tool","codesigning_flags":570522385}"#,
    );
    let down = installed("steps-downgrade");
    write_at(&down, later, &(kept + &kept_file), now - 200);
    write_at(&down, earlier, &old_file, now - 100);
    let (_once_dir, mut once) = store("steps-downgrade-once");
    let (_steps_dir, mut steps) = store("steps-downgrade-steps");
    reading(&mut once, &down, now);
    assert!(stepped(&mut steps, &down, now, LINE) > 1);
    let said = told(&arrivals(&steps).unwrap());
    assert_eq!(said, ["x", "-", "x"]);
    assert_eq!(said, told(&arrivals(&once).unwrap()));
}

#[test]
fn a_file_that_ends_in_a_line_not_yet_finished_does_not_keep_the_files_after_it_waiting() {
    // A file being written can end in a line not yet finished, which no step can read. When it
    // sorts before files left unread, as after a downgrade or a clock set back, the catch-up goes
    // on after it to them, and ends.
    // Two such files, each written after the next, come before a readable one.
    let root = installed("steps-unfinished");
    let earlier = "exec-20261004T00.jsonl";
    write_at(&root, earlier, &(plain(1) + "{\"schema"), NOW - 100);
    write_at(&root, &named(0), &(plain(2) + "{\"sch"), NOW - 200);
    write_at(&root, &named(1), &plain(3), NOW - 300);
    let (_dir, mut conn) = store("steps-unfinished-store");
    stepped(&mut conn, &root, NOW, LINE);
    let sql = "SELECT offset FROM event_file WHERE name = ?1";
    let offset: i64 = conn.query_row(sql, [named(1)], |r| r.get(0)).unwrap();
    assert_eq!(offset, plain(3).len() as i64);
}

/// The record's rows, `seq` and rule, in the order of their numbers.
fn record(conn: &Connection) -> Vec<(i64, String)> {
    conn.prepare("SELECT seq, rule FROM rule_line ORDER BY seq")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn a_file_made_again_on_the_same_inode_and_longer_is_read_from_its_start_and_no_number_is_given_twice()
 {
    // macOS gives a freed inode to the next file made, and rotatelogs empties a file and writes
    // it again: a file of the same name and inode, as long as or longer than where it was read,
    // is another file when its first bytes differ. It is read from its start, the rows on the
    // file it replaced go and raise the mark, and a new row never takes a number given before,
    // also the number of the row that went.
    let root = installed("steps-reused");
    write_at(&root, &named(0), &(high(1) + &plain(2)), NOW - 300);
    let (_dir, mut conn) = store("steps-reused-store");
    reading(&mut conn, &root, NOW - 200);
    let before = record(&conn);
    assert_eq!(before.len(), 1);
    let first = root.join(LOG).join(named(0));
    let inode = std::fs::metadata(&first).unwrap().ino();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&first)
        .unwrap()
        .set_len(0)
        .unwrap();
    write_at(
        &root,
        &named(0),
        &(high(3) + &plain(4) + &plain(5)),
        NOW - 100,
    );
    assert_eq!(std::fs::metadata(&first).unwrap().ino(), inode);
    reading(&mut conn, &root, NOW);
    let after = record(&conn);
    assert_eq!(after.len(), 1, "{after:?}");
    // The mark is past the row that went and below the new one: lines of the first file past
    // its place may never have been read.
    let removed = marks(&conn).unwrap().1;
    assert!(before[0].0 < removed && removed < after[0].0, "{removed}");
    let l = level(&conn, NOW).unwrap().unwrap();
    assert_eq!(l.last_day.starts, 5);
}

#[test]
fn files_sorted_across_a_clock_set_back_keep_their_rows_and_each_line_is_recorded_once() {
    // While the clock was ahead the collector wrote a file of a later hour; set back, it writes
    // to the file of the real hour, earlier by name. Neither file is taken for another: no row
    // goes, and each new match is recorded once, after every row before it.
    let root = installed("steps-clock-back");
    write_at(&root, &named(9), &high(1), NOW - 300);
    let (_dir, mut conn) = store("steps-clock-back-store");
    reading(&mut conn, &root, NOW - 200);
    write_at(&root, &named(0), &high(2), NOW - 100);
    reading(&mut conn, &root, NOW - 50);
    write_at(&root, &named(0), &high(3), NOW - 40);
    reading(&mut conn, &root, NOW);
    let seqs: Vec<i64> = record(&conn).into_iter().map(|(s, _)| s).collect();
    assert_eq!(seqs.len(), 3);
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(marks(&conn).unwrap().1, 0);
}

#[test]
fn a_write_whose_commit_landed_before_the_process_died_is_not_written_again() {
    // Killed after its commit and before it took the commit as its frontier, a reader leaves
    // the store whole: the next one starts from what the store says and records nothing twice.
    let root = installed("steps-kill-after");
    write_at(&root, &named(0), &(high(1) + &plain(2)), NOW - 300);
    let (_dir, mut conn) = store("steps-kill-after-store");
    let mut r = Reader::load(&conn, &root).unwrap();
    r.relist(NOW, u64::MAX, |_, _| {});
    let tx = conn.transaction().unwrap();
    crate::store::put_entity(&tx, "machine:mac").unwrap();
    r.write(&tx, "events-1", "machine:mac", NOW, true)
        .unwrap()
        .unwrap();
    tx.commit().unwrap();
    drop(r);
    let once = (
        record(&conn),
        level(&conn, NOW).unwrap().unwrap().last_day.starts,
    );
    reading(&mut conn, &root, NOW + 10);
    let again = (
        record(&conn),
        level(&conn, NOW + 10).unwrap().unwrap().last_day.starts,
    );
    assert_eq!(once, again);
    assert_eq!(once.1, 2);
}

#[test]
fn a_line_longer_than_the_bound_is_counted_as_not_judged_and_the_lines_after_it_are_read() {
    // No line the filter writes is longer than `LINE`: a longer one is counted as a line that
    // could not be read, so it is never taken for judged, and the reader goes on after it.
    let root = installed("steps-long-line");
    let long = format!("{}\n", "x".repeat(crate::events::LINE + 1));
    write_at(&root, &named(0), &(long + &high(1)), NOW - 300);
    let (_dir, mut conn) = store("steps-long-line-store");
    reading(&mut conn, &root, NOW);
    let t = level(&conn, NOW).unwrap().unwrap().last_day;
    assert_eq!((t.unreadable, t.starts), (1, 1));
    assert_eq!(record(&conn).len(), 1);
}

#[test]
fn lines_read_before_a_file_that_cannot_be_read_are_written_and_not_taken_for_the_whole_log() {
    // A file of a format this version does not know fails the reading at that file. What was
    // read of the files before it is written first, as read up to there and no further: never
    // as a reading that read the log to its end.
    let root = installed("steps-fail-later");
    write_at(&root, &named(0), &high(1), NOW - 300);
    let (_dir, mut conn) = store("steps-fail-later-store");
    reading(&mut conn, &root, NOW - 250);
    write_at(&root, &named(0), &high(2), NOW - 200);
    write_at(
        &root,
        &named(1),
        "{\"schema_version\":2,\"seq_num\":9}\n",
        NOW - 100,
    );
    let mut r = Reader::load(&conn, &root).unwrap();
    r.relist(NOW, u64::MAX, |_, _| {});
    let out = write(&mut conn, &mut r, NOW, false, true);
    assert!(!out.caught_up && out.failed.is_some());
    assert_eq!(record(&conn).len(), 2);
    r.relist(NOW + 1, u64::MAX, |_, _| {});
    let out = write(&mut conn, &mut r, NOW + 1, false, true);
    assert!(out.failed.is_some());
    assert_eq!(record(&conn).len(), 2);
}

#[test]
fn a_pass_that_left_a_file_out_concludes_the_reading_failed_and_never_the_log_read_whole() {
    // No false calm. Over a clean conclusion, the first file holds an ordinary start, the second
    // a line of a format this version does not know, the third a match of a high rule. A full
    // check writes what it read of the first and concludes that the reading failed, with why:
    // never running with full coverage, and the third file still to be read.
    let root = installed("steps-left-out");
    write_at(&root, &named(0), &plain(1), NOW - 400);
    let (_dir, mut conn) = store("steps-left-out-store");
    reading(&mut conn, &root, NOW - 350);
    assert_eq!(state(&conn).unwrap().as_deref(), Some(RUNNING));
    write_at(&root, &named(0), &plain(2), NOW - 300);
    let unknown = "{\"schema_version\":2,\"seq_num\":9}\n";
    write_at(&root, &named(1), unknown, NOW - 200);
    write_at(&root, &named(2), &high(3), NOW - 100);
    let out = reading(&mut conn, &root, NOW);
    assert_eq!(out.state, FAILED);
    assert!(out.failed.is_some() && !out.caught_up);
    let l = level(&conn, NOW).unwrap().unwrap();
    assert_eq!((l.state.as_str(), l.last_day.starts), (FAILED, 2));
    assert!(l.reason.is_some());
    let coverage = rows(
        &conn,
        "SELECT completeness, cause FROM coverage WHERE reader = 'events' AND kind = 'program starts on this Mac, from Apple''s eslogger'",
    );
    assert_eq!(coverage.len(), 1);
    assert!(
        coverage[0].contains("\"none\"") && coverage[0].contains("failed"),
        "{coverage:?}"
    );
    assert!(record(&conn).is_empty());
}

#[test]
fn a_match_read_in_a_file_that_becomes_another_before_it_is_written_is_never_recorded_against_it() {
    // No row of the record names bytes that were not judged. A first reading of a store with no
    // conclusion holds back: it read a match of a high rule at the start of the file and has
    // lines left. The file is replaced by a short one whose start matches nothing, or written
    // again in place, on its inode and longer. The match is not recorded against the new file;
    // its finding is raised from the event read, and the record says a match is gone.
    for how in ["replaced", "in place"] {
        let root = installed(&format!("steps-replaced-held-{}", how.len()));
        write_at(&root, &named(0), &(high(1) + &plain(2)), NOW - 300);
        let (_dir, mut conn) = fresh(&format!("steps-replaced-held-store-{}", how.len()));
        let mut r = Reader::load(&conn, &root).unwrap();
        r.relist(NOW, LINE, |_, _| {});
        assert!(r.holds_back() && r.matched() == 1, "{how}");
        let path = root.join(LOG).join(named(0));
        match how {
            "replaced" => {
                std::fs::remove_file(&path).unwrap();
                write_at(&root, &named(0), &plain(3), NOW - 100);
            }
            _ => std::fs::write(&path, plain(3) + &plain(4) + &plain(5)).unwrap(),
        }
        r.relist(NOW, u64::MAX, |_, _| {});
        assert!(!r.holds_back(), "{how}");
        write(&mut conn, &mut r, NOW, true, true);
        assert!(record(&conn).is_empty(), "{how}");
        let evidence: i64 = conn
            .query_row("SELECT COUNT(*) FROM rule_evidence", [], |r| r.get(0))
            .unwrap();
        assert_eq!(evidence, 1, "{how}");
        let (given, removed) = marks(&conn).unwrap();
        assert!(removed > 0 && removed == given, "{how}: {given} {removed}");
        assert_eq!(removed_unread(&conn, NOW), 1, "{how}");
    }
}

#[test]
fn a_line_read_again_that_is_not_the_line_judged_is_gone() {
    // A row of the record keeps the hash of the line judged: a line written again in place, on
    // the same inode and at the same offset, is not the event the row is about.
    let root = installed("steps-line-hash");
    write_at(&root, &named(0), &high(1), NOW - 300);
    let (_dir, mut conn) = store("steps-line-hash-store");
    reading(&mut conn, &root, NOW - 200);
    let row = recorded_after(&conn, 0, 10).unwrap().remove(0);
    let path = root.join(LOG).join(named(0));
    assert!(matches!(
        at_line(&root, &row.at, row.inode, &row.line),
        Ok(AtLine::Event(..))
    ));
    let other = high(1).replace("password", "passw0rd");
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    std::os::unix::fs::FileExt::write_all_at(&f, other.as_bytes(), 0).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), row.inode);
    assert!(matches!(
        at_line(&root, &row.at, row.inode, &row.line),
        Ok(AtLine::Gone)
    ));
}

/// What the readings counted as log files deleted before they were read to their end.
fn removed_unread(conn: &Connection, now: i64) -> i64 {
    level(conn, now).unwrap().unwrap().last_day.removed_unread
}

#[test]
fn a_file_that_leaves_or_becomes_another_before_it_was_known_read_to_its_end_counts_deleted_unread()
{
    // When unsure, the loss is counted, in the pass that sees it. The file being written was read
    // up to a line; a match is written after it; then the file is replaced, emptied or deleted
    // with no note, before a reader comes back. No line after the place was read, and nothing in
    // the log tells how much went: each counts as a file deleted unread at once, so no conclusion
    // of that pass says nothing was lost, and once only.
    for how in ["replaced", "emptied", "deleted"] {
        let root = installed(&format!("steps-unsure-{how}"));
        write_at(&root, &named(0), &plain(1), NOW - 300);
        let (_dir, mut conn) = store(&format!("steps-unsure-{how}-store"));
        reading(&mut conn, &root, NOW - 250);
        write_at(&root, &named(0), &high(2), NOW - 200);
        let path = root.join(LOG).join(named(0));
        match how {
            "replaced" => {
                std::fs::remove_file(&path).unwrap();
                write_at(&root, &named(0), "", NOW - 100);
            }
            "emptied" => std::fs::write(&path, "").unwrap(),
            _ => std::fs::remove_file(&path).unwrap(),
        }
        reading(&mut conn, &root, NOW - 50);
        let marked = removed_unread(&conn, NOW);
        reading(&mut conn, &root, NOW);
        assert_eq!((marked, removed_unread(&conn, NOW)), (1, 1), "{how}");
        assert!(record(&conn).is_empty(), "{how}");
    }
}

#[test]
fn a_file_read_to_its_end_once_its_hour_was_over_loses_nothing_when_it_leaves_with_no_note() {
    // rotatelogs writes no more to a file once a later one is written: read to its length
    // then, nothing of it is left unread, whatever becomes of it.
    // That holds of a file read to its length while it was the one being written, once a later
    // file is written and nothing more came to it.
    for later_first in [true, false] {
        let root = installed(&format!("steps-ended-{later_first}"));
        write_at(&root, &named(0), &plain(1), NOW - 300);
        let (_dir, mut conn) = store(&format!("steps-ended-{later_first}-store"));
        if !later_first {
            reading(&mut conn, &root, NOW - 250);
        }
        write_at(&root, &named(1), &plain(2), NOW - 200);
        reading(&mut conn, &root, NOW - 150);
        std::fs::remove_file(root.join(LOG).join(named(0))).unwrap();
        reading(&mut conn, &root, NOW - 100);
        reading(&mut conn, &root, NOW);
        assert_eq!(removed_unread(&conn, NOW), 0, "{later_first}");
        assert_eq!(rows(&conn, "SELECT name FROM event_file").len(), 1);
    }
}

#[test]
fn a_batch_read_from_one_generation_is_never_written_against_a_later_one_of_the_same_name_inode_and_length()
 {
    // The frontier a writer compares names each file's generation. A reader reads a match past
    // the place it loaded; before it writes, the file leaves and full checks see it gone, then
    // back on the same inode cut to the place, read again as another generation. A line of the
    // same length goes after it. The reader's batch is not written: it reads again from the
    // store's frontier, and the line in place of its match is the one judged.
    let root = installed("steps-generation");
    write_at(&root, &named(0), &plain(1), NOW - 300);
    let (_dir, mut conn) = store("steps-generation-store");
    reading(&mut conn, &root, NOW - 250);
    let mut r = Reader::load(&conn, &root).unwrap();
    write_at(&root, &named(0), &high(2), NOW - 200);
    r.relist(NOW - 200, u64::MAX, |_, _| {});
    assert_eq!(r.matched(), 1);
    let (path, away) = (root.join(LOG).join(named(0)), root.join("away"));
    std::fs::rename(&path, &away).unwrap();
    reading(&mut conn, &root, NOW - 150);
    std::fs::rename(&away, &path).unwrap();
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(plain(1).len() as u64).unwrap();
    reading(&mut conn, &root, NOW - 100);
    let other = plain(2) + &" ".repeat(high(2).len() - plain(2).len());
    let other = other.replacen('\n', "", 1) + "\n";
    assert_eq!(other.len(), high(2).len());
    std::fs::write(&path, plain(1) + &other).unwrap();
    let tx = conn.transaction().unwrap();
    assert!(
        r.write(&tx, "events-1", "machine:mac", NOW, false)
            .unwrap()
            .is_none()
    );
    drop(tx);
    r.reload(&conn).unwrap();
    step(&mut conn, &mut r, NOW, u64::MAX);
    assert!(record(&conn).is_empty());
    assert_eq!(totals(&conn).unwrap()[0], 3);
}

#[test]
fn a_loss_in_a_row_of_counts_stays_in_the_last_day_until_a_day_after_it_was_read() {
    // Rows of counts are kept by ten seconds: a row bears its latest write, so a loss read late
    // in its ten seconds is in "the last day" a whole day after it was read, never less.
    let root = installed("steps-row-stamp");
    write_at(&root, &named(0), &plain(1), NOW - 100);
    let (_dir, mut conn) = store("steps-row-stamp-store");
    let mut r = Reader::load(&conn, &root).unwrap();
    step(&mut conn, &mut r, NOW + 1, LINE);
    write_at(&root, &named(0), &plain(4), NOW - 50);
    step(&mut conn, &mut r, NOW + 9, LINE);
    assert_eq!(rows(&conn, "SELECT id FROM event_count").len(), 1);
    let l = level(&conn, NOW + 9 + DAY).unwrap().unwrap();
    assert_eq!(l.last_day.lost, 2);
}

/// Takes the collector away from `root`, its launch daemon and its log, as an uninstall does.
fn uninstall(root: &Path) {
    std::fs::remove_file(root.join(PLIST)).unwrap();
    std::fs::remove_dir_all(root.join(LOG)).unwrap();
}

#[test]
fn a_line_left_unread_when_the_collector_was_removed_tells_an_older_place_gone_and_loses_nothing_counted()
 {
    // A caller holds a place after every row; a matching line is written past the place read and
    // not read; the person removes the event level, a reading concludes it not installed, and the
    // level is installed again. The line was never judged: a caller whose place is older is told
    // gone. The uninstall took it, so no file counts as deleted unread. A full check and the
    // evaluator write the same.
    for watcher in [false, true] {
        let tag = format!("steps-uninstall-unread-{watcher}");
        let root = installed(&tag);
        write_at(&root, &named(0), &plain(1), NOW - 300);
        let (_dir, mut conn) = store(&format!("{tag}-store"));
        let mut r = Reader::load(&conn, &root).unwrap();
        let mut read = |conn: &mut Connection, at: i64| match watcher {
            true => drop(step(conn, &mut r, at, u64::MAX)),
            false => drop(reading(conn, &root, at)),
        };
        read(&mut conn, NOW - 250);
        let place = marks(&conn).unwrap().0;
        write_at(&root, &named(0), &high(2), NOW - 200);
        uninstall(&root);
        read(&mut conn, NOW - 150);
        assert_eq!(level(&conn, NOW).unwrap().unwrap().state, NOT_INSTALLED);
        std::fs::create_dir_all(root.join(LOG)).unwrap();
        std::fs::write(root.join(PLIST), "<plist/>").unwrap();
        write_at(&root, &named(1), &plain(1), NOW - 100);
        read(&mut conn, NOW);
        assert!(marks(&conn).unwrap().1 > place, "{watcher}");
        assert_eq!(removed_unread(&conn, NOW), 0, "{watcher}");
    }
}

#[test]
fn what_was_read_before_the_collector_was_removed_is_written_with_its_findings_and_losses() {
    // The evaluator read a match and saw a file deleted unread, and had not written them, when
    // the collector was removed: its write says not installed and writes them all the same, the
    // finding raised from the event read and the loss counted; the match's file left, so its row
    // is not recorded and the record says a match is gone.
    let root = installed("steps-uninstall-batch");
    write_at(&root, &named(0), &plain(1), NOW - 300);
    write_at(&root, &named(1), &plain(2), NOW - 290);
    let (_dir, mut conn) = store("steps-uninstall-batch-store");
    reading(&mut conn, &root, NOW - 250);
    let given = marks(&conn).unwrap().0;
    let mut r = Reader::load(&conn, &root).unwrap();
    write_at(&root, &named(0), &high(3), NOW - 280);
    std::fs::remove_file(root.join(LOG).join(named(1))).unwrap();
    r.relist(NOW - 200, u64::MAX, |_, _| {});
    assert_eq!(r.matched(), 1);
    uninstall(&root);
    r.relist(NOW - 100, u64::MAX, |_, _| {});
    assert_eq!(
        write(&mut conn, &mut r, NOW - 100, true, true).state,
        NOT_INSTALLED
    );
    let evidence: i64 = conn
        .query_row("SELECT COUNT(*) FROM rule_evidence", [], |r| r.get(0))
        .unwrap();
    assert_eq!(evidence, 1);
    assert!(record(&conn).is_empty());
    assert!(marks(&conn).unwrap().1 > given);
    assert_eq!(removed_unread(&conn, NOW), 1);
}

#[test]
fn a_match_not_written_whose_file_read_to_its_end_leaves_tells_an_older_place_gone() {
    // A match was read and not written when its file, read to its end with its hour over, was
    // deleted with a note that it was: no line was lost, but the match is never a row, so a
    // caller whose place is older is told gone.
    let root = installed("steps-dropped-ended");
    write_at(&root, &named(0), &plain(1), NOW - 300);
    write_at(&root, &named(1), &plain(2), NOW - 290);
    let (_dir, mut conn) = store("steps-dropped-ended-store");
    reading(&mut conn, &root, NOW - 250);
    let given = marks(&conn).unwrap().0;
    let mut r = Reader::load(&conn, &root).unwrap();
    write_at(&root, &named(0), &high(3), NOW - 295);
    r.relist(NOW - 200, u64::MAX, |_, _| {});
    assert_eq!(r.matched(), 1);
    std::fs::remove_file(root.join(LOG).join(named(0))).unwrap();
    let size = plain(1).len() + high(3).len();
    let note = format!("{} {} {size} age\n", NOW - 150, named(0));
    std::fs::write(root.join(LOG).join(REMOVED), note).unwrap();
    r.relist(NOW - 100, u64::MAX, |_, _| {});
    write(&mut conn, &mut r, NOW - 100, true, true);
    assert_eq!(removed_unread(&conn, NOW), 0);
    assert!(marks(&conn).unwrap().1 > given);
}

#[test]
fn a_file_written_again_to_the_length_read_is_seen_with_lines_waiting() {
    // What `immunity matches` sees of the log takes a file as the reader does: one emptied and
    // written again to exactly where it was read, with other first bytes, is another file, and
    // its line waits.
    let root = installed("steps-source-head");
    write_at(&root, &named(0), &plain(1), NOW - 300);
    let (_dir, mut conn) = store("steps-source-head-store");
    reading(&mut conn, &root, NOW - 250);
    let waiting = |conn: &Connection| match source_now(conn, &root, NOW).unwrap() {
        Source::Read(l) => l.waiting,
        _ => panic!("the collector is installed"),
    };
    assert!(!waiting(&conn));
    let path = root.join(LOG).join(named(0));
    std::fs::write(&path, plain(2)).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        plain(1).len() as u64
    );
    assert!(waiting(&conn));
}

#[test]
fn a_reader_that_found_the_collector_removed_writes_on_from_its_own_frontier() {
    // The files read leave with an uninstall, in the store and in the reader alike: the reader's
    // next write is not taken for one made after another reader read.
    let root = installed("steps-uninstalled");
    write_at(&root, &named(0), &plain(1), NOW - 300);
    let (_dir, mut conn) = store("steps-uninstalled-store");
    let mut r = Reader::load(&conn, &root).unwrap();
    step(&mut conn, &mut r, NOW - 200, u64::MAX);
    uninstall(&root);
    for at in [NOW - 100, NOW] {
        assert_eq!(step(&mut conn, &mut r, at, u64::MAX).state, NOT_INSTALLED);
    }
}

#[test]
fn a_file_seen_gone_that_comes_back_is_another_file_read_from_its_start_and_counted_unread() {
    // Its rows left when it was seen gone, and nothing tells what happened to it meanwhile: when
    // unsure, the loss is counted, and its lines are read again under a new generation.
    let root = installed("steps-back");
    write_at(&root, &named(0), &plain(1), NOW - 300);
    let (_dir, mut conn) = store("steps-back-store");
    reading(&mut conn, &root, NOW - 250);
    let (path, away) = (root.join(LOG).join(named(0)), root.join("away"));
    std::fs::rename(&path, &away).unwrap();
    reading(&mut conn, &root, NOW - 200);
    std::fs::rename(&away, &path).unwrap();
    reading(&mut conn, &root, NOW);
    assert_eq!(removed_unread(&conn, NOW), 1);
    assert_eq!(totals(&conn).unwrap()[0], 2);
}

#[test]
fn a_note_decides_a_deletion_it_comes_with_and_never_counts_one_already_counted() {
    // tidy.sh deletes a file and then writes its note. A look that sees both counts the file by
    // the size the note gives. A look between the two counts the file when unsure, unless it was
    // read to its end with its hour over, and the note read at the next look counts nothing more.
    for (bytes, between, unread) in [(0, false, 0), (1, false, 1), (0, true, 1), (1, true, 1)] {
        let tag = format!("steps-note-after-{bytes}-{between}");
        let root = installed(&tag);
        write_at(&root, &named(0), &plain(1), NOW - 300);
        let (_dir, mut conn) = store(&format!("{tag}-store"));
        reading(&mut conn, &root, NOW - 250);
        std::fs::remove_file(root.join(LOG).join(named(0))).unwrap();
        if between {
            reading(&mut conn, &root, NOW - 200);
        }
        let size = plain(1).len() + bytes;
        let note = format!("{} {} {size} age\n", NOW - 200, named(0));
        std::fs::write(root.join(LOG).join(REMOVED), note).unwrap();
        reading(&mut conn, &root, NOW);
        reading(&mut conn, &root, NOW);
        assert_eq!(removed_unread(&conn, NOW), unread, "{bytes} {between}");
    }
}

#[test]
fn a_note_of_the_same_second_as_the_last_counted_or_stamped_by_a_clock_set_back_is_counted() {
    // tidy.sh stamps a note with the second its run began, which can be the second of the look
    // before, or earlier than it after the clock was set back: the notes after the last one
    // counted are the new ones, whatever they say of time.
    let root = installed("steps-note-ties");
    write_at(&root, &named(0), &plain(1), NOW - 300);
    let (_dir, mut conn) = store("steps-note-ties-store");
    let notes = root.join(LOG).join(REMOVED);
    let unread = |n: u32| format!("{NOW} exec-20261003T000013-20261003T{n:02}0000.jsonl 9 cap\n");
    std::fs::write(&notes, unread(1)).unwrap();
    reading(&mut conn, &root, NOW);
    let tie = unread(1) + &unread(2);
    std::fs::write(&notes, &tie).unwrap();
    reading(&mut conn, &root, NOW);
    let back = unread(3).replacen(&NOW.to_string(), &(NOW - 3600).to_string(), 1);
    std::fs::write(&notes, tie + &back).unwrap();
    reading(&mut conn, &root, NOW);
    // Kept short by its end, the file holds the last notes only: none is counted twice.
    std::fs::write(&notes, back).unwrap();
    reading(&mut conn, &root, NOW);
    let t = level(&conn, NOW).unwrap().unwrap().last_day;
    assert_eq!((t.removed_cap, t.removed_unread), (3, 3));
}

#[test]
fn a_note_still_being_written_is_counted_once_it_is_whole_and_only_then() {
    // tidy.sh appends a note while a reader may read the file: a line without its newline yet is
    // not a note, and taking it would count it once as it was cut and again once whole.
    let root = installed("steps-note-part");
    let (_dir, mut conn) = store("steps-note-part-store");
    let notes = root.join(LOG).join(REMOVED);
    let note = format!("{NOW} exec-20261003T000013-20261003T010000.jsonl 9 cap\n");
    std::fs::write(&notes, &note[..note.len() - 3]).unwrap();
    reading(&mut conn, &root, NOW);
    std::fs::write(&notes, &note).unwrap();
    reading(&mut conn, &root, NOW);
    let t = level(&conn, NOW).unwrap().unwrap().last_day;
    assert_eq!((t.removed_cap, t.removed_unread), (1, 1));
}
