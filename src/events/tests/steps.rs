//! Promises of the watcher's reading of the log in steps (`Pass`): one log file a step, each
//! committed on its own, with what one reading of the same log concludes.

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

/// A store of its own.
fn store(tag: &str) -> (crate::common::Scratch, Connection) {
    let dir = crate::common::Scratch::new(tag);
    let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
    (dir, conn)
}

/// One reading of the log under `root` at `now`, committed: of every file, or one step of
/// `pass`, which then moves on as the watcher moves it (`crate::read_events_held`).
fn reading(conn: &mut Connection, root: &Path, now: i64, pass: Option<&mut Pass>) -> Outcome {
    let tx = conn.transaction().unwrap();
    crate::store::put_entity(&tx, "machine:mac").unwrap();
    let mut outcome = read(&tx, "events-1", "machine:mac", root, now, pass.as_deref()).unwrap();
    tx.commit().unwrap();
    if let Some(pass) = pass {
        *pass = std::mem::take(&mut outcome.pass);
    }
    outcome
}

/// The same reading, rolled back: one that met a busy store at its commit, or failed after it
/// read. The pass stays where it was.
fn rolled_back(conn: &mut Connection, root: &Path, now: i64, pass: Option<&Pass>) -> Outcome {
    let tx = conn.transaction().unwrap();
    crate::store::put_entity(&tx, "machine:mac").unwrap();
    read(&tx, "events-1", "machine:mac", root, now, pass).unwrap()
}

/// The steps of one pass, each committed, until no log is left: how many there were.
fn stepped(conn: &mut Connection, root: &Path, now: i64) -> usize {
    let mut pass = Pass::default();
    for n in 1..=10 {
        reading(conn, root, now, Some(&mut pass));
        if !pass.more() {
            return n;
        }
    }
    panic!("a pass of a log of a few files did not end in ten steps");
}

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
        "SELECT SUM(files), SUM(lost), SUM(unknown_gaps), SUM(unreadable) FROM event_file_count",
        "SELECT rule, SUM(matches) FROM rule_match GROUP BY rule ORDER BY rule",
        "SELECT finding, matches FROM rule_finding ORDER BY finding",
        "SELECT finding, args FROM rule_evidence ORDER BY finding, rowid",
        "SELECT file, inode, offset, rule, finding FROM rule_line ORDER BY 1, 2, 3, 4",
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
    // A watcher that fell behind reads one file a step and commits each, so that what it read
    // is kept whatever stops it. What it concludes is what one reading of the same log does.
    let root = backlog("steps-same");
    let (_once_dir, mut once) = store("steps-once");
    let (_steps_dir, mut steps) = store("steps-steps");
    reading(&mut once, &root, NOW, None);
    assert_eq!(stepped(&mut steps, &root, NOW), 4);
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
}

#[test]
fn losses_counted_since_a_check_or_over_the_day_are_the_same_for_many_rows_of_a_catch_up_as_for_one()
 {
    // A loss holds this Mac in part from the reading that counted it until a full check that
    // began after it has finished, told by the order of the rows; the day counts by their
    // stamps, and rows older than two days are deleted. A catch-up writes a row a step.
    let root = backlog("steps-since");
    let (_once_dir, mut once) = store("steps-since-once");
    let (_steps_dir, mut steps) = store("steps-since-steps");
    reading(&mut once, &root, NOW, None);
    stepped(&mut steps, &root, NOW);
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
        reading(conn, &root, NOW + 10, None);
        crate::store::journal_note(conn, NOW + 60, "check", "run_finished", "").unwrap();
    }
    assert_eq!(said(&steps, NOW + 60), said(&once, NOW + 60));
    // Two days on, the catch-up's rows are gone in both.
    let later = NOW + KEEP + 1;
    reading(&mut once, &root, later, None);
    reading(&mut steps, &root, later, Some(&mut Pass::default()));
    assert!(!losses(&steps, later).0);
    assert_eq!(said(&steps, later), said(&once, later));
}

#[test]
fn after_a_step_commits_a_later_step_that_is_skipped_or_fails_loses_only_itself() {
    let root = installed("steps-lose-one");
    for (hour, line) in [(0, high(1)), (1, plain(2)), (2, plain(3)), (3, plain(4))] {
        write_at(
            &root,
            &named(hour),
            &line,
            NOW - 400 + 100 * i64::from(hour),
        );
    }
    let (_dir, mut conn) = store("steps-lose-one-store");
    let places = |conn: &Connection| rows(conn, "SELECT name, offset FROM event_file ORDER BY 1");
    let mut pass = Pass::default();
    assert_eq!(reading(&mut conn, &root, NOW, Some(&mut pass)).starts, 1);
    let first = places(&conn);
    assert_eq!(first.len(), 1);
    // The next step meets a busy store at its commit: it is rolled back, and the pass stays
    // where the first step left it.
    assert_eq!(rolled_back(&mut conn, &root, NOW, Some(&pass)).starts, 1);
    assert_eq!(places(&conn), first);
    assert!(pass.more());
    // The step after it reads the same file again: the second, not the first, and not the third
    // before it.
    assert_eq!(
        reading(&mut conn, &root, NOW + 10, Some(&mut pass)).starts,
        1
    );
    let second = places(&conn);
    assert_eq!(second.len(), 2);
    // A step that fails on a format it does not know takes nothing as read; what came before
    // it stands.
    let unknown = plain(3).replace(r#""schema_version":1"#, r#""schema_version":99"#);
    std::fs::write(root.join(LOG).join(named(2)), unknown).unwrap();
    let failed = reading(&mut conn, &root, NOW + 20, Some(&mut pass));
    assert_eq!((failed.state, failed.starts), (FAILED, 0));
    assert!(!pass.more());
    assert_eq!(places(&conn), second);
    // Once it can be read, the next pass reads it and what is left, and every start once.
    std::fs::write(root.join(LOG).join(named(2)), plain(3)).unwrap();
    assert_eq!(stepped(&mut conn, &root, NOW + 30), 2);
    let l = level(&conn, NOW + 30).unwrap().unwrap();
    let t = &l.last_day;
    assert_eq!((t.starts, t.lost, t.unknown_gaps), (4, 0, 0));
    assert_eq!(l.matches_last_day[HIGH], 1);
}

#[test]
fn a_full_check_reads_every_file_in_its_one_reading_and_keeps_nothing_of_it_when_it_fails() {
    // The full check reads the log inside its own transaction, all of it: nothing it read is
    // kept unless the check commits.
    let root = installed("steps-check");
    for hour in 0..3 {
        write_at(
            &root,
            &named(hour),
            &plain(u64::from(hour) + 1),
            NOW - 300 + i64::from(hour),
        );
    }
    let (_dir, mut conn) = store("steps-check-store");
    assert_eq!(rolled_back(&mut conn, &root, NOW, None).starts, 3);
    assert!(rows(&conn, "SELECT name FROM event_file").is_empty());
    assert!(rows(&conn, "SELECT at FROM event_count").is_empty());
    assert_eq!(reading(&mut conn, &root, NOW, None).starts, 3);
    assert_eq!(rows(&conn, "SELECT name FROM event_file").len(), 3);
    assert_eq!(rows(&conn, "SELECT at FROM event_count").len(), 1);
}

#[test]
fn between_two_steps_the_status_says_no_more_than_one_reading_of_the_files_read_so_far() {
    // No false calm while files are left unread. A step that read the first of three files,
    // an hour old, says what one reading of that file said when it was written: the coverage
    // of the day and the losses come from what was read, and a file left unread has no place.
    // The state is the collector's, told from every file's time as one reading tells it. A
    // loss in a later file is said by the step that reads it.
    let root = installed("steps-between");
    write_at(&root, &named(0), &plain(1), NOW - 3600);
    let (_once_dir, mut once) = store("steps-between-once");
    reading(&mut once, &root, NOW - 3590, None);
    write_at(&root, &named(1), &plain(5), NOW - 200);
    write_at(&root, &named(2), &plain(6), NOW - 100);
    let (_steps_dir, mut steps) = store("steps-between-steps");
    let mut pass = Pass::default();
    reading(&mut steps, &root, NOW, Some(&mut pass));
    let said = |conn: &Connection| {
        let l = level(conn, NOW).unwrap().unwrap();
        let coverage = "SELECT kind, completeness, reason, cause FROM coverage
                        WHERE reader = 'events' ORDER BY kind";
        let lost = l.lost_since_check();
        (l.state, lost, l.last_day, rows(conn, coverage))
    };
    assert_eq!(said(&steps), said(&once));
    assert_eq!(rows(&steps, "SELECT name FROM event_file").len(), 1);
    // What arrives is told only by the file being written, which is not read yet: not known.
    assert_eq!(told(&arrivals(&steps).unwrap()), ["-", "-", "-"]);
    reading(&mut steps, &root, NOW, Some(&mut pass));
    let l = level(&steps, NOW).unwrap().unwrap();
    assert!(l.lost_since_check() && l.last_day.lost == 3);
}

#[test]
fn after_a_downgrade_only_the_file_being_written_tells_what_arrives_whichever_step_reads_it() {
    // No false calm after a downgrade. The earlier collector's file sorts first and is read by
    // the first step; the later collector's file, written before, by the next. Once the first
    // step has read the file being written, the later collector's file is the only one with
    // bytes left, and still says nothing of what arrives, as in one reading.
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
    reading(&mut once, &down, now, None);
    assert_eq!(stepped(&mut steps, &down, now), 2);
    let said = told(&arrivals(&steps).unwrap());
    assert_eq!(said, ["x", "-", "x"]);
    assert_eq!(said, told(&arrivals(&once).unwrap()));
}

#[test]
fn a_file_that_ends_in_a_line_not_yet_finished_does_not_keep_the_files_after_it_waiting() {
    // A file being written can end in a line not yet finished, which no step can read. When it
    // sorts before files left unread, as after a downgrade or a clock set back, the pass goes
    // on after it to them, and ends.
    let root = installed("steps-unfinished");
    let earlier = "exec-20261004T00.jsonl";
    write_at(&root, &named(0), &plain(1), NOW - 200);
    write_at(&root, earlier, &(plain(2) + "{\"schema"), NOW - 100);
    let (_dir, mut conn) = store("steps-unfinished-store");
    assert_eq!(stepped(&mut conn, &root, NOW), 2);
    let sql = "SELECT offset FROM event_file WHERE name = ?1";
    let offset: i64 = conn.query_row(sql, [named(0)], |r| r.get(0)).unwrap();
    assert_eq!(offset, plain(1).len() as i64);
}
