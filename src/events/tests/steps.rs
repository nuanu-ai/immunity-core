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

/// A store of its own that holds this Mac, and a whole reading of an empty log an hour before
/// `NOW`, so that a step has a conclusion to leave standing.
fn store(tag: &str) -> (crate::common::Scratch, Connection) {
    let (dir, mut conn) = fresh(tag);
    reading(
        &mut conn,
        &installed(&format!("{tag}-empty")),
        NOW - 3600,
        None,
    );
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
    let (_dir, mut conn) = fresh("steps-check-store");
    assert_eq!(rolled_back(&mut conn, &root, NOW, None).starts, 3);
    assert!(rows(&conn, "SELECT name FROM event_file").is_empty());
    assert!(rows(&conn, "SELECT at FROM event_count").is_empty());
    assert_eq!(reading(&mut conn, &root, NOW, None).starts, 3);
    assert_eq!(rows(&conn, "SELECT name FROM event_file").len(), 3);
    assert_eq!(rows(&conn, "SELECT at FROM event_count").len(), 1);
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
    // No false calm while files are left unread. The last whole reading found the collector
    // silent; five files arrive, the third with a start a high rule matches. Until the step that
    // ends the pass, the status says what that reading concluded, as while one reading of the
    // five went on: the state, the time of the reading, the coverage, this Mac and the headline.
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
    let mut pass = Pass::default();
    for _ in 0..2 {
        reading(&mut conn, &root, NOW, Some(&mut pass));
        assert!(pass.more());
        assert_eq!(concluded_at(&conn, &dir, NOW), before);
    }
    // The third file's match is a finding at once: louder, never calmer.
    reading(&mut conn, &root, NOW, Some(&mut pass));
    let third = concluded_at(&conn, &dir, NOW);
    let needs = crate::contract::v1::Headline::NeedsALook as i32;
    assert_eq!(third.0, needs);
    assert_eq!(
        (&third.3, third.4, &third.5),
        (&before.3, before.4, &before.5)
    );
    reading(&mut conn, &root, NOW, Some(&mut pass));
    reading(&mut conn, &root, NOW, Some(&mut pass));
    assert!(!pass.more());
    let after = concluded_at(&conn, &dir, NOW);
    assert_eq!((after.3.as_str(), after.4), (RUNNING, NOW));
}

#[test]
fn a_store_with_no_reading_of_the_level_reads_its_first_pass_whole() {
    // With no conclusion of an earlier reading to leave standing, nothing is read in part: the
    // first reading of a store is whole, as a reading was before steps.
    let root = installed("steps-first");
    for hour in 0..3 {
        let at = NOW - 300 + i64::from(hour);
        write_at(&root, &named(hour), &plain(u64::from(hour) + 1), at);
    }
    let (_dir, mut conn) = fresh("steps-first-store");
    assert_eq!(stepped(&mut conn, &root, NOW), 1);
    assert_eq!(rows(&conn, "SELECT name FROM event_file").len(), 3);
}

#[test]
fn between_two_steps_the_status_says_no_more_than_the_last_whole_reading() {
    // A step that read the second of three files, with the whole backlog present, leaves the
    // state, the time and the coverage of the reading of the first standing, and what arrives.
    // The losses it counted are said at once, which is louder; the coverage of the day says
    // them from the step that ends the pass.
    let root = installed("steps-between");
    write_at(&root, &named(0), &plain(1), NOW - 3600);
    let (dir, mut conn) = store("steps-between-store");
    reading(&mut conn, &root, NOW - 3590, None);
    let before = concluded_at(&conn, &dir, NOW);
    let told_before = told(&arrivals(&conn).unwrap());
    write_at(&root, &named(1), &plain(5), NOW - 200);
    write_at(&root, &named(2), &plain(6), NOW - 100);
    let mut pass = Pass::default();
    reading(&mut conn, &root, NOW, Some(&mut pass));
    assert!(pass.more());
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
    reading(&mut conn, &root, NOW, Some(&mut pass));
    let after = concluded_at(&conn, &dir, NOW);
    assert_eq!(after.4, NOW);
    assert!(after.5.iter().any(|r| r.contains("partial")), "{after:?}");
}

#[test]
fn a_newer_file_takes_over_as_the_one_being_written_within_a_pass() {
    // The file being written moves on with a rotation during a pass, and after a full check read
    // between two steps: the lines of the newer file say what arrives, as in one reading of the
    // log as it ends. The older file's lines keep who each process is; the newer file's do not.
    let kept = |seq, at| kept_start(seq, at, true, false);
    for check in [false, true] {
        let root = installed(&format!("steps-rotation-{check}"));
        write_at(&root, &named(0), &plain(1), NOW - 300);
        write_at(&root, &named(1), &kept(2, NOW - 200), NOW - 200);
        let (_dir, mut conn) = store(&format!("steps-rotation-{check}-store"));
        let mut pass = Pass::default();
        reading(&mut conn, &root, NOW, Some(&mut pass));
        if check {
            reading(&mut conn, &root, NOW, None);
        } else {
            write_at(&root, &named(1), &kept(3, NOW - 150), NOW - 150);
        }
        write_at(&root, &named(2), &plain(4), NOW - 100);
        for _ in 0..3 {
            if pass.more() {
                reading(&mut conn, &root, NOW, Some(&mut pass));
            }
        }
        assert!(!pass.more());
        let (_once_dir, mut once) = store(&format!("steps-rotation-{check}-once"));
        reading(&mut once, &root, NOW, None);
        let said = told(&arrivals(&conn).unwrap());
        assert_eq!(said, told(&arrivals(&once).unwrap()), "{check}");
        assert_ne!(said, ["-", "0", "-"]);
    }
}

#[test]
fn a_place_that_no_longer_fits_its_file_is_its_start() {
    // A file emptied on the same inode while a step reads another keeps no place past its end:
    // once it holds lines again, as many bytes as before, they are read.
    let root = installed("steps-emptied");
    write_at(&root, &named(0), &(plain(1) + &plain(2)), NOW - 300);
    write_at(&root, &named(1), &plain(3), NOW - 200);
    let (_dir, mut conn) = store("steps-emptied-store");
    reading(&mut conn, &root, NOW - 150, None);
    let first = root.join(LOG).join(named(0));
    let emptied = std::fs::OpenOptions::new()
        .write(true)
        .open(&first)
        .unwrap();
    emptied.set_len(0).unwrap();
    write_at(&root, &named(1), &plain(4), NOW - 120);
    write_at(&root, &named(2), &plain(5), NOW - 110);
    let mut pass = Pass::default();
    reading(&mut conn, &root, NOW, Some(&mut pass));
    assert!(pass.more());
    let sql = "SELECT offset FROM event_file WHERE name = ?1";
    let offset: i64 = conn.query_row(sql, [named(0)], |r| r.get(0)).unwrap();
    assert_eq!(offset, 0);
    write_at(&root, &named(0), &(plain(6) + &plain(7)), NOW - 100);
    reading(&mut conn, &root, NOW, Some(&mut pass));
    stepped(&mut conn, &root, NOW + 10);
    let l = level(&conn, NOW + 10).unwrap().unwrap();
    assert_eq!(l.last_day.starts, 7);
}

#[test]
fn an_empty_file_no_step_reads_is_kept_at_its_start_and_its_deletion_loses_nothing() {
    // An empty file is read to its end as it is: deleted later, it was not deleted unread, as
    // after one reading of the log.
    let root = installed("steps-empty");
    write_at(&root, &named(0), &plain(1), NOW - 300);
    write_at(&root, &named(1), "", NOW - 250);
    write_at(&root, &named(2), &plain(2), NOW - 200);
    let (_dir, mut conn) = store("steps-empty-store");
    assert_eq!(stepped(&mut conn, &root, NOW), 2);
    let sql = "SELECT offset FROM event_file WHERE name = ?1";
    let offset: i64 = conn.query_row(sql, [named(1)], |r| r.get(0)).unwrap();
    assert_eq!(offset, 0);
    std::fs::remove_file(root.join(LOG).join(named(1))).unwrap();
    let note = format!("{} {} 0 cap\n", NOW + 5, named(1));
    std::fs::write(root.join(LOG).join(REMOVED), note).unwrap();
    reading(&mut conn, &root, NOW + 10, None);
    let t = level(&conn, NOW + 10).unwrap().unwrap().last_day;
    assert_eq!((t.removed_cap, t.removed_unread), (1, 0));
}

#[test]
fn whether_file_events_are_collected_stays_as_the_last_whole_reading_said_until_the_pass_ends() {
    // A step with log left neither drops a file-event gap that holds this Mac in part because
    // the record of file events went, nor lets file rules watch because it came: the status
    // and the rules judged say what the last whole reading said until the pass ends.
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
        reading(&mut conn, &root, NOW - 3590, None);
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
        let mut pass = Pass::default();
        reading(&mut conn, &root, NOW, Some(&mut pass));
        assert!(pass.more());
        assert_eq!(said(&conn), before, "{had}");
        reading(&mut conn, &root, NOW, Some(&mut pass));
        assert!(!pass.more());
        let after = said(&conn);
        assert_eq!((after.0, after.1), (!had, !had));
    }
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
    // Two such files, each written after the next, come before a readable one.
    let root = installed("steps-unfinished");
    let earlier = "exec-20261004T00.jsonl";
    write_at(&root, earlier, &(plain(1) + "{\"schema"), NOW - 100);
    write_at(&root, &named(0), &(plain(2) + "{\"sch"), NOW - 200);
    write_at(&root, &named(1), &plain(3), NOW - 300);
    let (_dir, mut conn) = store("steps-unfinished-store");
    assert_eq!(stepped(&mut conn, &root, NOW), 3);
    let sql = "SELECT offset FROM event_file WHERE name = ?1";
    let offset: i64 = conn.query_row(sql, [named(1)], |r| r.get(0)).unwrap();
    assert_eq!(offset, plain(3).len() as i64);
}
