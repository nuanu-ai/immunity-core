//! Promises of what a reading did not read, as the store keeps it (`coverage_unread`), and of the
//! journal's words as vocabulary.

use super::*;
use crate::baseline::Unit;
use crate::look::Look;

/// A row of `coverage_unread`: path, part, cause, how, errno and said.
type Row = (
    Option<String>,
    String,
    String,
    String,
    Option<i32>,
    Option<String>,
);

/// Writes one reading with `gap` into a new store and gives back its cause and its rows.
fn written(completeness: &str, gap: &Gap) -> (Option<String>, Vec<Row>) {
    let dir = crate::common::Scratch::new("unread");
    let mut conn = open_or_make(&dir.join("store.db")).unwrap();
    let tx = conn.transaction().unwrap();
    put_entity(&tx, "machine:mac").unwrap();
    let r = Reading {
        reader: "watched-places",
        scope: "machine:mac",
        kind: "launch agents and daemons",
        run_id: "1900000000-000000000",
        at: 1_900_000_000,
        observed_at: 1_900_000_000,
    };
    put_coverage(&tx, &r, completeness, Some("why"), gap).unwrap();
    tx.commit().unwrap();
    let cause = conn
        .query_row("SELECT cause FROM coverage", [], |r| r.get(0))
        .unwrap();
    let rows = conn
        .prepare(
            "SELECT path, part, cause, how, errno, said FROM coverage_unread
             ORDER BY rowid",
        )
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    (cause, rows)
}

fn cause_of(literal: &str) -> Cause {
    [Cause::Failed, Cause::NoReader, Cause::NotGiven]
        .into_iter()
        .find(|c| c.literal() == literal)
        .unwrap()
}

#[test]
fn a_full_reading_has_no_row_of_what_it_did_not_read_and_any_other_has_one_and_its_cause_is_the_worst_of_them()
 {
    let unit = |p: &str| Some(Unit::whole(p));
    let not_given = NotRead::short(unit("Library/LaunchAgents/a.plist"), Cause::NotGiven);
    let no_reader = NotRead::short(unit("Library/LaunchAgents/b.plist"), Cause::NoReader);
    let with = |cause, rows: &[&NotRead]| Gap {
        not_read: rows.iter().map(|n| (*n).clone()).collect(),
        ..Gap::when(cause)
    };
    let (cause, rows) = written("full", &Gap::default());
    assert_eq!((cause, rows), (None, Vec::new()));
    // Each with how many rows of a unit and how many with none.
    for (completeness, gap, counts) in [
        // A reader with a `Look`: its rows, and the worst of them is its cause.
        (
            "partial",
            with(Some(Cause::NoReader), &[&not_given, &no_reader]),
            (2, 0),
        ),
        // A cause worse than any row's, as of a reader that also failed as a whole.
        ("partial", with(Some(Cause::Failed), &[&not_given]), (1, 1)),
        // A reader with no `Look`.
        ("none", Gap::of(Cause::NotGiven), (0, 1)),
    ] {
        let (cause, rows) = written(completeness, &gap);
        assert!(!rows.is_empty(), "{gap:?}");
        let worst = Cause::worst(rows.iter().map(|r| cause_of(&r.2)));
        assert_eq!(cause.as_deref().map(cause_of), worst, "{rows:?}");
        let alone = rows.iter().filter(|r| r.0.is_none()).count();
        assert_eq!((rows.len() - alone, alone), counts, "{rows:?}");
    }
}

#[test]
fn a_reading_with_no_look_that_is_not_full_has_one_row_with_no_unit_said_by_its_source() {
    let (_, rows) = written("none", &Gap::of(Cause::Failed));
    let row = (
        None,
        String::new(),
        "failed".into(),
        "source".into(),
        None,
        None,
    );
    assert_eq!(rows, [row]);
}

#[test]
fn a_unit_not_read_for_want_of_permission_has_its_row_with_the_system_s_number_and_its_word() {
    // Beside it, a unit that leads into a folder macOS asks permission for keeps no words of a
    // source: why it was not given is the core's, naming the folder.
    let mut look = Look::default();
    let denied = std::io::Error::from_raw_os_error(13);
    let unit = Unit::part("Library/LaunchAgents/a.plist", "/ProgramArguments");
    look.not_looked_at(unit, denied.raw_os_error(), denied.to_string());
    let home = Path::new("/Users/example");
    look.not_into(
        Unit::whole("Documents/b.plist"),
        home.join("Documents"),
        home,
    );
    let (completeness, _) = look.completeness();
    let (_, rows) = written(completeness, &look.gap());
    let permission = (
        Some("Library/LaunchAgents/a.plist".into()),
        "/ProgramArguments".into(),
        "failed".into(),
        "unreadable".into(),
        Some(13),
        Some(denied.to_string()),
    );
    let guarded = (
        Some("Documents/b.plist".into()),
        String::new(),
        "not_given".into(),
        "guarded".into(),
        None,
        None,
    );
    assert_eq!(rows, [permission, guarded]);
}

#[test]
fn a_secret_in_what_a_source_said_is_not_kept_in_said_and_the_path_is_kept_whole() {
    let token = "ghp_Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u";
    let path = format!("dev/{token}/.mcp.json");
    let mut look = Look::default();
    let why = format!("cannot parse: unexpected key near \"{token}\"");
    look.not_looked_at(Unit::whole(&path), None, why);
    let (completeness, _) = look.completeness();
    let (_, rows) = written(completeness, &look.gap());
    let said = rows[0].5.clone().unwrap();
    assert!(!said.contains(token), "{said}");
    assert!(
        said.starts_with("cannot parse: unexpected key near"),
        "{said}"
    );
    assert_eq!(rows[0].0.as_deref(), Some(path.as_str()));
}

#[test]
fn a_journal_entry_whose_word_is_not_in_the_vocabulary_cannot_be_written() {
    let dir = crate::common::Scratch::new("journal-word");
    let conn = open_or_make(&dir.join("store.db")).unwrap();
    let note = |entry: &str| {
        conn.execute(
            "INSERT INTO journal (at, run_id, entry) VALUES (1, 'r', ?1)",
            [entry],
        )
    };
    for entry in JOURNAL_ENTRIES {
        note(entry).unwrap();
    }
    let refused = note("run_begun").unwrap_err();
    assert_eq!(
        refused.sqlite_error_code(),
        Some(rusqlite::ErrorCode::ConstraintViolation),
        "{refused}"
    );
}
