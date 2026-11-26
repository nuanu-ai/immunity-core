//! Promises of the store in write-ahead mode: readers beside writers, what a reader sees, a
//! reader that cannot write, and the `-wal` and `-shm` that are part of the store.

use super::*;

fn notes(c: &Connection) -> rusqlite::Result<i64> {
    c.query_row("SELECT COUNT(*) FROM journal", [], |r| r.get(0))
}

fn len(file: &Path) -> u64 {
    std::fs::metadata(file).map_or(0, |m| m.len())
}

/// Takes write permission from the store's folder and from the store and its two files, as for
/// a reader that runs as another user or in a sandbox. The test's folder is opened again when
/// it is removed.
fn shut(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = |m| std::fs::Permissions::from_mode(m);
    for file in [path.to_path_buf()].into_iter().chain(beside(path)) {
        if file.exists() {
            std::fs::set_permissions(file, mode(0o444)).unwrap();
        }
    }
    std::fs::set_permissions(path.parent().unwrap(), mode(0o555)).unwrap();
}

#[test]
fn a_reader_that_holds_its_read_transaction_neither_keeps_a_commit_waiting_nor_shuts_another_reader_out()
 {
    // A command its caller starves can hold its read for minutes. The watcher's commit and a
    // run's go through at once, and every other command reads what they committed, while what
    // the long read reads stays of one state.
    let dir = crate::common::Scratch::new("long-reader");
    let path = dir.join("store.db");
    drop(open_or_make(&path).unwrap());
    let mut writer = open(&path).unwrap();
    writer.busy_timeout(Duration::ZERO).unwrap();
    let (first, second, other) = read(&path, |long| {
        let first = notes(long)?;
        let tx = writer.transaction()?;
        journal_note(&tx, 1, "run-1", "run_started", "")?;
        tx.commit()?;
        let other = open_read_only(&path)?;
        other.busy_timeout(Duration::ZERO)?;
        let tx = other.unchecked_transaction()?;
        let other = notes(&tx)?;
        Ok((first, notes(long)?, other))
    })
    .unwrap();
    assert_eq!((second, other), (first, first + 1));
    assert_eq!(read(&path, |c| Ok(notes(c)?)).unwrap(), first + 1);
}

#[test]
fn a_writer_that_reads_before_it_writes_is_never_failed_by_another_writer_s_commit_in_between() {
    // `immunity owner` takes no run lock, and the watcher's sample reads this Mac's id before it
    // writes. Its transaction holds the write lock from its start, so the other writer waits for
    // it, here not at all, and is a skip; the first one commits.
    let dir = crate::common::Scratch::new("two-writers");
    let path = dir.join("store.db");
    drop(open_or_make(&path).unwrap());
    let mut first = open(&path).unwrap();
    let second = open(&path).unwrap();
    second.busy_timeout(Duration::ZERO).unwrap();
    let tx = first.transaction().unwrap();
    let before = notes(&tx).unwrap();
    let skipped = journal_note(&second, 1, "run-2", "run_started", "").unwrap_err();
    assert_eq!(crate::outcome::of(&skipped).code, Code::StoreBusy);
    journal_note(&tx, 1, "sample-1", "run_started", "").unwrap();
    tx.commit().unwrap();
    assert_eq!(read(&path, |c| Ok(notes(c)?)).unwrap(), before + 1);
}

#[test]
fn a_writer_s_transaction_that_spills_its_cache_shuts_no_reader_out_and_is_read_only_once_committed()
 {
    // A full check writes for minutes in one transaction, more than the page cache holds.
    let dir = crate::common::Scratch::new("spilled");
    let path = dir.join("store.db");
    drop(open_or_make(&path).unwrap());
    let [wal, _] = beside(&path);
    let mut writer = open(&path).unwrap();
    let committed = id(&writer).unwrap();
    let uncommitted = "0123456789abcdef0123456789abcdef";
    let tx = writer.transaction().unwrap();
    tx.execute_batch(&format!(
        "UPDATE meta SET value = '{uncommitted}' WHERE key = 'store_id';
         INSERT INTO raw_input (reader, input, path, run_id)
             VALUES ('ballast', 'ballast', zeroblob(8000000), 'ballast');"
    ))
    .unwrap();
    // Spilled: pages of the transaction are already in the `-wal`.
    assert!(len(&wal) > 4_000_000, "{} bytes", len(&wal));
    let reader = open_read_only(&path).unwrap();
    reader.busy_timeout(Duration::ZERO).unwrap();
    assert_eq!(id(&reader).unwrap(), committed);
    tx.commit().unwrap();
    assert_eq!(read(&path, |c| Ok(id(c)?)).unwrap(), uncommitted);
}

/// One commit as every command and every step of a watcher makes it: on a connection of its own,
/// opened and closed.
fn commit_alone(path: &Path, n: usize) {
    journal_note(
        &open(path).unwrap(),
        1,
        &format!("run-{n}"),
        "run_started",
        "",
    )
    .unwrap();
}

#[test]
fn each_commit_on_a_connection_of_its_own_leaves_an_empty_wal_and_both_files_so_the_next_first_open_has_no_log_to_read_through()
 {
    // No connection lives longer than a command or a step of a watcher, so nearly every open is
    // the first one, which reads the whole log through to rebuild the `-shm`, holding the others
    // out meanwhile; a log every close kept would grow with every commit.
    let dir = crate::common::Scratch::new("alone");
    let path = dir.join("store.db");
    drop(open_or_make(&path).unwrap());
    let [wal, shm] = beside(&path);
    let before = read(&path, |c| Ok(notes(c)?)).unwrap();
    for n in 1..=30 {
        commit_alone(&path, n);
        assert_eq!(
            (len(&wal), wal.exists(), shm.exists()),
            (0, true, true),
            "{n}"
        );
        assert_eq!(read(&path, |c| Ok(notes(c)?)).unwrap(), before + n as i64);
    }
}

#[test]
fn the_log_a_held_read_made_grow_is_cut_to_nothing_once_the_reader_left_and_a_writer_closed_alone()
{
    let dir = crate::common::Scratch::new("alone-beside");
    let path = dir.join("store.db");
    drop(open_or_make(&path).unwrap());
    let [wal, shm] = beside(&path);
    let (held, grown) = read(&path, |long| {
        let held = notes(long)?;
        let mut sizes = vec![];
        for n in 1..=5 {
            commit_alone(&path, n);
            sizes.push(len(&wal));
        }
        assert!(sizes.windows(2).all(|s| s[0] < s[1]), "{sizes:?}");
        Ok((held, notes(long)?))
    })
    .unwrap();
    assert_eq!(grown, held);
    assert!(len(&wal) > 0);
    commit_alone(&path, 6);
    assert_eq!((len(&wal), shm.exists()), (0, true));
    assert_eq!(read(&path, |c| Ok(notes(c)?)).unwrap(), held + 6);
}

#[test]
fn what_was_committed_is_read_after_every_connection_closed_and_where_nothing_can_be_written() {
    // The last to close a writer alone, which leaves an empty `-wal`; or a reader, after a
    // writer closed beside it, which leaves the log as it was.
    for reader_last in [false, true] {
        let dir = crate::common::Scratch::new("closed");
        let path = dir.join("store.db");
        drop(open_or_make(&path).unwrap());
        let [wal, shm] = beside(&path);
        let before = read(&path, |c| Ok(notes(c)?)).unwrap();
        let reader = reader_last.then(|| open_read_only(&path).unwrap());
        commit_alone(&path, 1);
        drop(reader);
        assert_eq!((len(&wal) > 0, shm.exists()), (reader_last, true));
        shut(&path);
        // Twice: the reader that cannot write leaves the store as readable as it found it.
        assert_eq!(read(&path, |c| Ok(notes(c)?)).unwrap(), before + 1);
        assert_eq!(read(&path, |c| Ok(notes(c)?)).unwrap(), before + 1);
    }
}

#[test]
fn a_reader_that_cannot_make_a_missing_wal_or_shm_names_it_and_changes_nothing() {
    // Removed by hand: SQLite's own words say only that it cannot write or open the store.
    for (gone, code) in [(1, Code::CannotOpen), (0, Code::NotWritable)] {
        let dir = crate::common::Scratch::new("wal-gone");
        let path = dir.join("store.db");
        drop(open_or_make(&path).unwrap());
        let files = beside(&path);
        for file in &files[gone..] {
            std::fs::remove_file(file).unwrap();
        }
        shut(&path);
        let before = as_left(&path);
        let refused = read(&path, |c| Ok(id(c)?)).unwrap_err();
        assert_eq!(refused.code, code, "{refused}");
        let said = format!("with {} beside it", files[gone].display());
        assert!(refused.to_string().contains(&said), "{refused}");
        assert!(as_left(&path) == before);
    }
}

#[test]
fn a_store_in_another_journal_mode_is_refused_and_left_byte_for_byte() {
    let dir = crate::common::Scratch::new("journal-mode");
    let path = dir.join("store.db");
    drop(open_or_make(&path).unwrap());
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "journal_mode", "delete")
        .unwrap();
    assert!(beside(&path).iter().all(|f| !f.exists()));
    let said = refused(&path, Code::Damaged, &["is damaged", START_OVER]);
    assert!(said.contains("journal mode \"delete\""), "{said}");
}

#[test]
fn no_store_is_made_where_a_wal_or_shm_file_already_stands() {
    for (n, end) in ["-wal", "-shm"].into_iter().enumerate() {
        let dir = crate::common::Scratch::new("left-beside");
        let path = dir.join("store.db");
        let left = beside(&path)[n].clone();
        assert!(left.to_str().unwrap().ends_with(end));
        std::fs::write(&left, b"left by an invented store").unwrap();
        let before = as_left(&path);
        let refusal = open_or_make(&path).unwrap_err();
        assert_eq!(refusal.code, Code::NotAStore, "{refusal}");
        assert!(
            refusal.to_string().contains("Nothing was made"),
            "{refusal}"
        );
        assert!(as_left(&path) == before);
        assert_eq!(std::fs::read(&left).unwrap(), b"left by an invented store");
    }
}

#[test]
fn the_wal_a_long_reader_made_grow_is_cut_back_to_its_limit_once_the_reader_leaves() {
    let dir = crate::common::Scratch::new("wal-limit");
    let path = dir.join("store.db");
    drop(open_or_make(&path).unwrap());
    let [wal, _] = beside(&path);
    let writer = open(&path).unwrap();
    // The size the automatic checkpoint lets the log reach: 1,000 pages by SQLite's default.
    let pragma = |p: &str| writer.query_row(p, [], |r| r.get::<_, i64>(0)).unwrap() as u64;
    let limit = pragma("PRAGMA page_size") * pragma("PRAGMA wal_autocheckpoint");
    let ballast = |n: usize| {
        writer.execute(
            "INSERT INTO raw_input (reader, input, path, run_id)
             VALUES ('ballast', ?1, zeroblob(1000000), 'ballast')",
            [format!("ballast {n}")],
        )
    };
    let reader = open_read_only(&path).unwrap();
    let held = reader.unchecked_transaction().unwrap();
    notes(&held).unwrap();
    for n in 0..12 {
        ballast(n).unwrap();
    }
    assert!(len(&wal) > 2 * limit, "{} of {limit}", len(&wal));
    drop(held);
    drop(reader);
    // The first commit after copies the log into the file, the next starts it again.
    let mut n = 12;
    while len(&wal) > limit && n < 15 {
        ballast(n).unwrap();
        n += 1;
    }
    assert!(len(&wal) <= limit, "{} of {limit}", len(&wal));
}
