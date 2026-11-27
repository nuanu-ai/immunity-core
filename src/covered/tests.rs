use super::watched_kinds::watched_readings;
use super::*;
use crate::store::Gap;
use std::path::{Path, PathBuf};

#[test]
fn a_reading_or_a_download_that_failed_is_a_failure_whoever_can_fix_it() {
    // The causes raised when a reading or a download was tried and did not succeed (`fault.rs`).
    let failed = [
        "servers-not-checked",
        "servers-not-opened",
        "not-permitted",
        "could-not-read",
        "read-before-not-read-now",
        "eslogger-refused",
        "event-level-failing",
        "event-level-silent",
        "vulnerability-list-not-downloaded",
        "vulnerability-list-not-downloaded-fixable",
        "vulnerability-data-old",
        "vulnerability-data-not-updated-fixable",
    ];
    for c in CAUSES {
        let is = c.class == store::Cause::Failed;
        assert_eq!(is, failed.contains(&c.id), "{}", c.id);
    }
    // Among them, some the person can fix and some nobody can.
    for who in [YOU, NOTHING] {
        assert!(
            CAUSES
                .iter()
                .any(|c| c.class == store::Cause::Failed && c.who == who)
        );
    }
}

/// A store with this Mac in it, for readings written as a reader writes them.
fn store_of(tag: &str) -> (crate::common::Scratch, Connection) {
    let dir = crate::common::Scratch::new(tag);
    let mut conn = store::open_or_make(&dir.join("store.db")).unwrap();
    let tx = conn.transaction().unwrap();
    store::put_entity(&tx, MAC).unwrap();
    tx.commit().unwrap();
    // This Mac, read.
    let read = (watched::READER, watched::CONTENT);
    stored(&conn, MAC, read, ("full", None, Gap::default()));
    (dir, conn)
}

const MAC: &str = "machine:example-mac";

/// Writes one reading as `put_coverage` writes it, and gives back its latest record with what it
/// did not read, as `view::latest_coverage` reads it back.
fn stored(
    conn: &Connection,
    scope: &str,
    read: (&str, &str),
    coverage: (&str, Option<&str>, Gap),
) -> Latest {
    let (reader, kind) = read;
    let (completeness, reason, gap) = coverage;
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Deferred)
        .unwrap();
    store::put_entity(&tx, scope).unwrap();
    tx.execute(
        "INSERT OR IGNORE INTO coverage_kind (name) VALUES (?1)",
        [kind],
    )
    .unwrap();
    let r = store::Reading {
        reader,
        scope,
        kind,
        run_id: "run-1",
        at: 1,
        observed_at: 1,
    };
    store::put_coverage(&tx, &r, completeness, reason, &gap).unwrap();
    tx.commit().unwrap();
    let latest = crate::view::latest_coverage(conn).unwrap();
    let mine = |l: &&Latest| l.reader == reader && l.scope == scope && l.kind == kind;
    latest.iter().find(mine).unwrap().clone()
}

#[test]
fn a_reading_kept_closed_by_permissions_is_told_from_one_that_failed_otherwise() {
    // The owner can open a file whose permissions keep it closed; he can do nothing about
    // a source that is not there. The numbers are the system's own.
    // EPERM is 1, ENOENT 2, EAGAIN 35, EACCES 13 and EIO 5 (sys/errno.h).
    let (_dir, conn) = store_of("covered-permitted");
    for (errno, closed) in [(1, true), (13, true), (2, false), (35, false), (5, false)] {
        let said = std::io::Error::from_raw_os_error(errno).to_string();
        let gap = Gap::failed(Some(errno));
        let r = stored(
            &conn,
            MAC,
            ("example", "example kind"),
            ("none", Some(&said), gap),
        );
        assert_eq!(
            (not_permitted(&r), failed_otherwise(&r)),
            (closed, !closed),
            "{said}"
        );
    }
    let r = stored(
        &conn,
        MAC,
        ("example", "example kind"),
        ("none", Some("x"), Gap::failed(None)),
    );
    assert_eq!((not_permitted(&r), failed_otherwise(&r)), (false, true));
}

#[test]
fn a_reading_that_failed_both_for_want_of_permission_and_otherwise_is_told_twice_and_a_name_that_reads_like_an_error_is_never_one()
 {
    // No false calm. A reading of two files, one closed by its permissions and one the system
    // could not read for another reason, is something the person can fix and something they
    // cannot: told once each. A folder whose name holds the words of an error, a comma and a
    // semicolon is a name, and what failed in it is told by what the system said of it.
    let (_dir, conn) = store_of("covered-twice");
    let mut look = crate::look::Look::default();
    let unit = |p: &str| crate::baseline::Unit::whole(p);
    let denied = std::io::Error::from_raw_os_error(libc::EACCES);
    let io = std::io::Error::from_raw_os_error(libc::EIO);
    look.not_looked_at(unit(".zshrc"), denied.raw_os_error(), denied.to_string());
    look.not_looked_at(unit(".zprofile"), io.raw_os_error(), io.to_string());
    let (completeness, reason) = look.completeness();
    let both = stored(
        &conn,
        MAC,
        (watched::READER, "shell profiles"),
        (completeness, reason.as_deref(), look.gap()),
    );
    let mut named = crate::look::Look::default();
    let odd = "dev/a, b; c (os error 13)";
    named.not_looked_at(unit(odd), io.raw_os_error(), io.to_string());
    let (completeness, reason) = named.completeness();
    assert!(
        reason
            .as_deref()
            .is_some_and(|r| r.contains("(os error 13)"))
    );
    let name = stored(
        &conn,
        MAC,
        (watched::READER, "launch agents and daemons"),
        (completeness, reason.as_deref(), named.gap()),
    );
    let told = |latest: &[Latest]| {
        let p = status::problems(&conn, latest).unwrap();
        let items = not_covered(&conn, latest, &p, None, None).unwrap();
        let ids = [NOT_PERMITTED.id, READING_FAILED.id];
        (items.iter())
            .filter(|u| ids.contains(&u.cause.id))
            .map(|u| (u.cause.id, u.count))
            .collect::<Vec<_>>()
    };
    let twice = vec![(NOT_PERMITTED.id, 1), (READING_FAILED.id, 1)];
    assert_eq!(told(std::slice::from_ref(&both)), twice);
    assert_eq!(told(&[name]), [(READING_FAILED.id, 1)]);
}

#[test]
fn a_file_of_another_account_closed_here_is_never_the_persons_to_fix_and_once_read_here_is_among_what_could_not_be_read()
 {
    // Each as the reading of a watched file's content stores it, which no answer to a
    // finding changes: one never read here is not given and leaves this Mac watched; one
    // read here before failed, is said among what could not be read and leaves this Mac
    // watched in part; neither is the person's to fix, as their own closed file is.
    use crate::watched::Content;
    let (_dir, conn) = store_of("covered-closed");
    let reading = |path: &str, content: Content| {
        let (completeness, reason, gap) = watched::content_coverage(&content, false);
        let scope = format!("file:{MAC}/{path}");
        let read = (watched::READER, watched::CONTENT);
        stored(&conn, &scope, read, (completeness, reason, gap))
    };
    let said = |latest: &[Latest]| {
        let p = status::problems(&conn, latest).unwrap();
        let items = not_covered(&conn, latest, &p, None, None).unwrap();
        let ids = [NOT_PERMITTED.id, READING_FAILED.id, OTHER_ACCOUNTS.id];
        let items: Vec<(&str, usize)> = (items.iter())
            .filter(|u| ids.contains(&u.cause.id))
            .map(|u| (u.cause.id, u.count))
            .collect();
        (items, this_mac(&conn, latest, false).unwrap().state)
    };
    let closed = |cause| Content::Unread(cause, watched::CLOSED.to_string(), None);
    let never = reading("Library/Example/helper", closed(store::Cause::NotGiven));
    let read_here = reading("Users/example/.zprofile", closed(store::Cause::Failed));
    let denied = std::io::Error::from_raw_os_error(libc::EACCES);
    let own = Content::Unread(store::Cause::Failed, denied.to_string(), Some(libc::EACCES));
    let own_closed = reading("Users/example/.zshrc", own);
    assert_eq!(
        said(std::slice::from_ref(&never)),
        (vec![(OTHER_ACCOUNTS.id, 1)], "watched")
    );
    let in_part = vec![(READING_FAILED.id, 1), (OTHER_ACCOUNTS.id, 1)];
    assert_eq!(said(&[never, read_here]), (in_part, "watched_in_part"));
    let own = vec![(NOT_PERMITTED.id, 1)];
    assert_eq!(said(&[own_closed]), (own, "watched_in_part"));
}

#[test]
fn every_cause_a_person_can_fix_has_a_short_name_that_fits_its_row() {
    // The app shows such a cause as a row whose second line is its short name, about 36
    // characters wide; the sentence, the meaning and the advice carry the detail.
    for c in CAUSES.iter().filter(|c| c.who == YOU) {
        assert!(c.kind.chars().count() <= 36, "{}: {:?}", c.id, c.kind);
    }
}

#[test]
fn an_example_whose_source_said_nothing_has_no_reason_and_never_an_empty_one() {
    // A reader takes an absent reason as nothing said; an empty one would read as words.
    let e = with_reason("db-1".to_string(), Some(""));
    assert_eq!((e.name.as_str(), e.reason), ("db-1", None));
    let e = with_reason("db-1".to_string(), Some("refused"));
    assert_eq!(e.reason.as_deref(), Some("refused"));
}

#[test]
fn what_this_version_does_not_understand_is_named_as_the_owner_knows_it() {
    // "for example software inside containers on servers and yarn.lock" reads as one
    // thing; the names of files come first.
    let kinds: BTreeSet<String> = [
        plain_lack(servers::CONTAINER_CONTENTS, None),
        plain_lack(crate::lockfiles::LOCKFILE_KIND, Some("yarn.lock")),
        plain_lack(servers::PACKAGE_MANAGER, Some("apk")),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        names_first(&kinds),
        [
            "yarn.lock",
            "apk packages",
            "software inside containers on servers"
        ]
    );
    // A lockfile not opened is a kind this version reads, so it is never named bare, as if
    // the kind were not understood.
    use crate::lockfiles::{DEEPER, LINKED, NOT_LOOKED, NOT_TOLD, SET_ASIDE};
    assert_eq!(
        [
            plain_lack(DEEPER, Some("Cargo.lock")),
            plain_lack(SET_ASIDE, Some("package-lock.json")),
            plain_lack(NOT_LOOKED, None),
            plain_lack(LINKED, Some("pnpm-lock.yaml")),
            plain_lack(NOT_TOLD, Some("yarn.lock")),
        ],
        [
            "Cargo.lock deeper than four folders in a project",
            "package-lock.json in vendor or hidden folders",
            "folders of very large projects not looked through for lockfiles",
            "pnpm-lock.yaml that is a link",
            "entries of yarn.lock whose package cannot be told",
        ]
    );
}

#[test]
fn every_sentence_this_version_cannot_judge_and_only_those_is_told_to_a_person_as_a_limit() {
    // A gap an agent reads in `cannot_judge` and the owner never sees would be calm the
    // program has not earned; a limit told after its gap was closed would be a false one.
    let told: Vec<&str> = LIMITS.iter().map(|(s, _)| *s).collect();
    assert_eq!(told, status::CANNOT_JUDGE);
    assert!(LIMITS.iter().all(|(_, c)| c.who == NOTHING));
    // An agent learns from the catalogue every item it can meet, a limit's among them.
    assert!(
        LIMITS
            .iter()
            .all(|(_, c)| CAUSES.iter().any(|known| known.id == c.id))
    );
}

#[test]
fn the_places_not_checked_on_this_macos_are_told_to_an_agent_and_to_a_person_with_one_count() {
    // The status names the sentence of the Mac it runs on, with or without a store.
    let path = std::path::Path::new("/nonexistent/store.db");
    let m = status::message(None, None, false, path, 0).unwrap();
    let said = autorun::not_checked_said(autorun::MacOs::this_mac()).unwrap();
    assert_eq!(m.cannot_judge.last(), Some(&said));
    // The person's item counts the same rows, and says why in either case.
    for (macos, reason) in [
        (autorun::MacOs::Major(26), "This Mac runs macOS 26"),
        (autorun::MacOs::NotKnown, "could not be read"),
    ] {
        let item = not_checked_on_macos(macos).unwrap();
        let n = autorun::not_checked_on(macos).len();
        assert_eq!(item.count, n);
        assert!(
            autorun::not_checked_said(macos)
                .unwrap()
                .contains(&n.to_string())
        );
        assert!(
            item.title().starts_with(&format!("{n} places")),
            "{}",
            item.title()
        );
        assert!(item.meaning().contains(reason), "{}", item.meaning());
        // No row is checked on any version yet, so it holds on every Mac and a person is
        // not shown it as something about this one.
        assert!(autorun::POINTS.iter().all(|p| p.checked_on.is_empty()));
        assert!(item.every_mac);
    }
}

#[test]
fn every_place_a_tool_read_before_was_looked_for_is_told_whole_whatever_its_name_holds() {
    // A place given to look for a tool at is a name from the Mac: a folder named with a comma
    // and a space before a slash is one place, never two.
    let (_dir, conn) = store_of("covered-lost");
    let places = [
        "/Users/example/Tools, /brew".to_string(),
        "/opt/homebrew/bin/brew".to_string(),
    ];
    let reason = format!(
        "{}{}{}",
        crate::brew::NAME,
        crate::tools::READ_BEFORE,
        places.join(", ")
    );
    let gap = crate::tools::lost(&places);
    let read = (crate::brew::READER, crate::brew::KIND);
    let r = stored(&conn, MAC, read, ("none", Some(&reason), gap));
    let p = status::problems(&conn, std::slice::from_ref(&r)).unwrap();
    let items = not_covered(&conn, &[r], &p, None, None).unwrap();
    let lost = items.iter().find(|u| u.cause.id == TOOL_LOST.id).unwrap();
    let named: Vec<&str> = lost.examples.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(named, places);
}

#[test]
fn a_folder_macos_asks_permission_for_is_told_by_its_row_whole() {
    // A disk is named as the Mac names it, a comma in it too, and only the folders the rows
    // name are told.
    let (_dir, conn) = store_of("covered-guarded");
    let home = Path::new("/Users/example");
    let folders = [
        home.join("Documents"),
        PathBuf::from("/Volumes/Backup, old"),
    ];
    let reason = format!(
        "{}~/Documents, /Volumes/Backup, old",
        guarded::NOT_LOOKED_INTO
    );
    let gap = guarded::gap(&folders, home);
    let read = (crate::checkouts::READER, guarded::KIND);
    let r = stored(&conn, MAC, read, ("none", Some(&reason), gap));
    assert_eq!(not_looked_into(&r), ["Documents", "the disk Backup, old"]);
    let found = projects_found(&[r], Some(MAC));
    assert_eq!(found.folders_text, ["Documents", "the disk Backup, old"]);
}

#[test]
fn a_walk_limited_to_the_folder_given_is_told_by_its_row_and_never_by_its_reason_s_words() {
    // Only the folder given was walked: what was found is whole for that folder. Told by the
    // row the walk writes, so that any other gap beside it is told as the reading not full.
    let (_dir, conn) = store_of("covered-given");
    let sessions = (crate::agent_folders::READER, crate::agent_folders::KIND);
    stored(&conn, MAC, sessions, ("full", None, Gap::default()));
    let latest = || crate::view::latest_coverage(&conn).unwrap();
    let mut look = crate::look::Look::default();
    look.present = 1;
    look.read(crate::baseline::Unit::whole("dev"));
    let given = crate::checkouts::ONLY_GIVEN.to_string();
    look.short_as(store::Cause::NotGiven, crate::checkouts::GIVEN, given);
    let (completeness, _) = look.completeness_noted(None);
    let read = (crate::checkouts::READER, crate::checkouts::KIND);
    let words = "the walk was given dev, a folder";
    stored(&conn, MAC, read, (completeness, Some(words), look.gap()));
    let found = projects_found(&latest(), Some(MAC));
    assert_eq!(found.why.as_deref(), Some(crate::checkouts::ONLY_GIVEN));
    // Beside a folder that could not be listed, the reading is not full, whatever it says.
    look.not_looked_at(
        crate::baseline::Unit::whole("dev/a"),
        Some(libc::EIO),
        "x".into(),
    );
    let (completeness, _) = look.completeness_noted(None);
    let given = crate::checkouts::ONLY_GIVEN;
    stored(&conn, MAC, read, (completeness, Some(given), look.gap()));
    let found = projects_found(&latest(), Some(MAC));
    let why = format!("the reading of {} was not full", crate::checkouts::KIND);
    assert_eq!(found.why, Some(why));
}

#[test]
fn every_kind_of_place_and_every_kind_of_the_rows_read_here_is_in_the_one_list_of_watched_files() {
    // No kind of watched files is left out of what an answer goes over: each kind of place,
    // in the order of the table of places, then each kind of the rows of the table of autorun
    // points read here, and every coverage kind of each has its kind of files.
    let files = watched_files();
    let places: Vec<&str> = watched::kinds().into_iter().map(|k| k.0).collect();
    let named: Vec<&str> = files.iter().map(|k| k.0).collect();
    assert_eq!(named[..places.len()], places[..]);
    for (as_, kind) in watched::kinds() {
        let kinds = &files.iter().find(|k| k.0 == as_).expect(as_).1;
        assert!(kinds.iter().any(|k| k == kind), "{as_}");
    }
    for (as_, ..) in autorun::watched() {
        let kinds = &files.iter().find(|k| k.0 == as_).expect(as_).1;
        assert_eq!(*kinds, autorun::kinds_of(as_), "{as_}");
        assert!(!kinds.is_empty(), "{as_}");
    }
}

#[test]
fn a_kind_of_watched_files_is_full_only_when_every_kind_of_its_list_was_read_in_full_on_this_mac() {
    // No false calm. A coding agent's own settings read in full and the other files of that
    // kind never read is not that kind read in full, and neither is a full reading of the rest
    // on another machine, which stands for nothing here. The rest not read count as readings
    // of nothing. A kind with no reading here says nothing.
    let (_dir, conn) = store_of("covered-watched-readings");
    let as_ = autorun::AGENT_SETTINGS.0;
    let kinds = autorun::kinds_of(as_);
    let full = |scope: &str, kind: &str, note: Option<&str>| {
        stored(
            &conn,
            scope,
            (watched::READER, kind),
            ("full", note, Gap::default()),
        )
    };
    let of = |latest: &[Latest], as_: &str| {
        let all = watched_readings(latest, Some(MAC), None, 0);
        let k = all.into_iter().find(|k| k.watched_as == as_).unwrap();
        (k.coverage, k.full, k.partial, k.none, k.reason)
    };
    let mut latest = vec![full(MAC, &kinds[0], Some("none of the keys read is in it"))];
    let rest = kinds.len() - 1;
    assert_eq!(of(&latest, as_), (Some("partial"), 1, 0, rest, None));
    for kind in &kinds[1..] {
        latest.push(full("machine:example-other", kind, None));
    }
    assert_eq!(of(&latest, as_), (Some("partial"), 1, 0, rest, None));
    for kind in &kinds[1..] {
        latest.push(full(MAC, kind, None));
    }
    assert_eq!(of(&latest, as_).0, Some("full"));
    assert_eq!(of(&latest[1..=rest], as_), (None, 0, 0, 0, None));
    // The hooks of a checkout are this Mac's when the checkout is on it, and not on a machine
    // whose id only begins with this one's.
    let hooks = |scope: &str| [full(scope, watched::HOOK_KIND, None)];
    let mine = hooks(&format!("checkout:{MAC}/dev/app"));
    assert_eq!(of(&mine, watched::HOOK).0, Some("full"));
    let other = hooks(&format!("checkout:{MAC}-2/dev/app"));
    assert_eq!(of(&other, watched::HOOK).0, None);
}

#[test]
fn a_kind_of_watched_files_is_fresh_only_when_every_reading_of_it_here_is_of_the_latest_check() {
    // No false calm: only a kind read in full and fresh may be said to hold nothing. A reading
    // taken before the latest full check began, one dated ahead of the clock, a kind of its list
    // never read here, and a kind with no reading at all are not fresh; when it was last read is
    // its latest reading's time.
    let (_dir, conn) = store_of("covered-watched-fresh");
    let (run, now) = (1_000_000, 1_000_100);
    let as_ = watched::PROFILE;
    let at = |at: i64| Latest {
        at,
        ..stored(
            &conn,
            MAC,
            (watched::READER, watched::PROFILE_KIND),
            ("full", None, Gap::default()),
        )
    };
    let of = |latest: &[Latest], run: Option<i64>| {
        let k = (watched_readings(latest, Some(MAC), run, now).into_iter())
            .find(|k| k.watched_as == as_)
            .unwrap();
        (k.fresh, k.read_at)
    };
    assert_eq!(of(&[at(run + 1)], Some(run)), (true, Some(run + 1)));
    assert_eq!(of(&[at(run - 1)], Some(run)), (false, Some(run - 1)));
    let ahead = now + crate::store::AHEAD_ALLOWED + 1;
    assert_eq!(of(&[at(ahead)], Some(run)), (false, Some(ahead)));
    assert!(!of(&[at(run + 1)], None).0);
    assert_eq!(of(&[], Some(run)), (false, None));
    let agent = autorun::AGENT_SETTINGS.0;
    let one = stored(
        &conn,
        MAC,
        (watched::READER, &autorun::kinds_of(agent)[0]),
        ("full", None, Gap::default()),
    );
    let k = (watched_readings(&[Latest { at: run + 1, ..one }], Some(MAC), Some(run), now))
        .into_iter()
        .find(|k| k.watched_as == agent)
        .unwrap();
    assert!(!k.fresh);
}

#[test]
fn a_reading_names_the_kinds_of_watched_place_it_speaks_for_and_no_other() {
    // A row of what is watched is drawn as a fault by these words alone: a reading of a kind of
    // watched files names that kind, one of installed software its kind, a lockfile's the
    // packages, the search for projects every kind kept in projects and the packages, and a
    // reading of nothing watched names nothing. A reading of another machine names nothing of
    // this Mac's.
    let (_dir, conn) = store_of("covered-kinds-read-by");
    let of = |readings: &[(&str, &str, &str)]| {
        kinds_read_by(&conn, readings.iter().copied(), Some(MAC)).unwrap()
    };
    assert_eq!(
        of(&[(watched::READER, watched::PROFILE_KIND, MAC)]),
        [watched::PROFILE]
    );
    assert_eq!(
        of(&[(integrity::READER, integrity::KEGS, MAC)]),
        [integrity::KEGS]
    );
    assert_eq!(
        of(&[(crate::lockfiles::READER, "any kind", MAC)]),
        [DEPENDENCIES]
    );
    assert!(of(&[(watched::READER, watched::PROFILE_KIND, "machine:other")]).is_empty());
    // The content of a watched file speaks for every kind the file is watched as.
    let file = format!("file:{MAC}/.zshrc");
    let tx = rusqlite::Transaction::new_unchecked(&conn, rusqlite::TransactionBehavior::Deferred)
        .unwrap();
    store::put_entity(&tx, &file).unwrap();
    tx.commit().unwrap();
    let watched_as = |layer: &str, as_: &str| {
        conn.execute(
            "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                    source_ref, basis, observed_at, run_id, retracted_at,
                                    retracted_by)
             VALUES (?1, ?2, 'watched_as', ?3, ?4, ?5, ?6, 'invented:1', 'observed',
                     1, 'run-1', CASE ?1 WHEN 'retracted' THEN 2 END,
                     CASE ?1 WHEN 'retracted' THEN 'run-2' END)",
            params![
                layer,
                file,
                as_,
                watched::READER,
                MAC,
                watched::PROFILE_KIND
            ],
        )
        .unwrap()
    };
    watched_as("retracted", watched::SSH);
    watched_as("live", watched::PROFILE);
    assert_eq!(
        of(&[(watched::READER, watched::CONTENT, &file)]),
        [watched::PROFILE]
    );
    // Live under a second kind, as a shell startup file a project's Git settings name as its
    // hooks file: the reading speaks for both, and both rows show its fault.
    watched_as("live", watched::HOOK);
    let both = of(&[(watched::READER, watched::CONTENT, &file)]);
    assert!(
        both.len() == 2 && both.contains(&watched::PROFILE) && both.contains(&watched::HOOK),
        "{both:?}"
    );
    // A file watched no longer speaks for the kind it was last watched as.
    conn.execute(
        "UPDATE assertion SET layer = 'retracted', retracted_at = 3, retracted_by = 'run-3'
         WHERE subject = ?1 AND object = ?2",
        params![file, watched::HOOK],
    )
    .unwrap();
    conn.execute(
        "UPDATE assertion SET layer = 'retracted', retracted_at = 3, retracted_by = 'run-3'
         WHERE subject = ?1 AND object = ?2",
        params![file, watched::PROFILE],
    )
    .unwrap();
    assert_eq!(
        of(&[(watched::READER, watched::CONTENT, &file)]),
        [watched::HOOK]
    );
    // A file of another machine, under the same kinds, speaks for none of this Mac's.
    let theirs = file.replace(MAC, "machine:other");
    assert!(of(&[(watched::READER, watched::CONTENT, &theirs)]).is_empty());
    assert!(of(&[(watched::READER, watched::CONTENT, "file:machine:none")]).is_empty());
    let (by, kind) = crate::project::FOUND_BY[0];
    let found = of(&[(by, kind, MAC), (by, kind, MAC)]);
    let kept: Vec<&str> = (watched().into_iter())
        .filter_map(|(c, ..)| match c {
            Count::Files(as_) if in_projects(c) => Some(as_),
            _ => None,
        })
        .chain([DEPENDENCIES])
        .collect();
    assert_eq!(found, kept);
    assert!(of(&[(crate::tailnet::READER, crate::tailnet::KIND, MAC)]).is_empty());
}
