//! Which files of a thing changed between two of its lists, and how a finding tells them: the
//! raw copies a reading keeps of a thing's list and of what changed in it (`list_input`,
//! `changes_input`, `kept_file`), the comparison of two lists (`compare`), and what a finding
//! reads of it (`files_changed`).

use super::{MAX_FILES, READER, stat};
use rusqlite::{Connection, OptionalExtension};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The name among the raw copies of a thing's list (`Thing::list`), and of what changed in it at
/// its latest change (`Changes`): made from the thing's id by its SHA-256, so that any id is a
/// safe file name.
pub fn list_input(subject: &str) -> String {
    format!("files/{}.txt", crate::sha256::hex(subject.as_bytes()))
}

pub fn changes_input(subject: &str) -> String {
    format!("changes/{}.json", crate::sha256::hex(subject.as_bytes()))
}

/// The file of a raw copy of `input` under the store's folder, from its path as `raw_input`
/// holds it: only of the shape `Run::keep_raw` writes, `raw/<one folder>/<input>`. Another
/// program can write that table, so a path of any other shape, absolute or with `..`, is none.
pub fn kept_file(folder: &Path, path: &str, input: &str) -> Option<PathBuf> {
    let run = path
        .strip_prefix("raw/")?
        .strip_suffix(input)?
        .strip_suffix('/')?;
    let one = !run.is_empty() && !run.contains('/') && run != "." && run != "..";
    one.then(|| folder.join(path))
}

/// The most a list kept before is read: a line for each of `MAX_FILES` files, of a path as long
/// as macOS allows and its change time. A larger file is no list.
pub const LIST_CAP: u64 = MAX_FILES as u64 * 1_100;
/// The most of what changed that is read, and the longest name passed on, in bytes.
const CHANGES_CAP: u64 = 64 << 10;
const NAME_CAP: usize = 1_024;
/// The most the entries of one kind take in the record as written, so that the record fits
/// `CHANGES_CAP`: a third of it, less 1 KiB for the digests, the counts and the keys.
const PART: usize = (CHANGES_CAP as usize - 1_024) / 3;

/// The files of one thing added, removed and changed between two of its lists, with the digests
/// of both, so that it is told only of the change the journal holds between those two digests.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Changes {
    from: String,
    to: String,
    added: Told,
    removed: Told,
    changed: Told,
}

/// The files of one kind of change, counted exactly, and told by structure: in path order, a
/// folder below the thing's own every file under which, in either list, changed this way, at the
/// outermost, and every other file alone. The thing's own folder is never an entry, so a thing
/// that changed whole is told by what is in it. The entries stop before they take more than
/// `PART`; the files they leave out are the count less theirs.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Told {
    count: u64,
    entries: Vec<Entry>,
}

/// A path from the thing's folder and how many files of the kind it holds: a file holds 1, and a
/// folder is an entry only when it holds more.
#[derive(serde::Serialize, serde::Deserialize)]
struct Entry {
    path: String,
    folder: bool,
    files: u64,
}

/// The folders below the thing's own a path from a list is in, outermost first: the path before
/// each `/` but the first, since every path in a list begins with one.
fn folders_of(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    (1..path.len())
        .filter(|&i| path[i] == b'/')
        .map(|i| &path[..i])
}

/// A list's records as path and change time; `None` when it is not a list `walk` makes. A path
/// can hold a newline and never a NUL, and a change time holds neither, so each record ends at
/// the first newline after its NUL.
fn records(list: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let mut out = Vec::new();
    let mut rest = list;
    while !rest.is_empty() {
        let (path, after) = rest.split_at(rest.iter().position(|b| *b == 0)?);
        let (time, after) = after[1..].split_at(after[1..].iter().position(|b| *b == b'\n')?);
        out.push((path, time));
        rest = &after[1..];
    }
    Some(out)
}

/// What changed from one list of a thing to the next: a path in the new list only is added, in
/// the old only removed, in both with another change time changed, and in both alike kept. A
/// folder below the thing's own changed whole one way when every file under it, in either list,
/// changed that way, as
/// `git status` tells an untracked folder and `diff -r` a folder only in one tree. `None` when
/// either is not a list, or when no file is told: what cannot be said is never said as nothing.
pub fn compare(before: &[u8], now: &[u8]) -> Option<Changes> {
    const KEPT: usize = 3;
    let (old, new) = (records(before)?, records(now)?);
    let (was, is): (BTreeMap<_, _>, BTreeMap<_, _>) =
        (old.iter().copied().collect(), new.iter().copied().collect());
    // Each file by its kind, 0 added, 1 removed, 2 changed and `KEPT`, and what each folder
    // holds of each kind.
    let mut files = Vec::new();
    for (path, time) in &new {
        files.push(match was.get(path) {
            None => (*path, 0),
            Some(t) if t != time => (*path, 2),
            Some(_) => (*path, KEPT),
        });
    }
    files.extend(
        old.iter()
            .filter(|(p, _)| !is.contains_key(p))
            .map(|(p, _)| (*p, 1)),
    );
    let mut held: BTreeMap<&[u8], [u64; 4]> = BTreeMap::new();
    for (path, kind) in &files {
        for folder in folders_of(path) {
            held.entry(folder).or_default()[*kind] += 1;
        }
    }
    // The entries of each kind, by path, with how many files each holds.
    let mut told: [BTreeMap<&[u8], u64>; 3] = Default::default();
    let mut counts = [0u64; 3];
    for (path, kind) in files.iter().filter(|(_, kind)| *kind != KEPT) {
        counts[*kind] += 1;
        let whole = folders_of(path)
            .map(|f| (f, held[f]))
            .find(|(_, n)| (0..4).all(|k| k == *kind || n[k] == 0));
        let (at, files) = match whole {
            Some((folder, n)) if n[*kind] > 1 => (folder, n[*kind]),
            _ => (*path, 1),
        };
        told[*kind].insert(at, files);
    }
    let [added, removed, changed] = std::array::from_fn(|kind| {
        let mut out = Told {
            count: counts[kind],
            entries: Vec::new(),
        };
        let mut part = 0;
        for (path, files) in &told[kind] {
            let name = path.strip_prefix(b"/").unwrap_or(path);
            let entry = Entry {
                path: String::from_utf8_lossy(name).into_owned(),
                folder: *files > 1,
                files: *files,
            };
            part += serde_json::to_vec(&entry).map_or(PART + 1, |b| b.len() + 1);
            if part > PART {
                break;
            }
            out.entries.push(entry);
        }
        out
    });
    let c = Changes {
        from: stat(before),
        to: stat(now),
        added,
        removed,
        changed,
    };
    (counts.iter().sum::<u64>() > 0).then_some(c)
}

/// What files changed at the latest change of a finding's thing, from the raw copy the reading
/// kept (`changes_input`): only when the latest journal entry the finding rests on is a change
/// from the copy's old digest to its new one, so that the copy is of that very change. `None`
/// otherwise, and the finding says nothing of files.
pub fn files_changed(
    conn: &Connection,
    finding: &str,
) -> rusqlite::Result<Option<crate::contract::v1::FilesChanged>> {
    let change: Option<(String, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT j.subject, j.old_value, j.new_value FROM finding_basis b
             JOIN journal j ON j.seq = b.journal
             WHERE b.finding = ?1 ORDER BY j.seq DESC LIMIT 1",
            [finding],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((subject, Some(from), Some(to))) = change else {
        return Ok(None);
    };
    let input = changes_input(&subject);
    let Some(path) = crate::store::last_raw(conn, READER, &input)? else {
        return Ok(None);
    };
    // Raw copies are kept in the store's folder, as paths from it. What is read is bounded,
    // whatever the file holds.
    let folder = conn.path().map(Path::new).and_then(Path::parent);
    let kept = folder
        .and_then(|f| kept_file(f, &path, &input))
        .and_then(|file| crate::open::read(&file, crate::open::Reach::Own, CHANGES_CAP).ok())
        .and_then(|bytes| serde_json::from_slice::<Changes>(&bytes).ok())
        .filter(|c| c.from == from && c.to == to);
    Ok(kept.as_ref().and_then(message))
}

/// What a finding says of the files of one change; `None` when the record tells no file, or when
/// its entries cover more files than their kind counts, so that what they leave out is always the
/// count less theirs.
fn message(c: &Changes) -> Option<crate::contract::v1::FilesChanged> {
    let covered = |t: &Told| {
        t.entries
            .iter()
            .try_fold(0u64, |sum, e| sum.checked_add(e.files))
            .is_some_and(|sum| sum <= t.count)
    };
    let kinds = [&c.added, &c.removed, &c.changed];
    if !kinds.iter().any(|t| t.count > 0) || !kinds.iter().all(|t| covered(t)) {
        return None;
    }
    let paths = |t: &Told| {
        t.entries
            .iter()
            .map(|e| crate::contract::v1::ChangedPath {
                path_text: crate::known::whole(cut(&e.path)),
                folder: e.folder,
                files: e.files,
            })
            .collect()
    };
    Some(crate::contract::v1::FilesChanged {
        added: c.added.count,
        removed: c.removed.count,
        changed: c.changed.count,
        added_paths: paths(&c.added),
        removed_paths: paths(&c.removed),
        changed_paths: paths(&c.changed),
    })
}

/// A name cut to `NAME_CAP` bytes, at the end of a character.
fn cut(name: &str) -> &str {
    let mut end = name.len().min(NAME_CAP);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

#[cfg(test)]
mod tests {
    use super::{Told, compare, kept_file};
    use std::path::Path;

    #[test]
    fn a_kept_copy_is_a_file_only_at_a_path_of_the_shape_the_store_writes() {
        // The table of raw copies is data another program can write: a path from it never
        // reaches a file outside the store's folder of raw copies.
        let (store, input) = (Path::new("/Users/example/store"), "files/ab.txt");
        let file = kept_file(store, "raw/1795400000-000000001/files/ab.txt", input);
        assert_eq!(
            file,
            Some(store.join("raw/1795400000-000000001/files/ab.txt"))
        );
        for path in [
            "/Users/example/store/raw/1795400000-000000001/files/ab.txt",
            "raw/../files/ab.txt",
            "raw/./files/ab.txt",
            "raw//files/ab.txt",
            "raw/1795400000-000000001/../../files/ab.txt",
            "other/1795400000-000000001/files/ab.txt",
            "raw/1795400000-000000001/files/cd.txt",
        ] {
            assert_eq!(kept_file(store, path, input), None, "{path}");
        }
    }

    #[test]
    fn lists_that_tell_no_file_apart_are_never_told_as_no_file_changed() {
        let list = b"/bin/tool\x001.5\n/lib/a\nb\x002.5\n";
        assert!(compare(list, list).is_none());
        assert!(compare(b"damaged", list).is_none());
        // A name may hold a line break; it is still one file, unchanged here.
        let c = compare(list, b"/bin/tool\x001.6\n/lib/a\nb\x002.5\n").unwrap();
        assert_eq!(told(&c.changed), [("bin/tool", false, 1)]);
        assert_eq!((c.added.count, c.removed.count), (0, 0));
    }

    /// A list as `walk` makes it, of paths from the thing's folder and their change times.
    fn list(files: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, time) in files {
            out.extend_from_slice(format!("/{path}\0{time}\n").as_bytes());
        }
        out
    }

    fn told(t: &Told) -> Vec<(&str, bool, u64)> {
        t.entries
            .iter()
            .map(|e| (e.path.as_str(), e.folder, e.files))
            .collect()
    }

    #[test]
    fn a_whole_folder_inside_a_whole_folder_is_told_once_at_the_outermost() {
        let before = list(&[("bin/tool", "1")]);
        let now = list(&[
            ("bin/tool", "1"),
            ("lib/2.0/a.js", "2"),
            ("lib/2.0/deep/b.js", "2"),
            ("lib/2.0/deep/c.js", "2"),
            ("lib/d.js", "2"),
        ]);
        let c = compare(&before, &now).unwrap();
        assert_eq!(told(&c.added), [("lib", true, 4)]);
        assert_eq!(c.added.count, 4);
        // The other way round.
        let c = compare(&now, &before).unwrap();
        assert_eq!(told(&c.removed), [("lib", true, 4)]);
    }

    #[test]
    fn a_file_added_into_a_folder_that_held_files_and_one_removed_from_a_folder_that_keeps_files_are_named()
     {
        let before = list(&[("lib/a.js", "1"), ("lib/b.js", "1"), ("bin/x", "1")]);
        let now = list(&[("lib/a.js", "1"), ("lib/z.js", "2"), ("bin/x", "1")]);
        let c = compare(&before, &now).unwrap();
        assert_eq!(told(&c.added), [("lib/z.js", false, 1)]);
        assert_eq!(told(&c.removed), [("lib/b.js", false, 1)]);
        assert_eq!(c.changed.count, 0);
    }

    #[test]
    fn a_folder_where_every_file_was_written_again_is_one_entry_and_with_one_left_as_it_was_its_files_are_named()
     {
        let before = list(&[("bin/x", "1"), ("lib/a.js", "1"), ("lib/b.js", "1")]);
        let all = list(&[("bin/x", "1"), ("lib/a.js", "2"), ("lib/b.js", "2")]);
        assert_eq!(
            told(&compare(&before, &all).unwrap().changed),
            [("lib", true, 2)]
        );
        let before = list(&[("lib/a.js", "1"), ("lib/b.js", "1"), ("lib/c.js", "1")]);
        let some = list(&[("lib/a.js", "2"), ("lib/b.js", "1"), ("lib/c.js", "2")]);
        let c = compare(&before, &some).unwrap();
        assert_eq!(
            told(&c.changed),
            [("lib/a.js", false, 1), ("lib/c.js", false, 1)]
        );
        // A file added beside the files rewritten keeps the folder from being changed whole.
        let more = list(&[
            ("lib/a.js", "2"),
            ("lib/b.js", "2"),
            ("lib/c.js", "2"),
            ("lib/d", "2"),
        ]);
        let c = compare(&before, &more).unwrap();
        assert_eq!(c.changed.entries.len(), 3);
        assert_eq!(told(&c.added), [("lib/d", false, 1)]);
    }

    #[test]
    fn a_folder_of_one_file_is_told_as_the_file() {
        let before = list(&[("bin/x", "1"), ("old/deep/one.js", "1")]);
        let now = list(&[("bin/x", "2"), ("new/deep/one.js", "1")]);
        let c = compare(&before, &now).unwrap();
        assert_eq!(told(&c.added), [("new/deep/one.js", false, 1)]);
        assert_eq!(told(&c.removed), [("old/deep/one.js", false, 1)]);
        assert_eq!(told(&c.changed), [("bin/x", false, 1)]);
    }

    /// The counts of a change: added, removed and changed.
    fn counts(c: &super::Changes) -> [u64; 3] {
        [c.added.count, c.removed.count, c.changed.count]
    }

    #[test]
    fn three_files_directly_in_a_things_folder_that_all_went_are_three_names_and_none_is_its_own_folder()
     {
        // Told as the thing's own folder with a count, three files that went say nothing of what
        // they were; by name, a person or an agent knows in one line.
        let files = list(&[("lock", "1"), ("run", "1"), ("socket", "1")]);
        let names = [("lock", false, 1), ("run", false, 1), ("socket", false, 1)];
        let c = compare(&files, b"").unwrap();
        assert_eq!(told(&c.removed), names);
        assert_eq!(counts(&c), [0, 3, 0]);
        let c = compare(b"", &files).unwrap();
        assert_eq!(told(&c.added), names);
        assert_eq!(counts(&c), [3, 0, 0]);
        let again = list(&[("lock", "2"), ("run", "2"), ("socket", "2")]);
        let c = compare(&files, &again).unwrap();
        assert_eq!(told(&c.changed), names);
        assert_eq!(counts(&c), [0, 0, 3]);
    }

    #[test]
    fn a_thing_every_file_of_which_changed_is_told_by_its_top_folders_with_their_counts_and_its_roots_own_files_by_name()
     {
        let files = list(&[
            ("README", "1"),
            ("bin/x", "1"),
            ("lib/a.js", "1"),
            ("lib/deep/b.js", "1"),
            ("run.sh", "1"),
        ]);
        let want = [
            ("README", false, 1),
            ("bin/x", false, 1),
            ("lib", true, 2),
            ("run.sh", false, 1),
        ];
        let c = compare(b"", &files).unwrap();
        assert_eq!(told(&c.added), want);
        assert_eq!(counts(&c), [5, 0, 0]);
        let c = compare(&files, b"").unwrap();
        assert_eq!(told(&c.removed), want);
        assert_eq!(counts(&c), [0, 5, 0]);
        let again = list(&[
            ("README", "2"),
            ("bin/x", "2"),
            ("lib/a.js", "2"),
            ("lib/deep/b.js", "2"),
            ("run.sh", "2"),
        ]);
        let c = compare(&files, &again).unwrap();
        assert_eq!(told(&c.changed), want);
        assert_eq!(counts(&c), [0, 0, 5]);
    }

    #[test]
    fn a_flat_folder_of_more_files_than_the_bound_takes_stops_within_it_and_the_line_of_counts_says_how_many_are_left_out()
     {
        let paths: Vec<String> = (0..3_000).map(|i| format!("f{i:04}.js")).collect();
        let files = list(&paths.iter().map(|p| (p.as_str(), "1")).collect::<Vec<_>>());
        let c = compare(b"", &files).unwrap();
        assert_eq!(counts(&c), [3_000, 0, 0]);
        let entries = told(&c.added);
        assert!(
            entries.len() > 50 && entries.len() < 3_000,
            "{}",
            entries.len()
        );
        for (entry, path) in entries.iter().zip(&paths) {
            assert_eq!(*entry, (path.as_str(), false, 1));
        }
        let left = (3_000 - entries.len()) as u64;
        let message = super::message(&c).unwrap();
        let (line, _) = crate::finding_text::files_said(&message);
        let said = format!(
            "3,000 added ({} not listed), 0 removed, 0 changed",
            crate::overview::grouped(left)
        );
        assert!(line.ends_with(&said), "{line}");
    }

    #[test]
    fn entries_of_a_kind_are_in_path_order_and_stop_within_their_part_of_the_cap() {
        // Thousands of single files changed, each beside one that stayed: every one is an entry
        // of its own, too many to keep. The counts stay exact, the entries are the first in
        // path order, and the record as written fits the cap.
        let mut before = Vec::new();
        let mut now = Vec::new();
        for i in 0..3_000 {
            let (changed, kept) = (format!("d{i:04}/a.js"), format!("d{i:04}/kept"));
            before.push((changed.clone(), "1"));
            now.push((changed, "2"));
            before.push((kept.clone(), "1"));
            now.push((kept, "1"));
        }
        let as_list = |v: &[(String, &str)]| {
            list(&v.iter().map(|(p, t)| (p.as_str(), *t)).collect::<Vec<_>>())
        };
        let c = compare(&as_list(&before), &as_list(&now)).unwrap();
        assert_eq!(c.changed.count, 3_000);
        let entries = told(&c.changed);
        assert!(
            entries.len() > 50 && entries.len() < 3_000,
            "{}",
            entries.len()
        );
        for (i, (path, folder, files)) in entries.iter().enumerate() {
            assert_eq!(
                (*path, *folder, *files),
                (format!("d{i:04}/a.js").as_str(), false, 1)
            );
        }
        // Removed and added as well, so that all three parts are full.
        let gone: Vec<(String, &str)> = before.iter().map(|(p, t)| (format!("{p}x"), *t)).collect();
        let mut both = as_list(&before);
        both.extend(as_list(&gone));
        let mut after = as_list(&now);
        after.extend(as_list(
            &gone
                .iter()
                .map(|(p, t)| (format!("{p}y"), *t))
                .collect::<Vec<_>>(),
        ));
        let c = compare(&both, &after).unwrap();
        assert_eq!(
            (c.added.count, c.removed.count, c.changed.count),
            (6_000, 6_000, 3_000)
        );
        let written = serde_json::to_vec(&c).unwrap();
        assert!(
            written.len() as u64 <= super::CHANGES_CAP,
            "{}",
            written.len()
        );
        assert!(
            written.len() as u64 > super::CHANGES_CAP - 4_096,
            "{}",
            written.len()
        );
    }

    #[test]
    fn an_entry_that_fills_its_part_to_the_byte_is_kept_and_the_next_is_not() {
        // Each entry takes its JSON and a comma: 47 bytes for `dNNNN/a.js`, and 456 of them
        // leave 72 bytes of the part, which an entry of a 35-byte path fills exactly.
        let mut before = vec![("kept".to_string(), "1")];
        let mut now = before.clone();
        let mut paths: Vec<String> = (0..456).map(|i| format!("d{i:04}/a.js")).collect();
        paths.push(format!("d0456/{}.js", "b".repeat(26)));
        paths.push("d0457/a.js".to_string());
        for p in &paths {
            before.push((p.clone(), "1"));
            now.push((p.clone(), "2"));
        }
        let as_list = |v: &[(String, &str)]| {
            list(&v.iter().map(|(p, t)| (p.as_str(), *t)).collect::<Vec<_>>())
        };
        let c = compare(&as_list(&before), &as_list(&now)).unwrap();
        assert_eq!(super::PART, 21_504);
        assert_eq!(c.changed.entries.len(), 457);
        assert_eq!(c.changed.entries[456].path, paths[456]);
    }
}
