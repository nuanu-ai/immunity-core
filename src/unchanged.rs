//! A reading of files that a full check does not do again. A full reading records beside its
//! coverage the files it opened: each by its path as the reading names it, with the SHA-256 of
//! its bytes and the build that read it. When the reading's latest coverage carries
//! that record and the files it would open now are the same files with the same bytes, read by
//! the same build, the reading would write what it wrote then: its statements are the facts
//! the store holds, and promoting them again changes no fact and journals nothing. So it is not
//! done; the check writes the coverage that reading writes, as this run's, and moves the record
//! to it.
//!
//! Three rules make the record say exactly that:
//! - only a full reading writes a record, and the record that counts is the one on the latest
//!   coverage of the reading, so a partial, failed or retired reading since leaves none;
//! - the record goes with the facts of its reading. Facts become live only by a reading of their
//!   own, which writes coverage of its own, and leave by one of three ways: a reading of the
//!   same reader, scope and kind (`lifecycle::promote`, `lifecycle::retire`), which writes new
//!   coverage; `look::retire_facts`, for the watched places, which keep no record; or because
//!   what holds them is gone (`lifecycle::retract_inside`), which lets go of the record
//!   (`forget`). A fact changed in the store by another program is not guarded, as nothing
//!   the store holds is against a program that targets it;
//! - the build is the running program's own code, so a reader that changed reads again.
//!
//! A reading whose files cannot all be hashed now, one that could not be opened among them, is
//! not compared: it is read, and says what it could not read.

use crate::store::Reading;
use rusqlite::{Connection, params};
use std::sync::OnceLock;

/// The record of the files a full reading opened, beside its coverage.
pub const SCHEMA: &str = "
CREATE TABLE coverage_file (
    coverage INTEGER NOT NULL REFERENCES coverage (id) ON DELETE CASCADE,
    path     TEXT NOT NULL,     -- as the reading's ids name it
    sha256   TEXT NOT NULL,     -- of its bytes as read
    build    TEXT NOT NULL,     -- the build that read them (`unchanged::build`)
    PRIMARY KEY (coverage, path)
) WITHOUT ROWID;
";

/// One file a reading opened.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct File {
    pub path: String,
    pub sha256: String,
}

/// The latest coverage of the reading `r` names.
const LATEST: &str =
    "(SELECT MAX(id) FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3)";

/// Whether the latest reading of what `r` names recorded exactly `files`, each with the same
/// SHA-256, read by this build: then reading them again writes nothing but its
/// coverage.
pub fn same(conn: &Connection, r: &Reading, files: &[File]) -> rusqlite::Result<bool> {
    let mut recorded: Vec<(File, String)> = conn
        .prepare(&format!(
            "SELECT path, sha256, build FROM coverage_file WHERE coverage = {LATEST}"
        ))?
        .query_map(params![r.reader, r.scope, r.kind], |row| {
            let file = File {
                path: row.get(0)?,
                sha256: row.get(1)?,
            };
            Ok((file, row.get(2)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let Some(build) = build() else {
        return Ok(false);
    };
    let mut now: Vec<(File, String)> = (files.iter().cloned())
        .map(|f| (f, build.to_string()))
        .collect();
    recorded.sort();
    now.sort();
    Ok(recorded == now)
}

/// Lets go of the record of every reading of `scope`, whose facts were just retracted. The
/// record is small, one row for each file of each project's latest reading, so it is looked
/// through whole rather than through every reading of the store.
pub fn forget(conn: &Connection, scope: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM coverage_file WHERE coverage IN
             (SELECT f.coverage FROM coverage_file f JOIN coverage c ON c.id = f.coverage
              WHERE c.scope = ?1)",
        [scope],
    )?;
    Ok(())
}

/// Records `files` beside the latest coverage of the reading `r` names, a full reading's, and
/// lets go of the record of every reading of it before.
pub fn record(conn: &Connection, r: &Reading, files: &[File]) -> rusqlite::Result<()> {
    let Some(build) = build() else {
        return Ok(());
    };
    conn.execute(
        "DELETE FROM coverage_file WHERE coverage IN
             (SELECT id FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3)",
        params![r.reader, r.scope, r.kind],
    )?;
    let mut put = conn.prepare(&format!(
        "INSERT INTO coverage_file (coverage, path, sha256, build)
         VALUES ({LATEST}, ?4, ?5, ?6)"
    ))?;
    for f in files {
        put.execute(params![r.reader, r.scope, r.kind, f.path, f.sha256, build])?;
    }
    Ok(())
}

/// The build that reads: the SHA-256 of the running program's own `__TEXT` segment, its code
/// and constants as they are in memory, which nothing on disk changes while it runs. A reader
/// that changed, or anything it is built with, is a new build, and every reading of files is
/// done again once. Taken from what macOS ships: the main image's header from dyld and its
/// segment from `getsegmentdata`; the bytes are hashed, not parsed. `None` when either cannot
/// be had: then no reading is recorded or compared.
pub fn build() -> Option<&'static str> {
    static BUILD: OnceLock<Option<String>> = OnceLock::new();
    let built = BUILD.get_or_init(|| {
        unsafe extern "C" {
            /// `_dyld_get_image_header` from `<mach-o/dyld.h>`: the header of a loaded image,
            /// image 0 being the main executable.
            fn _dyld_get_image_header(image_index: u32) -> *const std::ffi::c_void;
            /// `getsegmentdata` from `<mach-o/getsect.h>`: the address of the named segment of
            /// the image whose header is `mhp`, slid as it is loaded, and its size.
            fn getsegmentdata(
                mhp: *const std::ffi::c_void,
                segname: *const libc::c_char,
                size: *mut libc::c_ulong,
            ) -> *const u8;
        }
        let mut size: libc::c_ulong = 0;
        // SAFETY: image 0 is the main executable, loaded for as long as the process runs; the
        // segment `getsegmentdata` returns is mapped readable for its whole size.
        unsafe {
            let header = _dyld_get_image_header(0);
            if header.is_null() {
                return None;
            }
            let at = getsegmentdata(header, c"__TEXT".as_ptr(), &mut size);
            let text = (!at.is_null() && size > 0)
                .then(|| std::slice::from_raw_parts(at, size as usize))?;
            Some(crate::sha256::hex(text))
        }
    });
    built.as_deref()
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_build_is_the_hash_of_this_program_s_own_code_and_never_of_nothing() {
        // A record names the build that read; a build that could not be told, or the hash of
        // no bytes, would let one build's record stand for another's.
        let build = super::build().unwrap();
        assert_eq!(build.len(), 64);
        assert!(build.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(build, crate::sha256::hex(b""));
        assert_eq!(super::build(), Some(build));
    }
}
