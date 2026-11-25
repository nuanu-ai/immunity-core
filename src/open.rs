//! Every file the core reads is opened here, one way, and `scripts/lint.sh` fails a read of a
//! file anywhere else outside `store.rs` and `service.rs`.
//!
//! The path is looked at first, by `lstat`: an error there is the only one a reader may take
//! as nothing there (`look::Absent`), and anything but a regular file is refused by what it is
//! and never opened. Then it is opened to read, without waiting (`O_NONBLOCK`) and without
//! becoming the terminal of the process (`O_NOCTTY`), by the rule of its `Reach` for links;
//! what was opened is looked at again, and anything but a regular file is refused. A file over
//! the cap is refused before a byte is read, and what is read stops one byte past it, for a
//! file that grows. Gone or a link at the open, after the first look found a file, is a change.
//!
//! Not opened relative to a folder's descriptor: a folder swapped for a link while the path is
//! made real is a stated limit.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// What a path is, which says what links its open may pass.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Reach {
    /// A place on the Mac, made real by the reader (`guarded::real` and its kin): no part may
    /// be a link at the open (`O_NOFOLLOW_ANY`), so a part that became one since is not
    /// followed out of the place or into a folder macOS asks permission for.
    Place,
    /// A file of the core's own, in the store's folder: a link in its last part is refused
    /// (`O_NOFOLLOW`); the folders above may be reached through links.
    Own,
    /// A file a person names by a flag: made real as given, since following it is asked for,
    /// then opened as `Own`.
    Given,
}

/// No cap: for a reader that has none today.
pub const UNCAPPED: u64 = u64::MAX;

/// Why a file was not read.
#[derive(Debug)]
pub enum Refused {
    /// The first look failed, as the system said: nothing there is `look::Absent`'s to tell.
    Look(std::io::Error),
    /// Not a regular file, at the first look or as opened: what it is.
    Kind(&'static str),
    /// Larger than this cap, in bytes.
    Over(u64),
    /// Gone, or a link, at the open, after the first look found a regular file.
    Changed,
    /// The system would not open or read it.
    Failed(std::io::Error),
}

/// Why a file that changed between the first look and the open was not read.
pub const CHANGED: &str = "it changed while it was read";

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Refused::Look(e) | Refused::Failed(e) => write!(f, "{e}"),
            Refused::Kind(what) => write!(f, "a {what}, not a regular file"),
            Refused::Over(cap) => write!(f, "over the size cap of {} KiB", cap >> 10),
            Refused::Changed => f.write_str(CHANGED),
        }
    }
}

impl std::error::Error for Refused {}

/// The regular file at `path`, opened to read, with its metadata as opened.
pub fn open(path: &Path, reach: Reach, cap: u64) -> Result<(File, Metadata), Refused> {
    let given;
    let path = match reach {
        Reach::Given => {
            given = std::fs::canonicalize(path);
            given.as_deref().unwrap_or(path)
        }
        _ => path,
    };
    let first = std::fs::symlink_metadata(path).map_err(Refused::Look)?;
    if !first.is_file() {
        return Err(Refused::Kind(kind_of(first.file_type())));
    }
    opened(path, reach, cap)
}

/// `path` opened, after the first look found a regular file there.
fn opened(path: &Path, reach: Reach, cap: u64) -> Result<(File, Metadata), Refused> {
    let links = match reach {
        Reach::Place => libc::O_NOFOLLOW_ANY,
        Reach::Own | Reach::Given => libc::O_NOFOLLOW,
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | links)
        .open(path);
    let file = match file {
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ELOOP)) => {
            return Err(Refused::Changed);
        }
        Err(e) => return Err(Refused::Failed(e)),
        Ok(file) => file,
    };
    let opened = file.metadata().map_err(Refused::Failed)?;
    if !opened.is_file() {
        return Err(Refused::Kind(kind_of(opened.file_type())));
    }
    if opened.len() > cap {
        return Err(Refused::Over(cap));
    }
    Ok((file, opened))
}

/// The bytes of the regular file at `path`, at most `cap` of them (`open`).
pub fn read(path: &Path, reach: Reach, cap: u64) -> Result<Vec<u8>, Refused> {
    bounded(open(path, reach, cap)?.0, cap)
}

/// What `from` holds, read one byte past `cap` for a file that grew since it was looked at.
fn bounded(from: impl Read, cap: u64) -> Result<Vec<u8>, Refused> {
    let mut bytes = Vec::new();
    match from.take(cap.saturating_add(1)).read_to_end(&mut bytes) {
        Err(e) => Err(Refused::Failed(e)),
        Ok(_) if bytes.len() as u64 > cap => Err(Refused::Over(cap)),
        Ok(_) => Ok(bytes),
    }
}

/// What a thing that is not a regular file is, by its own metadata.
pub fn kind_of(t: std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if t.is_symlink() {
        "symbolic link"
    } else if t.is_dir() {
        "folder"
    } else if t.is_fifo() {
        "fifo"
    } else if t.is_socket() {
        "socket"
    } else if t.is_block_device() {
        "block device"
    } else {
        "character device"
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    /// What `f` returns, or `None` when it waited past ten seconds.
    pub fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(f()));
        rx.recv_timeout(Duration::from_secs(10)).ok()
    }

    /// In `dir`: a named pipe, a link to `/dev/zero`, a folder, a file of four bytes and a name
    /// with nothing at it.
    pub fn refusals(dir: &Path) -> [PathBuf; 5] {
        let all = ["pipe", "zero", "folder", "four", "missing"].map(|n| dir.join(n));
        let c = std::ffi::CString::new(all[0].to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        std::os::unix::fs::symlink("/dev/zero", &all[1]).unwrap();
        std::fs::create_dir(&all[2]).unwrap();
        std::fs::write(&all[3], "four").unwrap();
        all
    }

    #[test]
    fn nothing_but_a_regular_file_within_its_cap_is_read_and_only_the_first_look_says_nothing_is_there()
     {
        let dir = crate::common::Scratch::new("open-refused");
        let [pipe, zero, folder, four, missing] = refusals(&dir);
        for reach in [Reach::Place, Reach::Own, Reach::Given] {
            let read = |p: &PathBuf, cap| {
                let p = p.clone();
                within(move || read(&p, reach, cap)).expect("the open waited")
            };
            assert!(matches!(read(&pipe, 64), Err(Refused::Kind("fifo"))));
            assert!(matches!(read(&folder, 64), Err(Refused::Kind("folder"))));
            let zero = read(&zero, 64);
            match reach {
                // Made real as given: the device it leads to.
                Reach::Given => assert!(matches!(zero, Err(Refused::Kind("character device")))),
                _ => assert!(matches!(zero, Err(Refused::Kind("symbolic link")))),
            }
            assert!(matches!(read(&four, 3), Err(Refused::Over(3))), "{reach:?}");
            assert_eq!(read(&four, 4).unwrap(), b"four");
            let Err(Refused::Look(e)) = read(&missing, 64) else {
                panic!("not the first look");
            };
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            // Opened to stream, a file over the cap is refused before a byte is read.
            assert!(matches!(open(&four, reach, 3), Err(Refused::Over(3))));
        }
        // A file that grew past the cap after it was looked at is not read short.
        assert!(matches!(bounded(&b"four"[..], 3), Err(Refused::Over(3))));
    }

    #[test]
    fn what_was_opened_is_refused_unless_a_regular_file_and_the_open_follows_no_link_it_must_not() {
        // Between the first look and the open a file may become a pipe, a device or a link.
        let dir = crate::common::Scratch::new("open-changed");
        let [pipe, _, folder, four, missing] = refusals(&dir);
        let opened = |p: &Path, reach| {
            let p = p.to_path_buf();
            within(move || opened(&p, reach, 64).map(|_| ())).expect("the open waited")
        };
        assert!(matches!(
            opened(&pipe, Reach::Place),
            Err(Refused::Kind("fifo"))
        ));
        let dev = opened(Path::new("/dev/null"), Reach::Own);
        assert!(matches!(dev, Err(Refused::Kind("character device"))));
        assert!(matches!(
            opened(&folder, Reach::Own),
            Err(Refused::Kind("folder"))
        ));
        assert!(matches!(
            opened(&missing, Reach::Place),
            Err(Refused::Changed)
        ));
        // A link in the last part, for either; a link above it, for a place only.
        std::os::unix::fs::symlink(&four, dir.join("last")).unwrap();
        std::os::unix::fs::symlink(&*dir, dir.join("above")).unwrap();
        let above = dir.join("above/four");
        for reach in [Reach::Place, Reach::Own] {
            assert!(matches!(
                opened(&dir.join("last"), reach),
                Err(Refused::Changed)
            ));
        }
        assert!(matches!(
            opened(&above, Reach::Place),
            Err(Refused::Changed)
        ));
        assert!(opened(&above, Reach::Own).is_ok());
        assert!(opened(&four, Reach::Place).is_ok());
    }
}
