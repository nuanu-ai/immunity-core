//! The commit a checkout is at, read from its `.git` folder. The lockfiles reader records it
//! beside the lockfiles it lists.
//! Each file of git is read as a regular file, without waiting and up to a cap; one refused
//! leaves the commit unknown, as one that cannot be read does.

use crate::worktrees::pointer;
use std::path::{Component, Path, PathBuf};

/// The commit the checkout is at, read from `.git` by hand, or `unknown`. `Err` names the
/// folder macOS asks permission for that the git folder is in, which is not entered; `homes`
/// are the home folder's names.
pub fn commit(checkout: &Path, homes: &[&Path]) -> Result<String, PathBuf> {
    Ok(read_commit(checkout, homes, super::CAP)?.unwrap_or_else(|| "unknown".to_string()))
}

/// `commit`, with `packed-refs` read up to `cap`.
fn read_commit(checkout: &Path, homes: &[&Path], cap: u64) -> Result<Option<String>, PathBuf> {
    // `.git` itself may be a link, which is not followed into a guarded folder.
    let dotgit = crate::guarded::followed(&checkout.join(".git"), homes)?;
    // A worktree or a submodule has a `.git` file that points at the real folder. Where it
    // points is data, so it is made real without entering a guarded folder.
    let real = |p: PathBuf| match crate::guarded::real(&p, homes) {
        crate::guarded::Real::At(p) => Ok(Some(p)),
        crate::guarded::Real::Guarded(g) => Err(g),
        crate::guarded::Real::Failed(_) => Ok(None),
    };
    let gitdir = if dotgit.is_dir() {
        dotgit
    } else {
        let Some(to) = pointer(&dotgit, homes)
            .and_then(|text| Some(text.strip_prefix("gitdir:")?.trim().to_string()))
        else {
            return Ok(None);
        };
        match real(checkout.join(to))? {
            Some(p) => p,
            None => return Ok(None),
        }
    };
    let commondir = gitdir.join("commondir");
    let common = match pointer(&commondir, homes) {
        Some(to) => match real(gitdir.join(to))? {
            Some(p) => p,
            None => return Ok(None),
        },
        // Without a `commondir` the git folder is the common one; one there and refused
        // leaves the commit unknown.
        None if std::fs::symlink_metadata(&commondir).is_err() => gitdir.clone(),
        None => return Ok(None),
    };
    head_commit(&gitdir, &common, homes, cap)
}

fn head_commit(
    gitdir: &Path,
    common: &Path,
    homes: &[&Path],
    cap: u64,
) -> Result<Option<String>, PathBuf> {
    let Some(head) = pointer(&gitdir.join("HEAD"), homes) else {
        return Ok(None);
    };
    let Some(name) = head.strip_prefix("ref:").map(str::trim) else {
        return Ok(is_hash(&head).then_some(head));
    };
    // A ref names a file under the git folder: an absolute name or one with `..` would name a
    // file elsewhere, and is not opened.
    if !(Path::new(name).components()).all(|c| matches!(c, Component::Normal(_))) {
        return Ok(None);
    }
    for dir in [gitdir, common] {
        // The name of the ref is data: the file it names is not looked for in a guarded
        // folder. A ref file there and refused is not passed over for `packed-refs`.
        match crate::guarded::real(&dir.join(name), homes) {
            crate::guarded::Real::Guarded(g) => return Err(g),
            crate::guarded::Real::At(path) => {
                return Ok(pointer(&path, homes).filter(|hash| is_hash(hash)));
            }
            crate::guarded::Real::Failed(_) => continue,
        }
    }
    let packed = crate::open::read(&common.join("packed-refs"), crate::open::Reach::Place, cap);
    let packed = packed.ok();
    let Some(packed) = packed.and_then(|bytes| String::from_utf8(bytes).ok()) else {
        return Ok(None);
    };
    Ok(packed.lines().find_map(|line| {
        let (hash, refname) = line.split_once(' ')?;
        (refname.trim() == name && is_hash(hash)).then(|| hash.to_string())
    }))
}

fn is_hash(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::super::CAP;
    use super::read_commit;
    use crate::common::Scratch;
    use std::path::{Path, PathBuf};

    const HASH: &str = "0123456789abcdef0123456789abcdef01234567";

    /// A checkout `shop` under an invented home, whose `.git` folder holds `files`.
    fn checkout(tag: &str, files: &[(&str, &str)]) -> (Scratch, PathBuf) {
        let dir = Scratch::new(tag);
        let shop = dir.join("home/dev/shop");
        std::fs::create_dir_all(&shop).unwrap();
        for (name, text) in files {
            let path = shop.join(".git").join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        (dir, shop)
    }

    fn fifo(path: &Path) {
        let _ = std::fs::remove_file(path);
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    /// The commit read with `packed-refs` capped at `cap`, or `None` when the read has not
    /// returned in ten seconds: a read that waits fails the test instead of holding the suite.
    fn within(shop: &Path, cap: u64) -> Option<Result<Option<String>, PathBuf>> {
        let (shop, (tx, rx)) = (shop.to_path_buf(), std::sync::mpsc::channel());
        let home = shop.parent().unwrap().parent().unwrap().to_path_buf();
        std::thread::spawn(move || tx.send(read_commit(&shop, &[&home], cap)));
        rx.recv_timeout(std::time::Duration::from_secs(10)).ok()
    }

    #[test]
    fn a_pipe_a_device_or_a_file_of_git_over_its_cap_leaves_the_commit_unknown_and_never_holds_the_run()
     {
        // Any `.git` makes a folder a checkout, and a cloned or unpacked one can hold a named
        // pipe, which a plain read waits on forever, or a link to a device that never ends.
        // A loose ref refused is not passed over for the one `packed-refs` holds.
        let (main, packed) = (format!("{HASH}\n"), format!("{HASH} refs/heads/main\n"));
        let files = [
            ("HEAD", "ref: refs/heads/main\n"),
            ("refs/heads/main", main.as_str()),
            ("packed-refs", packed.as_str()),
        ];
        let (_dir, shop) = checkout("commit-ordinary", &files);
        assert_eq!(within(&shop, CAP), Some(Ok(Some(HASH.to_string()))));
        for file in ["HEAD", "refs/heads/main", "commondir"] {
            let (_dir, shop) = checkout("commit-fifo", &files);
            fifo(&shop.join(".git").join(file));
            assert_eq!(within(&shop, CAP), Some(Ok(None)), "{file}");
        }
        let (_dir, shop) = checkout("commit-packed-fifo", &files[..1]);
        fifo(&shop.join(".git/packed-refs"));
        assert_eq!(within(&shop, CAP), Some(Ok(None)));
        let (_dir, shop) = checkout("commit-dotgit-fifo", &[]);
        fifo(&shop.join(".git"));
        assert_eq!(within(&shop, CAP), Some(Ok(None)));
        let (_dir, shop) = checkout("commit-head-over", &files);
        let over = format!("ref: refs/heads/main\n{}", " ".repeat(4096));
        std::fs::write(shop.join(".git/HEAD"), over).unwrap();
        assert_eq!(within(&shop, CAP), Some(Ok(None)));
        // Last: a plain read of a device that never ends does not return to fail the test.
        let (_dir, shop) = checkout("commit-head-device", &files);
        std::fs::remove_file(shop.join(".git/HEAD")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", shop.join(".git/HEAD")).unwrap();
        assert_eq!(within(&shop, CAP), Some(Ok(None)));
    }

    #[test]
    fn a_packed_refs_over_the_cap_leaves_the_commit_unknown() {
        let packed = format!("# pack-refs with: peeled sorted\n{HASH} refs/heads/main\n");
        let files = [
            ("HEAD", "ref: refs/heads/main\n"),
            ("packed-refs", packed.as_str()),
        ];
        let (_dir, shop) = checkout("commit-packed-cap", &files);
        let size = packed.len() as u64;
        assert_eq!(within(&shop, size), Some(Ok(Some(HASH.to_string()))));
        assert_eq!(within(&shop, size - 1), Some(Ok(None)));
    }

    #[test]
    fn a_ref_that_names_a_file_outside_the_git_folder_is_never_opened() {
        // A hash in a file elsewhere is no commit of this checkout, and `/dev/zero` would be
        // read without end.
        let (dir, shop) = checkout("commit-ref-outside", &[("HEAD", "")]);
        std::fs::write(dir.join("outside"), format!("{HASH}\n")).unwrap();
        let absolute = format!("ref: {}\n", dir.join("outside").display());
        for head in [
            absolute.as_str(),
            "ref: ../../../../outside\n",
            "ref: /dev/zero\n",
        ] {
            std::fs::write(shop.join(".git/HEAD"), head).unwrap();
            assert_eq!(within(&shop, CAP), Some(Ok(None)), "{head}");
        }
    }
}
