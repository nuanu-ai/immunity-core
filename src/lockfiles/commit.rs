//! The commit a checkout is at, read from its `.git` folder. The lockfiles reader records it
//! beside the lockfiles it lists.

use std::path::{Path, PathBuf};

/// The commit the checkout is at, read from `.git` by hand, or `unknown`. `Err` names the
/// folder macOS asks permission for that the git folder is in, which is not entered; `homes`
/// are the home folder's names.
pub fn commit(checkout: &Path, homes: &[&Path]) -> Result<String, PathBuf> {
    Ok(read_commit(checkout, homes)?.unwrap_or_else(|| "unknown".to_string()))
}

fn read_commit(checkout: &Path, homes: &[&Path]) -> Result<Option<String>, PathBuf> {
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
        let Some(to) = std::fs::read_to_string(&dotgit)
            .ok()
            .and_then(|text| Some(text.trim().strip_prefix("gitdir:")?.trim().to_string()))
        else {
            return Ok(None);
        };
        match real(checkout.join(to))? {
            Some(p) => p,
            None => return Ok(None),
        }
    };
    let common = match std::fs::read_to_string(gitdir.join("commondir")) {
        Ok(text) => match real(gitdir.join(text.trim()))? {
            Some(p) => p,
            None => return Ok(None),
        },
        Err(_) => gitdir.clone(),
    };
    head_commit(&gitdir, &common, homes)
}

fn head_commit(gitdir: &Path, common: &Path, homes: &[&Path]) -> Result<Option<String>, PathBuf> {
    let Ok(head) = std::fs::read_to_string(gitdir.join("HEAD")) else {
        return Ok(None);
    };
    let head = head.trim();
    let Some(name) = head.strip_prefix("ref:").map(str::trim) else {
        return Ok(is_hash(head).then(|| head.to_string()));
    };
    for dir in [gitdir, common] {
        // The name of the ref is data: the file it names is not looked for in a guarded
        // folder.
        let path = match crate::guarded::real(&dir.join(name), homes) {
            crate::guarded::Real::Guarded(g) => return Err(g),
            crate::guarded::Real::At(path) => path,
            crate::guarded::Real::Failed(_) => continue,
        };
        if let Ok(hash) = std::fs::read_to_string(path) {
            let hash = hash.trim();
            return Ok(is_hash(hash).then(|| hash.to_string()));
        }
    }
    let Ok(packed) = std::fs::read_to_string(common.join("packed-refs")) else {
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
