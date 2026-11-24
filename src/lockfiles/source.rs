//! Where a lockfile entry comes from, and how that is kept in a component's name.

/// Where a lockfile entry comes from. A closed set: only `Registry`, the ecosystem's public
/// registry, is what the ecosystem's open vulnerability data speaks of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// npm's public registry; for Cargo, crates.io.
    Registry,
    Git,
    /// A file, a link or a folder on disk: npm's `file:` and linked entries, Cargo's path and
    /// workspace crates.
    Path,
    /// Any other registry, or an address that is not the public registry's.
    OtherRegistry,
    /// The lockfile gives the name and the version and does not record which index the package
    /// comes from, as `pdm.lock` by default or a hashed `requirements.txt` that names no index:
    /// the tool takes it from whatever index it is set up with. A reader gives this for an entry
    /// that has everything the registry's own entry would have, a version in the ecosystem's
    /// canonical form and files that pass the registry's file-name rule, except a record of the
    /// index. Such an entry is compared with the registry's records, and a release they do not
    /// hold is never "does not affect me, known for certain": a private index can serve its own
    /// build under the same name and version.
    UnrecordedIndex,
}

impl Source {
    /// Each source but the public registry: the words in brackets after a component's name, and
    /// where an answer says the entry comes from.
    const SAID: [(Source, &'static str, &'static str); 4] = [
        (Source::Git, "git", "git"),
        (Source::Path, "path", "a path"),
        (Source::OtherRegistry, "other registry", "another registry"),
        (
            Source::UnrecordedIndex,
            "unrecorded index",
            "an unrecorded index",
        ),
    ];

    /// Where an entry of this source comes from, in the words an answer gives.
    pub fn said(self) -> &'static str {
        (Self::SAID.iter())
            .find(|(s, _, _)| *s == self)
            .map_or("registry", |(_, _, said)| said)
    }
}

/// The name part of a component's id: the real name, and for any source but the public registry
/// the source in brackets.
pub fn component_name(name: &str, source: Source) -> String {
    match Source::SAID.iter().find(|(s, _, _)| *s == source) {
        Some((_, bracket, _)) => format!("{name} ({bracket})"),
        None => name.to_string(),
    }
}

/// The name part of a component's id told apart: the package's name, and where it comes from.
/// The inverse of `component_name`. Applied to a whole component id, it gives the id of the
/// package under its plain name.
pub fn split_name(name: &str) -> (&str, Source) {
    for (source, bracket, _) in Source::SAID {
        let package = (name.strip_suffix(')'))
            .and_then(|n| n.strip_suffix(bracket))
            .and_then(|n| n.strip_suffix(" ("));
        if let Some(package) = package {
            return (package, source);
        }
    }
    (name, Source::Registry)
}
