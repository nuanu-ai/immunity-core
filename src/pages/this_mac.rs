//! The page of what is watched on this Mac, kind by kind: first an index of what is read, the
//! summary's rows for this Mac and its projects (`read_index`); then what each kind is and which
//! rule tells of a change in it, its things, the ways a project or the home folder runs code by
//! itself and the projects found. What could not be read is told on the summary. Drawn from what
//! `immunity machine` answers for this Mac (`Known`) and from the status: whether a list may say
//! that nothing is there is the status's word for its kind (`WatchedKind.coverage` and `fresh`,
//! `IntegrityReading`), never an empty list's. The readings `Known` gives name what was not read,
//! their reasons given whole and cut on the page (`Said::of`). Every name and reason from the Mac
//! is printed through `secrets::Name` and `secrets::Said`.

use super::{FOOT, THIS_MAC_TITLE, VULNERABILITIES, anchor, capital};
use super::{coverage_of_list, grouped, installed_whole, said, top, unread};
use crate::contract::{self, v1};
use crate::covered::{self, Count, Latest};
use crate::findings::{self, This};
use crate::secrets::{Name, Said};
use crate::view::{self, Out, cell, counted, esc, when};
use crate::{autorun, integrity, watched};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// What each kind of watched thing is, in a line.
fn about(what: &str) -> &'static str {
    match what {
        "startup items" => {
            "Programs macOS starts by itself when you log in or the Mac starts: the usual way for something unwanted to stay on a Mac."
        }
        covered::LOGIN_HOOKS => {
            "Scripts the login window runs with full control at every login and logout, a way Apple replaced years ago."
        }
        "shell startup files" => "Files your terminal runs every time it opens a shell.",
        "SSH files" => "Your SSH settings, and the keys allowed to log in to this Mac.",
        covered::LOGIN_MODULES => {
            "The rules and plugins that decide how you log in, unlock and approve an administrator action, and how your password is checked."
        }
        "git hooks in projects" => {
            "Scripts git runs by itself in your projects, for example before a commit."
        }
        "applications" => "Applications in the Applications folders, with who signed each.",
        "Homebrew packages" => "What Homebrew installed in /opt/homebrew or /usr/local.",
        "npm packages" => {
            "Packages npm installed for every project at once in /opt/homebrew/lib/node_modules or /usr/local/lib/node_modules."
        }
        "app code kept outside the app" => {
            "Code that applications not made by Apple keep in your Library folder, outside the application itself."
        }
        covered::DEPENDENCIES => {
            "Packages your projects list in their crates.io, npm and PyPI lockfiles, compared at every check with the known vulnerabilities and malicious packages of those ecosystems."
        }
        _ => crate::autorun::about(what),
    }
}

/// A kind of thing that is listed as watched and that no rule speaks about.
const KEPT_AS_LIST: &str = "Kept as a list. Nothing tells you about a change here in this version.";
/// The mark of a rule whose findings notify at once.
const NOTIFIES: &str = "Sends a notification";
/// What an empty list says when the status says its kind was read in full and fresh.
const NONE_FOUND: &str = "None found here.";
/// The same for a kind kept in projects while projects were not looked for everywhere.
const NONE_IN_FOUND: &str = "None in the projects found.";
/// What a list says that is not whole when no reading the answer gives names why.
const NOT_WHOLE: &str = "Not read in full, so this list may not be whole.";

/// What the owner is told about: each rule's title and what it means, marked where its
/// findings notify at once; for no rule, that the thing is only kept as a list.
fn told(out: &mut String, rules: &[findings::Rule]) -> Out {
    if rules.is_empty() {
        writeln!(out, "<p class=\"muted\">{}</p>", esc(KEPT_AS_LIST))?;
        return Ok(());
    }
    out.push_str("<ul class=\"rules\">\n");
    for r in rules {
        let mark = match findings::urgent(r.severity, Some(r.confidence)) {
            true => format!(" <span class=\"badge notify\">{NOTIFIES}</span>"),
            false => String::new(),
        };
        writeln!(
            out,
            "<li>{}{mark}<br><span class=\"muted\">{}</span></li>",
            esc(r.words.title),
            esc(r.words.meaning)
        )?;
    }
    out.push_str("</ul>\n");
    Ok(())
}

/// The rules with one id, as `told` takes them.
fn rule_with(id: &str) -> Vec<findings::Rule> {
    (findings::rules().into_iter())
        .filter(|r| r.id == id)
        .collect()
}

/// What the page reads of the two answers.
struct Mac<'a> {
    m: &'a v1::Known,
    /// This Mac's id and name, from the status.
    this: Option<This>,
    /// The facts of the answer by subject, each as the store names it.
    facts: BTreeMap<String, Vec<&'a v1::Fact>>,
    /// When the latest full check began: a reading before it speaks for no list.
    latest_run: Option<i64>,
    /// That check's id, as `Coverage.run_id` names runs.
    latest_run_id: Option<&'a str>,
    /// Whether projects were looked for everywhere but where this version does not enter, and
    /// why not when a reading failed (`covered::projects_found`, as the status gives it).
    found: Option<&'a v1::ProjectsFound>,
}

impl Mac<'_> {
    /// Whether projects were not looked for in folders this version does not enter: what is
    /// said of projects is said of the projects found.
    fn not_entered(&self) -> bool {
        self.found
            .is_some_and(|f| !f.all && v1::Cause::try_from(f.cause) == Ok(v1::Cause::NotGiven))
    }

    /// Why the projects may not all be found, by a reading that failed, in the core's words as
    /// safe HTML; also when the status gives no answer about them, which is never "all".
    fn failed_walk(&self) -> Option<String> {
        match self.found {
            Some(f) if f.all || self.not_entered() => None,
            Some(f) => Some(esc(f
                .why
                .as_deref()
                .unwrap_or("projects were not all found"))),
            None => Some("projects have not been looked for yet".to_string()),
        }
    }

    /// The answer's readings on this Mac of a reader and some kinds, as `unread` takes them.
    fn readings(&self, reader: &str, kinds: &[String]) -> Vec<Latest> {
        let this = self.this.as_ref().map(|t| t.id.as_str());
        (self.m.coverage.iter())
            .filter(|c| c.reader == reader && kinds.contains(&c.kind))
            .filter(|c| {
                this.is_some_and(|t| {
                    covered::on_this_mac_or_in(&contract::unescape(&c.scope_text), t)
                })
            })
            .map(latest_of)
            .collect()
    }

    /// What a list cannot claim: nothing when `whole`, the status's word, and nothing else it
    /// rests on (`extra`) is short; else the readings that are not full and fresh, named, with
    /// what else is short.
    fn gap(&self, whole: bool, readings: &[Latest], extra: &[String], now: i64) -> Option<String> {
        if whole && extra.is_empty() {
            return None;
        }
        let refs: Vec<&Latest> = readings.iter().collect();
        Some(unread(&refs, self.latest_run, now, extra).unwrap_or_else(|| NOT_WHOLE.to_string()))
    }

    /// Where a thing is, as a person recognises it (`findings::place`), as the printer prints it.
    fn place(&self, id_text: &str) -> String {
        let place = findings::place(&contract::unescape(id_text), self.this.as_ref());
        Name::of(&place).html()
    }

    /// The values of one predicate of a subject.
    fn values(&self, subject: &str, predicate: &str) -> Vec<&v1::Fact> {
        (self.facts.get(subject).into_iter().flatten().copied())
            .filter(|f| f.predicate == predicate)
            .collect()
    }
}

/// A reading of the answer as `unread` reads one: its reason taken whole, cut where it is said.
fn latest_of(c: &v1::Coverage) -> Latest {
    let completeness = v1::Completeness::try_from(c.completeness).map_or("none", |c| match c {
        v1::Completeness::Full => "full",
        v1::Completeness::Partial => "partial",
        _ => "none",
    });
    Latest {
        reader: c.reader.clone(),
        scope: contract::unescape(&c.scope_text),
        kind: c.kind.clone(),
        completeness: completeness.to_string(),
        reason: c.reason_text.as_deref().map(contract::unescape),
        at: c.observed_at.unwrap_or_default(),
        last_full: c.last_full_at,
        ..Default::default()
    }
}

/// What is watched on this Mac: the index of what is read, then one section per kind with the
/// things of that kind, the ways code runs by itself and the projects. Without an answer of
/// `immunity machine` about this Mac it says so, and no list is drawn.
pub fn page(r: &v1::Status, m: Option<&v1::Known>, now: i64) -> String {
    let mac = r.this_mac.clone().unwrap_or_default();
    let this = (mac.id_text.as_deref()).map(|id| This {
        id: contract::unescape(id),
        name: mac.name_text.as_deref().map(contract::unescape),
    });
    let check = (r.last_finished_run.as_ref()).and_then(|f| f.check.as_ref());
    let latest_run = check.map(|c| c.started_at);
    let found = r
        .vulnerabilities
        .as_ref()
        .and_then(|v| v.projects_found.as_ref());
    let mut out = top(
        THIS_MAC_TITLE,
        &format!(
            "Last full check {} · this page made {}",
            mac.checked_at
                .map_or("never".to_string(), |at| when(at, now)),
            when(now, now)
        ),
    );
    // First what is read here, kind by kind, each leading to its section.
    let _ = super::read_index(&mut out, r, now);
    match m {
        None => out.push_str(NO_ANSWER),
        Some(m) => {
            let mut facts: BTreeMap<String, Vec<&v1::Fact>> = BTreeMap::new();
            for f in &m.facts {
                facts.entry(f.subject_text.clone()).or_default().push(f);
            }
            let s = Mac {
                m,
                this,
                facts,
                latest_run,
                latest_run_id: check.map(|c| c.id.as_str()),
                found,
            };
            let _ = kinds(&mut out, &s, r, now);
            let _ = also(&mut out, &s, now);
            let _ = ways(&mut out, &s);
            let _ = projects(&mut out, &s, now);
        }
    }
    out.push_str(FOOT);
    out
}

/// One section per kind of watched thing, then the running programs.
fn kinds(out: &mut String, s: &Mac, r: &v1::Status, now: i64) -> Out {
    let mac = r.this_mac.clone().unwrap_or_default();
    let watched_kinds = r.watched.as_ref().map_or(&[][..], |w| &w.kinds[..]);
    let full = v1::Completeness::Full as i32;
    for (count, what, _) in covered::watched() {
        writeln!(
            out,
            "<section id=\"{}\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>",
            anchor(what),
            esc(&capital(what)),
            esc(about(what))
        )?;
        told(out, &covered::rules_about(what))?;
        let in_projects = covered::in_projects(count);
        let walk: Vec<String> = in_projects
            .then(|| s.failed_walk())
            .flatten()
            .into_iter()
            .collect();
        match count {
            Count::Files(as_) => {
                let k = watched_kinds.iter().find(|k| k.kind == as_);
                let whole = k.is_some_and(|k| k.coverage == Some(full) && k.fresh);
                let readings = s.readings(watched::READER, &covered::kinds_of(as_));
                let gap = s.gap(whole, &readings, &walk, now);
                let none = match in_projects && s.not_entered() {
                    true => NONE_IN_FOUND,
                    false => NONE_FOUND,
                };
                files(out, s, as_, gap.as_deref(), none, now)?;
            }
            Count::Installed(kind) => {
                let whole = installed_whole(r, kind) == Some(true);
                let readings = s.readings(integrity::READER, &[kind.to_string()]);
                let gap = s.gap(whole, &readings, &[], now);
                installed(out, s, kind, gap.as_deref())?;
            }
            Count::Dependencies => {
                let n = (mac.watched.iter())
                    .find(|w| w.what == covered::DEPENDENCIES)
                    .map_or(0, |w| w.count);
                writeln!(
                    out,
                    "<p>{} on this Mac depend on {} packages, each counted once per project; each project and its count are under Projects found below. <a href=\"{VULNERABILITIES}.html\">Known vulnerabilities in them</a> are listed by project.</p>",
                    if s.not_entered() {
                        "The projects found"
                    } else {
                        "Your projects"
                    },
                    grouped(n as i64)
                )?;
                // The count is of the projects found: a walk that failed is said under it.
                if let Some(why) = walk.first() {
                    let said = format!("Not read in full, so this list may not be whole: {why}.");
                    coverage_of_list(out, Some(&said), false, "");
                }
            }
        }
        out.push_str("</section>\n");
    }
    // Running programs: how many the latest sample saw, while a watcher samples them.
    writeln!(
        out,
        "<section id=\"{}\">\n<h2>{}</h2>\n<p class=\"muted\">While a watcher runs, it looks at the programs running under your user and where they connect, every {} seconds. Only a program or connection that needs a look is kept; no list of them is.</p>",
        anchor(covered::SAMPLED),
        esc(&capital(covered::SAMPLED)),
        crate::watch::SAMPLE.as_secs()
    )?;
    told(out, &covered::rules_about(covered::SAMPLED))?;
    // Three states apart: never sampled, the latest sample with its time and counts, and
    // whether a watcher samples them now.
    match &mac.latest_sample {
        Some(l) => writeln!(
            out,
            "<p>The latest sample, taken {}, saw {} and {}.</p>",
            when(l.at, now),
            counted(l.programs as i64, "running program", "running programs"),
            counted(l.connections as i64, "connection", "connections")
        )?,
        None => out.push_str("<p class=\"muted\">No sample has been taken yet.</p>\n"),
    }
    let now_sampled = mac.watched.iter().any(|w| w.what == covered::SAMPLED);
    out.push_str(match now_sampled {
        true => "<p class=\"muted\">A watcher samples them now.</p>\n",
        false => "<p class=\"muted\">No watcher samples them now.</p>\n",
    });
    out.push_str("</section>\n");
    Ok(())
}

/// After the kinds: the rules about no one kind, so that every rule the owner can be told by is
/// named on this page, and whether a list of indicators was read, by the answer's reading of it.
fn also(out: &mut String, s: &Mac, now: i64) -> Out {
    out.push_str("<section id=\"also\">\n<h2>Also told</h2>\n<h3>A list of signs of a known attack, when you give one</h3>\n");
    told(out, &rule_with(INDICATOR_RULE))?;
    let lists: Vec<&v1::Coverage> = (s.m.coverage.iter())
        .filter(|c| c.reader == crate::indicators::READER && c.kind == crate::indicators::LIST_KIND)
        .collect();
    // "At the last check" only when a reading of the list is of that check, whichever comes
    // first in the answer; else when one was last read in full.
    let of_last: Vec<&&v1::Coverage> = (lists.iter())
        .filter(|c| c.run_id.is_some() && c.run_id.as_deref() == s.latest_run_id)
        .collect();
    let full = |c: &&&v1::Coverage| c.completeness == v1::Completeness::Full as i32;
    let said = if lists.is_empty() {
        "No list has been given, so nothing is compared.".to_string()
    } else if of_last.is_empty() {
        format!(
            "The last check read no list. One was last read in full {}.",
            (lists.iter().filter_map(|c| c.last_full_at).max())
                .map_or("never".to_string(), |at| when(at, now))
        )
    } else if of_last.iter().any(full) {
        "A list was read at the last check.".to_string()
    } else {
        "A list was given but could not be read at the last check.".to_string()
    };
    writeln!(
        out,
        "<p class=\"muted\">{said}</p>\n<h3>Every watched place</h3>"
    )?;
    told(out, &rule_with(FIRST_READ_RULE))?;
    out.push_str("</section>\n");
    Ok(())
}

/// What the page says without an answer of `immunity machine` about this Mac.
const NO_ANSWER: &str = "<section id=\"no-answer\">\n<p class=\"muted\">There is no answer about this Mac yet, so nothing is said of what is on it.</p>\n</section>\n";

/// The rule about a match of a list of indicators, which is about no one kind.
const INDICATOR_RULE: &str = "indicator.match";
/// The rule about places read for the first time, which is about every watched kind.
const FIRST_READ_RULE: &str = "watched.first-read";

/// The watched files of one kind: where each is, when it was first seen and when its content last
/// changed, from the answer's facts. Only checksums are kept, never content. `gap` is what the
/// list cannot claim. An entry watched only for presence says so instead of when it changed, and
/// one whose content the latest reading did not read says that.
fn files(out: &mut String, s: &Mac, as_: &str, gap: Option<&str>, none: &str, now: i64) -> Out {
    let of_kind: Vec<(&str, &v1::Assertion)> = (s.m.parts.iter())
        .filter_map(|p| {
            let seen = (s.values(&p.id_text, "watched_as").into_iter())
                .filter(|f| f.object_text == as_)
                .flat_map(|f| &f.assertions)
                .min_by_key(|a| a.observed_at)?;
            Some((p.id_text.as_str(), seen))
        })
        .collect();
    coverage_of_list(out, gap, of_kind.is_empty(), none);
    if of_kind.is_empty() {
        return Ok(());
    }
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    view::thead(out, &["File", "First seen", "Last changed"]);
    for (id, first) in of_kind {
        out.push_str("<tr>");
        cell(out, "mono", &s.place(id))?;
        cell(out, "nowrap", &when(first.observed_at, now))?;
        // Changed when its content or link target now was first read by a later run than the one
        // that first saw it, told by run and not by time, which two runs may share.
        let content = s.values(id, "has_content");
        let since = (content.iter().chain(s.values(id, "links_to").iter()))
            .flat_map(|f| &f.assertions)
            .max_by_key(|a| a.observed_at);
        let presence = (content.iter())
            .any(|f| contract::unescape(&f.object_text).starts_with(watched::NOT_A_FILE));
        let (class, last) = match (content_now(s, id), presence, since) {
            (Some(not_read), ..) => ("", not_read),
            (None, true, _) => ("", esc(watched::PRESENCE_ONLY)),
            (None, false, None) => ("", esc(watched::NEVER_READ)),
            (None, false, Some(t)) if t.run_id != first.run_id => {
                ("nowrap", when(t.observed_at, now))
            }
            (None, false, Some(_)) => ("nowrap", "not since first seen".to_string()),
        };
        cell(out, class, &last)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
    Ok(())
}

/// What a row says in place of when an entry last changed when the latest check did not read its
/// content in full: the reading of its content, when it is of the run of the reading of its kind
/// that placed it or later, else that reading. `None` when it was read.
fn content_now(s: &Mac, id_text: &str) -> Option<String> {
    let placed = (s.values(id_text, "watched_as").into_iter())
        .flat_map(|f| f.assertions.iter())
        .filter_map(|a| {
            (s.m.coverage.iter())
                .find(|c| c.reader == a.reader && c.scope_text == a.scope_text && c.kind == a.kind)
        })
        .max_by_key(|c| c.observed_at);
    let content =
        (s.m.coverage.iter()).find(|c| c.kind == watched::CONTENT && c.scope_text == id_text);
    let full = v1::Completeness::Full as i32;
    let not_read = |why: String| format!("{}: {why}", esc(watched::NOT_READ_NOW));
    let read = match (placed, content) {
        (Some(k), Some(c)) if c.run_id == k.run_id || c.observed_at > k.observed_at => c,
        (None, Some(c)) => c,
        (Some(k), _) if k.completeness != full => k,
        _ => return Some(not_read(esc(watched::CONTENT_NOT_READ))),
    };
    (read.completeness != full).then(|| {
        not_read((read.reason_text.as_deref()).map_or(esc(watched::CONTENT_NOT_READ), said))
    })
}

/// One installed thing as a person reads it.
#[derive(Default)]
struct Installed {
    name: String,
    signed_by: BTreeSet<String>,
    version: BTreeSet<String>,
    at: String,
}

/// The installed things of one kind, from the facts its reader holds of the answer's parts: name
/// first, who signed it where that is known, version and where it is. `gap` is what the list
/// cannot claim.
fn installed(out: &mut String, s: &Mac, kind: &str, gap: Option<&str>) -> Out {
    let mut list: Vec<Installed> = Vec::new();
    for p in &s.m.parts {
        let of = |f: &&v1::Fact| {
            (f.assertions.iter()).any(|a| a.reader == integrity::READER && a.kind == kind)
        };
        let facts: Vec<&v1::Fact> = (s.facts.get(&p.id_text).into_iter().flatten().copied())
            .filter(of)
            .collect();
        if facts.is_empty() {
            continue;
        }
        let subject = contract::unescape(&p.id_text);
        let mut t = Installed::default();
        for f in facts {
            let value = contract::unescape(&f.object_text);
            match f.predicate.as_str() {
                "signed_by" => {
                    t.signed_by.insert(value);
                }
                "has_version" => {
                    t.version.insert(value);
                }
                "installed_at" => t.at = value,
                _ => {}
            }
        }
        if t.at.is_empty() {
            t.at = findings::place(&subject, s.this.as_ref());
        }
        let path = t.at.trim_end_matches('/').to_string();
        let last = path.rsplit('/').next().unwrap_or(&path).to_string();
        t.name = if let Some(app) = last.strip_suffix(".app") {
            app.to_string()
        } else if subject.starts_with("component:") {
            view::component_name(&subject).1.to_string()
        } else if let Some((_, keg)) = path.split_once("/Cellar/") {
            // A Homebrew keg, `<name>/<version>`.
            let (name, version) = keg.split_once('/').unwrap_or((keg, ""));
            if t.version.is_empty() && !version.is_empty() {
                t.version.insert(version.to_string());
            }
            name.to_string()
        } else {
            last
        };
        list.push(t);
    }
    list.sort_by_key(|t| t.name.to_lowercase());
    coverage_of_list(out, gap, list.is_empty(), NONE_FOUND);
    if list.is_empty() {
        return Ok(());
    }
    let signed = list.iter().any(|t| !t.signed_by.is_empty());
    let join = |set: &BTreeSet<String>| {
        let names: Vec<String> = set.iter().map(|v| Name::of(v).html()).collect();
        names.join(", ")
    };
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    match signed {
        true => view::thead(out, &["Name", "Signed by", "Version", "Where"]),
        false => view::thead(out, &["Name", "Version", "Where"]),
    }
    for t in &list {
        out.push_str("<tr>");
        cell(out, "", &Name::of(&t.name).html())?;
        if signed {
            cell(out, "", &join(&t.signed_by))?;
        }
        cell(out, "mono", &join(&t.version))?;
        cell(out, "mono", &Name::of(&t.at).html())?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
    Ok(())
}

/// What the section of the ways a project runs code by itself says first.
const WAYS: &str = "Files in a project that make a tool run code by itself during routine work, such as opening the folder or installing its packages. Each one listed is read, and a change in what it says is told, whether it is in your projects now or not.";

/// What the section of the places in the home folder says first.
const HOME_WAYS: &str = "Files and folders in your home folder where a developer tool keeps its own settings for what it runs by itself, such as the programs a coding agent starts or an editor's extensions. Each one listed is read, and a change in what it says is told, whether it is on this Mac now or not.";

/// The ways a project runs code by itself that this version reads, from the table in `autorun`:
/// the file, what runs it, whether the tool asks first, when it is read, and in how many of the
/// projects found it is, from the answer's facts `holds_autorun_point`; then, in a section of
/// their own, the places of the home folder, and whether this Mac holds each. While the reading
/// of projects failed, a way no project is known to hold is not counted as none.
fn ways(out: &mut String, s: &Mac) -> Out {
    use autorun::{Part, Scope};
    let this = s.this.as_ref().map_or(String::new(), |t| t.id.clone());
    let (machine, checkouts) = (
        crate::known::whole(&this),
        crate::known::whole(&format!("checkout:{this}/")),
    );
    let holding = |name: &str, home: bool| -> usize {
        let name = crate::known::whole(name);
        (s.m.facts.iter())
            .filter(|f| f.predicate == autorun::HOLDS && f.object_text == name)
            .filter(|f| match home {
                true => f.subject_text == machine,
                false => f.subject_text.starts_with(&checkouts),
            })
            .map(|f| f.subject_text.as_str())
            .collect::<BTreeSet<&str>>()
            .len()
    };
    // Why the counts of ways in projects may be short: the reading of which ways each project
    // holds, or the search for projects, less the folders this version does not enter.
    let present = s.readings(watched::READER, &[autorun::PRESENT_KIND.to_string()]);
    // As safe HTML: a reading's reason, given whole, through the printer; the status's why is
    // the core's words.
    let gap = match s.not_entered() {
        true => None,
        false => (present.iter())
            .find_map(|r| r.reason.as_deref().map(|r| Said::of(r).html()))
            .or_else(|| s.found.and_then(|f| f.why.as_deref().map(esc))),
    };
    for home in [false, true] {
        let (id, heading, intro, column) = match home {
            true => (
                "home-code-runs",
                "Places where a developer tool's own settings can make code run by itself",
                HOME_WAYS,
                "On this Mac",
            ),
            false => (
                "ways-code-runs",
                "Ways a project can make code run by itself",
                WAYS,
                "Projects found with it",
            ),
        };
        writeln!(
            out,
            "<section id=\"{id}\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>",
            esc(heading),
            esc(intro)
        )?;
        let gap = gap.as_deref().filter(|_| !home);
        if let Some(why) = gap {
            let said =
                format!("Not every project was looked at, so these counts may be short: {why}.");
            coverage_of_list(out, Some(&said), false, "");
        }
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(out, &["File", "What runs it", "Asks first", "Read", column]);
        let read = |p: &autorun::Point| p.part != Part::Present;
        for (p, way) in autorun::ways().filter(|(p, _)| (p.scope == Scope::Home) == home && read(p))
        {
            let words = match home {
                true => way.trigger.words_home(),
                false => way.trigger.words(),
            };
            let runs = format!("{} ({})", capital(words), way.tool);
            let read = match p.part {
                Part::Entries => "Read: every entry",
                _ if p.hourly().is_some() => "Read at full checks",
                Part::Folders(_) => "Read: every folder, by name",
                _ => "Read",
            };
            let here = match p.scope {
                Scope::NamedBy(_) => "—".to_string(),
                Scope::Checkout | Scope::System => match holding(&p.name(), false) {
                    0 if gap.is_some() => "Not known".to_string(),
                    n => grouped(n as i64),
                },
                Scope::Home if holding(&p.name(), true) > 0 => "Yes".to_string(),
                Scope::Home => "No".to_string(),
            };
            out.push_str("<tr>");
            view::td(out, "mono", &p.name())?;
            view::td(out, "", &runs)?;
            view::td(out, "", way.asks.words())?;
            view::td(out, "", read)?;
            view::td(out, "", &here)?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n</section>\n");
    }
    Ok(())
}

/// The projects found on this Mac, each with how many of its dependencies are known, from the
/// answer's checkouts and their counts (`Entity.parts_total`).
fn projects(out: &mut String, s: &Mac, now: i64) -> Out {
    writeln!(
        out,
        "<section id=\"projects\">\n<h2>Projects found</h2>\n<p class=\"muted\">Folders of code kept with git that were found on this Mac, with how many of their dependencies are known from the files that list them. {}</p>",
        esc(&crate::checkouts::walked())
    )?;
    let mut list: Vec<(String, u64)> = (s.m.parts.iter())
        .filter(|p| p.r#type == "checkout")
        .map(|p| (p.id_text.clone(), p.parts_total.unwrap_or_default()))
        .collect();
    list.sort();
    let kinds = [crate::checkouts::KIND, crate::agent_folders::KIND].map(str::to_string);
    let readings: Vec<Latest> = (s.m.coverage.iter())
        .filter(|c| kinds.contains(&c.kind))
        .map(latest_of)
        .collect();
    let refs: Vec<&Latest> = readings.iter().collect();
    let gap = unread(&refs, s.latest_run, now, &[]);
    coverage_of_list(
        out,
        gap.as_deref(),
        list.is_empty(),
        "None found in the folders looked into.",
    );
    if !list.is_empty() {
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(out, &["Project", "Dependencies known"]);
        for (id, n) in list {
            out.push_str("<tr>");
            cell(out, "mono", &s.place(&id))?;
            view::td(out, "", &grouped(n as i64))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the page reads of an answer, with nothing else known.
    fn mac<'a>(m: &'a v1::Known, found: Option<&'a v1::ProjectsFound>) -> Mac<'a> {
        Mac {
            m,
            this: None,
            facts: BTreeMap::new(),
            latest_run: None,
            latest_run_id: None,
            found,
        }
    }

    #[test]
    fn a_way_read_is_in_every_place_derived_from_the_table_so_adding_a_row_changes_no_code() {
        // Adding a product is adding a row. Every place that tells or acts on what runs by
        // itself takes it from the table: a row read here that one of them missed would be
        // read and never told, or told and never watched live.
        use crate::autorun;
        let mut page = String::new();
        let known = v1::Known::default();
        ways(&mut page, &mac(&known, None)).unwrap();
        for (p, way) in autorun::ways() {
            let cell = format!("<td class=\"mono\">{}</td>", esc(&p.name()));
            // The page lists the ways that are read, and no way that is only known.
            assert_eq!(
                page.contains(&cell),
                p.part != autorun::Part::Present,
                "{}",
                p.name()
            );
            if p.part == autorun::Part::Present {
                continue;
            }
            // A row read only at full checks says so in its reading column.
            let rest = &page[page.find(&cell).unwrap()..];
            let line = &rest[..rest.find("</tr>").unwrap()];
            assert_eq!(
                line.contains(">Read at full checks<"),
                p.hourly().is_some(),
                "{line}"
            );
            if !p.read_here() {
                continue;
            }
            let as_ = p.watched_as().unwrap_or_default();
            let (_, what, line) = p.watched().unwrap_or_default();
            assert!(!as_.is_empty() && !line.is_empty(), "{}", p.name());
            // A row not watched live says why; a path with a `*` cannot be watched live.
            for path in p.paths {
                let live = match p.scope {
                    autorun::Scope::Home => {
                        autorun::home_places().iter().any(|(h, _, _)| h == path)
                    }
                    _ => autorun::files().iter().any(|(f, _)| f == path),
                };
                assert_eq!(live, p.hourly().is_none(), "{path}");
                assert!(!live || !path.contains('*'), "{path}");
            }
            assert!(autorun::kinds_of(as_).contains(&p.kind()));
            assert!(
                covered::watched()
                    .iter()
                    .any(|w| matches!(w.0, Count::Files(a) if a == as_) && w.1 == what)
            );
            assert_eq!(about(what), line);
            let rules = covered::rules_about(what);
            assert_eq!(rules.len(), 1, "{}", p.name());
            assert_eq!(
                (rules[0].technique, rules[0].severity, rules[0].confidence),
                (way.technique, way.severity, way.confidence),
                "{}",
                p.name()
            );
        }
    }

    #[test]
    fn every_kind_of_watched_place_says_on_the_page_what_it_is_and_which_rule_tells_of_it() {
        // A kind listed with no line leaves the owner a name without a meaning, and one no
        // rule speaks about is watched without anyone being told of a change.
        for (_, (watched_as, _)) in crate::autorun::places() {
            let (_, what, _) = covered::watched()
                .into_iter()
                .find(|w| matches!(w.0, Count::Files(a) if a == watched_as))
                .unwrap_or_else(|| panic!("{}", watched_as));
            assert!(about(what).ends_with('.'), "{what}");
            assert_eq!(covered::rules_about(what).len(), 1, "{what}");
        }
    }

    #[test]
    fn every_ecosystem_that_is_matched_is_named_in_each_sentence_that_says_what_is_compared() {
        // These sentences are written by hand; a lockfile reader for a new ecosystem fails this
        // until each names it, so none says less is compared than is.
        let sentences = [
            about(covered::DEPENDENCIES),
            covered::NOT_COMPARED.meaning,
            (covered::LIMITS.iter())
                .find(|(_, c)| c.id == covered::NOT_COMPARED.id)
                .unwrap()
                .0,
        ];
        for feed in crate::vulnerabilities::matched_feeds() {
            for said in sentences {
                assert!(said.contains(feed.ecosystem), "{}: {said}", feed.ecosystem);
            }
        }
    }

    /// The page of what is watched for a status and an answer that hold nothing.
    fn this_mac_page() -> String {
        page(
            &v1::Status::default(),
            Some(&v1::Known::default()),
            1_791_000_000,
        )
    }

    /// Each section of a kind of watched thing on the page, by its anchor, up to its end.
    fn kinds(page: &str) -> Vec<&str> {
        covered::watched()
            .into_iter()
            .map(|(_, what, _)| what)
            .chain([covered::SAMPLED])
            .map(|what| {
                let at = page
                    .find(&format!("<section id=\"{}\">", anchor(what)))
                    .unwrap_or_else(|| panic!("{what}"));
                &page[at..at + page[at..].find("</section>").unwrap()]
            })
            .collect()
    }

    /// Each line of what is told, as the text of its `<li>`.
    fn rule_lines(html: &str) -> Vec<&str> {
        html.split("<ul class=\"rules\">")
            .skip(1)
            .flat_map(|list| list[..list.find("</ul>").unwrap()].split("<li>").skip(1))
            .collect()
    }

    #[test]
    fn every_rule_is_on_the_page_of_what_is_watched() {
        // The owner reads on the page what he is told about. A rule added later and not
        // placed under a kind or under "Also told" would tell him something the page never
        // says it does.
        let page = this_mac_page();
        for r in findings::rules() {
            assert!(page.contains(&esc(r.words.title)), "{}: {page}", r.id);
            assert!(page.contains(&esc(r.words.meaning)), "{}: {page}", r.id);
        }
    }

    #[test]
    fn the_page_never_calls_a_thing_watched_without_saying_what_is_told_about_it() {
        // False calm: a kind listed as watched that no rule can fire about must say so in
        // words, or "watched" promises a warning that never comes.
        let page = this_mac_page();
        for kind in kinds(&page) {
            let said = kind.contains("<ul class=\"rules\">\n<li>") || kind.contains(KEPT_AS_LIST);
            assert!(said, "{kind}");
        }
        let mut lone = String::new();
        told(&mut lone, &[]).unwrap();
        assert!(lone.contains(KEPT_AS_LIST), "{lone}");
    }

    #[test]
    fn a_rule_marked_as_sending_a_notification_is_exactly_an_urgent_one() {
        // The page tells the owner which changes notify at once; the app notifies for what
        // is urgent. The two must not disagree.
        let page = this_mac_page();
        let lines = rule_lines(&page);
        for r in findings::rules() {
            let line = lines
                .iter()
                .find(|l| l.starts_with(&esc(r.words.title)))
                .unwrap_or_else(|| panic!("{} is not on the page", r.id));
            assert_eq!(
                line.contains(NOTIFIES),
                findings::urgent(r.severity, Some(r.confidence)),
                "{}: {line}",
                r.id
            );
        }
    }

    /// The section of a kind of watched thing on this Mac's page.
    fn section(r: &v1::Status, m: &v1::Known, what: &str) -> String {
        let p = page(r, Some(m), NOW);
        let at = p
            .find(&format!("<section id=\"{}\">", anchor(what)))
            .unwrap();
        p[at..at + p[at..].find("</section>").unwrap()].to_string()
    }

    const NOW: i64 = 1_800_000_000;
    const MAC: &str = "machine:example-mac";

    /// A status of this Mac after a full check, with the status's word for one kind of files and
    /// the readings of installed software.
    fn status(kinds: Vec<v1::WatchedKind>, installed: Vec<v1::IntegrityReading>) -> v1::Status {
        v1::Status {
            this_mac: Some(v1::ThisMac {
                id_text: Some(MAC.to_string()),
                ..Default::default()
            }),
            last_finished_run: Some(v1::FinishedCheck {
                check: Some(v1::CheckMark {
                    id: "run-2".to_string(),
                    started_at: NOW - 60,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            watched: Some(v1::WatchedPlaces {
                kinds,
                ..Default::default()
            }),
            integrity: Some(v1::Integrity {
                readings: installed,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Running programs: never sampled, the latest sample with its time and counts, and whether a
    /// watcher samples them now are told apart, as the status gives them.
    #[test]
    fn the_running_programs_say_whether_a_sample_was_taken_and_whether_one_is_taken_now() {
        let running = |sample: Option<v1::LatestSample>, now_sampled: bool| {
            let mut r = status(vec![], vec![]);
            let mac = r.this_mac.as_mut().unwrap();
            mac.latest_sample = sample;
            if now_sampled {
                mac.watched.push(v1::WatchedThing {
                    what: covered::SAMPLED.to_string(),
                    count: 2,
                    how: "sampled".to_string(),
                });
            }
            section(&r, &v1::Known::default(), covered::SAMPLED)
        };
        let never = running(None, false);
        assert!(
            never.contains("No sample has been taken yet.")
                && never.contains("No watcher samples them now."),
            "{never}"
        );
        let taken = v1::LatestSample {
            at: NOW - 600,
            programs: 2,
            connections: 1,
        };
        let earlier = running(Some(taken), false);
        assert!(
            earlier.contains(&format!(
                "The latest sample, taken {}, saw 2 running programs and 1 connection.",
                when(NOW - 600, NOW)
            )) && earlier.contains("No watcher samples them now."),
            "{earlier}"
        );
        assert!(running(Some(taken), true).contains("A watcher samples them now."));
    }

    /// No false calm: without an answer of `immunity machine` about this Mac the page says so,
    /// and no list says nothing is there, whatever the status says of its kinds.
    #[test]
    fn without_an_answer_about_this_mac_no_list_says_none_found_here() {
        let whole = v1::WatchedKind {
            kind: watched::PROFILE.to_string(),
            coverage: Some(v1::Completeness::Full as i32),
            fresh: true,
            ..Default::default()
        };
        let p = page(&status(vec![whole], vec![]), None, NOW);
        assert!(
            p.contains("There is no answer about this Mac yet") && !p.contains(NONE_FOUND),
            "{p}"
        );
    }

    /// The list of signs of a known attack is said read "at the last check" only by a reading
    /// that check made (`Coverage.run_id`); one an earlier check made says when it was read.
    #[test]
    fn the_list_of_signs_is_said_read_at_the_last_check_only_by_a_reading_of_that_check() {
        let also = |runs: &[&str]| {
            let read = v1::Known {
                coverage: (runs.iter())
                    .map(|run| v1::Coverage {
                        reader: crate::indicators::READER.to_string(),
                        kind: crate::indicators::LIST_KIND.to_string(),
                        scope_text: format!("{MAC} {run}"),
                        completeness: v1::Completeness::Full as i32,
                        observed_at: Some(NOW - 86_400),
                        last_full_at: Some(NOW - 86_400),
                        run_id: Some(run.to_string()),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            };
            let p = page(&status(vec![], vec![]), Some(&read), NOW);
            p[p.find("<section id=\"also\">").unwrap()..].to_string()
        };
        assert!(also(&["run-2"]).contains("A list was read at the last check."));
        // A reading of the last check behind an older one of another scope is still of it.
        let both = also(&["run-1", "run-2"]);
        assert!(
            both.contains("A list was read at the last check."),
            "{both}"
        );
        let earlier = also(&["run-1"]);
        assert!(
            !earlier.contains("at the last check.")
                && earlier.contains(&format!(
                    "The last check read no list. One was last read in full {}.",
                    when(NOW - 86_400, NOW)
                )),
            "{earlier}"
        );
    }

    /// No false calm: an empty list of this Mac's page says "None found here." only where the
    /// status says its kind was read in full and fresh (`WatchedKind.coverage` and `fresh`, an
    /// `IntegrityReading` in full), never because the answer holds no part of it and never because
    /// the readings the answer gives look full: a kind of the list never read here leaves no
    /// reading to name, and the list still says it may not be whole.
    #[test]
    fn a_list_says_none_found_here_only_where_the_status_says_its_kind_was_read_in_full_and_fresh()
    {
        use v1::Completeness::{Full, Partial};
        let kind = |c: v1::Completeness, fresh: bool| v1::WatchedKind {
            kind: watched::PROFILE.to_string(),
            coverage: Some(c as i32),
            fresh,
            ..Default::default()
        };
        let empty = v1::Known::default();
        let files = "shell startup files";
        let whole = status(vec![kind(Full, true)], vec![]);
        assert!(section(&whole, &empty, files).contains(NONE_FOUND));
        for r in [
            status(vec![kind(Full, false)], vec![]),
            status(vec![kind(Partial, true)], vec![]),
            status(vec![], vec![]),
        ] {
            let said = section(&r, &empty, files);
            assert!(!said.contains(NONE_FOUND), "{said}");
            assert!(said.contains("<p class=\"muted\">Not read"), "{said}");
        }
        // The answer's own reading is full and fresh, and the status says the kind is not whole.
        let read = v1::Known {
            coverage: vec![v1::Coverage {
                reader: watched::READER.to_string(),
                kind: watched::PROFILE_KIND.to_string(),
                scope_text: MAC.to_string(),
                completeness: Full as i32,
                observed_at: Some(NOW - 30),
                ..Default::default()
            }],
            ..Default::default()
        };
        let said = section(&status(vec![kind(Full, false)], vec![]), &read, files);
        assert!(
            said.contains(NOT_WHOLE) && !said.contains(NONE_FOUND),
            "{said}"
        );
        // A file of the kind is listed, and the list is never said to be empty.
        let file = format!("file:{MAC}/.zshrc");
        let held = v1::Known {
            parts: vec![v1::Entity {
                id_text: file.clone(),
                r#type: "file".to_string(),
                parts_total: Some(0),
            }],
            facts: vec![v1::Fact {
                subject_text: file,
                predicate: "watched_as".to_string(),
                object_text: watched::PROFILE.to_string(),
                assertions: vec![v1::Assertion {
                    observed_at: NOW - 30,
                    ..Default::default()
                }],
            }],
            ..Default::default()
        };
        let said = section(&whole, &held, files);
        assert!(
            said.contains(".zshrc") && !said.contains(NONE_FOUND),
            "{said}"
        );
        // Installed software, by the status's reading of its kind.
        let kegs = "Homebrew packages";
        let reading = |c: v1::Completeness| v1::IntegrityReading {
            kind: crate::integrity::KEGS.to_string(),
            completeness: c as i32,
            ..Default::default()
        };
        assert!(section(&status(vec![], vec![reading(Full)]), &empty, kegs).contains(NONE_FOUND));
        for r in [
            status(vec![], vec![reading(Partial)]),
            status(vec![], vec![]),
        ] {
            assert!(!section(&r, &empty, kegs).contains(NONE_FOUND));
        }
    }

    #[test]
    fn why_the_counts_of_ways_may_be_short_is_what_the_reading_said_cut_where_it_is_shown() {
        // A reading's reason is its source's words, whole in the message: on the page a secret
        // in it is cut, and the words stand apart as a source's.
        let token = ["gh", "p_", "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u"].concat();
        let known = v1::Known {
            coverage: vec![v1::Coverage {
                reader: watched::READER.to_string(),
                kind: autorun::PRESENT_KIND.to_string(),
                scope_text: MAC.to_string(),
                completeness: v1::Completeness::Partial as i32,
                reason_text: Some(format!("could not list ?t={token}")),
                observed_at: Some(NOW - 30),
                ..Default::default()
            }],
            ..Default::default()
        };
        let page = page(&status(vec![], vec![]), Some(&known), NOW);
        let ways = &page[page.find("<section id=\"ways-code-runs\">").unwrap()..];
        assert!(
            ways.contains("may be short: <bdi class=\"src\">could not list ?t=\\cut{"),
            "{ways}"
        );
        assert!(!page.contains(&token), "{page}");
    }
}
