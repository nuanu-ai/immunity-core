//! The page of known vulnerabilities in the packages the projects use, drawn from what
//! `immunity vulnerabilities` answers, and the page of threat data, drawn from the status. "None
//! is known" rests on the totals (`text::Matched::all_compared` and `affected_records`), never on
//! the list being empty, since the list is cut at the contract's `vulnerabilities::SHOWN`. The
//! catalogue is said to be current by the one rule the answers rest on
//! (`vulnerabilities::catalogue_current_at` over `Threats.read_at`), never by the latest
//! attempt's outcome.

use super::{THREAT_DATA_TITLE, anchor, capital, grouped, top};
use crate::contract::{self, v1};
use crate::covered::{self, Found};
use crate::secrets::{Name, Said};
use crate::view::{FOOT, Out, counted, esc, utc};
use std::collections::BTreeMap;
use std::fmt::Write;

/// What the page says first of known vulnerabilities.
const VULNERABILITIES_SAY: &str = "These are published weaknesses in packages your projects depend on. They are listed, not alarmed: most matter only under particular conditions. A package known to be malicious, or a vulnerability attackers are using, is shown at the top as something that needs a look.";

/// A label as a person reads it.
fn label_words(label: &str) -> &'static str {
    match label {
        "malicious" => "Malicious package",
        "critical" => "Critical",
        "high" => "High",
        "moderate" => "Moderate",
        "low" => "Low",
        _ => "No label",
    }
}

/// Names from the answer, as the printer prints them, joined.
fn names(list: &[String]) -> String {
    let shown: Vec<String> = list.iter().map(|n| Name::given(n).html()).collect();
    shown.join(", ")
}

/// What the list cannot claim, as safe HTML: the places whose lockfiles were not read, with why,
/// cut where it is printed, and each matched feed of vulnerability data that is not current.
/// `None` when nothing is short.
fn gap(v: &v1::Vulnerabilities, t: &v1::VulnerabilityTotals) -> Option<String> {
    let unread = v.unread.clone().unwrap_or_default();
    let mut said: Vec<String> = (unread.items.iter())
        .map(|p| {
            let why = (p.why_text.as_deref()).map_or(esc("not read in full"), |w| {
                Said::of(&contract::unescape(w)).html()
            });
            format!(
                "{} ({}, {why})",
                Name::given(&p.project_text).html(),
                esc(&p.ecosystem)
            )
        })
        .collect();
    let more = unread.total.saturating_sub(unread.items.len() as u64);
    if more > 0 {
        said.push(format!("and {more} more"));
    }
    said.extend(
        (t.feeds.iter())
            .filter(|f| f.matched && !f.current)
            .map(|f| {
                let why = f.not_current_why.as_deref().unwrap_or("not current");
                esc(&format!("the {} vulnerability data ({why})", f.ecosystem))
            }),
    );
    (!said.is_empty()).then(|| {
        format!(
            "Not read in full, so this list may not be whole: {}.",
            said.join("; ")
        )
    })
}

/// Every known vulnerability in packages the projects use, grouped by project, from the answer of
/// `immunity vulnerabilities`; the status gives how many projects the store holds.
pub fn page(v: &v1::Vulnerabilities, r: &v1::Status, now: i64) -> String {
    let mut out = top(
        "Known vulnerabilities in packages your projects use",
        &format!("This page made {}", utc(now)),
    );
    let _ = body(&mut out, v, r);
    out.push_str(FOOT);
    out
}

fn body(out: &mut String, v: &v1::Vulnerabilities, r: &v1::Status) -> Out {
    writeln!(
        out,
        "<section id=\"by-project\">\n<h2>Known vulnerabilities by project</h2>\n<p class=\"muted\">{}</p>\n<p class=\"muted\">{}</p>",
        esc(VULNERABILITIES_SAY),
        esc(&v.declared_note)
    )?;
    let t = v.totals.clone().unwrap_or_default();
    // Of the projects found, while not all were. Which folders this version does not enter is
    // a limit of the version, which the commands say; a search that failed is said here.
    let (found, scope) = Found::of(t.projects_found.as_ref());
    let scope = scope.filter(|_| found == Found::LookedAt);
    let matched = crate::text::Matched::of(&t);
    // "None" only when every project was compared and the totals hold no record; else the
    // status's own sentence, by count.
    let all = v.totals.is_some() && matched.all_compared();
    match gap(v, &t) {
        Some(said) => writeln!(out, "<p class=\"muted\">{said}</p>")?,
        None if all && t.affected_records == 0 => {
            let none = match found {
                Found::All => "None is known.".to_string(),
                f => format!("None is known in {}.", f.projects()),
            };
            writeln!(out, "<p class=\"muted\">{}</p>", esc(&none))?;
        }
        None => {}
    }
    if !all {
        let projects = r.estate.as_ref().map(|e| e.checkouts);
        writeln!(
            out,
            "<p class=\"muted\">{}.</p>",
            esc(&capital(&matched.said(found, projects)))
        )?;
    }
    if let Some(line) = scope {
        writeln!(out, "<p class=\"muted\">{}</p>", esc(&line))?;
    }
    let affected = v.affected.clone().unwrap_or_default();
    let mut projects: BTreeMap<&str, Vec<&v1::AffectedPackage>> = BTreeMap::new();
    for a in &affected.items {
        projects.entry(a.project_text.as_str()).or_default().push(a);
    }
    for (project, of) in projects {
        writeln!(
            out,
            "<h3 class=\"mono\">{}</h3>\n<div class=\"scroll\"><table class=\"dense\">",
            Name::given(project).html()
        )?;
        crate::view::thead(out, &["Package", "Label", "Fixed in", "Record"]);
        for a in of {
            let record = a.record.clone().unwrap_or_default();
            let releases: Vec<String> = a.releases.iter().map(|r| r.version_text.clone()).collect();
            writeln!(
                out,
                "<tr><td class=\"mono\">{} {}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{} ({})</td></tr>",
                Name::given(&a.package_text).html(),
                names(&releases),
                label_words(&record.label),
                names(&record.fixed_text),
                Name::given(&record.id_text).html(),
                esc(&record.source)
            )?;
        }
        out.push_str("</tbody></table></div>\n");
    }
    // The list is cut at the contract's length: the total is said.
    let more = affected.total.saturating_sub(affected.items.len() as u64);
    if more > 0 {
        writeln!(
            out,
            "<p class=\"muted\">And {} more, not listed here.</p>",
            grouped(more as i64)
        )?;
    }
    out.push_str("</section>\n");
    Ok(())
}

/// What the list of vulnerabilities used in attacks is, why it is short, and what the program
/// does with it, in words a person without security training follows.
const CATALOGUE_IS: &str = "A list kept by CISA, a US government agency, of vulnerabilities that attackers are known to have used in real attacks. It is short because most published vulnerabilities are never seen used in one. When a package your projects use has one of them, the program shows it as something that needs a look.";

/// Every source of threat data the summary counts, from the status: first the scale, the short
/// list of vulnerabilities used in attacks beside every record of known vulnerabilities held;
/// then the list, then each set of records, one section each, saying what it is, how much it
/// holds, when it was read and whether that is current, and what it is compared with here. A
/// source never read or not current says so, and nothing says it was compared.
pub fn threat_data(r: &v1::Status, now: i64) -> String {
    let mut out = top(THREAT_DATA_TITLE, &format!("This page made {}", utc(now)));
    let _ = threats(&mut out, r, now);
    out.push_str(FOOT);
    out
}

fn threats(out: &mut String, r: &v1::Status, now: i64) -> Out {
    let fresh = (r.vulnerabilities.as_ref()).map_or(Vec::new(), |v| v.feeds.clone());
    let held = |source: &str| -> v1::FeedState {
        (r.vulnerability_data.as_ref())
            .and_then(|d| d.feeds.iter().find(|f| f.source == source).cloned())
            .unwrap_or_default()
    };
    let t = r.threats.clone().unwrap_or_default();
    let current = crate::vulnerabilities::catalogue_current_at(t.read_at, now);
    // The scale: only counts the program has, and none where a source was never read.
    let read: Vec<(&str, i64)> = (fresh.iter().filter(|f| f.read_at.is_some()))
        .map(|f| {
            (
                f.ecosystem.as_str(),
                held(&f.source).records.unwrap_or_default() as i64,
            )
        })
        .collect();
    // A count, big, and what it counts beside it.
    let figure = |n: i64, one: &str, many: &str| {
        format!(
            "<p><span class=\"num\">{}</span> <span>{}</span></p>\n",
            grouped(n),
            esc(if n == 1 { one } else { many })
        )
    };
    out.push_str("<div class=\"scale\">\n");
    match t.entries {
        Some(n) => out.push_str(&figure(
            n as i64,
            "vulnerability known to be used in real attacks",
            "vulnerabilities known to be used in real attacks",
        )),
        None => out.push_str("<p class=\"quiet\">The list of vulnerabilities used in real attacks has not been read.</p>\n"),
    }
    if read.is_empty() {
        out.push_str("<p class=\"quiet\">No record of known vulnerabilities has been read.</p>\n");
    } else {
        let names: Vec<&str> = read.iter().map(|(e, _)| *e).collect();
        let of = format!(
            "of known vulnerabilities and malicious packages, for {} packages",
            covered::listed(&names)
        );
        out.push_str(&figure(
            read.iter().map(|(_, n)| n).sum(),
            &format!("record {of}"),
            &format!("records {of}"),
        ));
    }
    out.push_str("</div>\n");
    // The two side by side are explained only where both are counts.
    if t.entries.is_some() && !read.is_empty() {
        out.push_str("<p class=\"muted\">The first is the short list of what attackers are known to use. The second is every record the program holds from OSV, the open database of published vulnerabilities, for the packages named; most of them are never used in an attack.</p>\n");
    }

    // The list of vulnerabilities used in attacks: how many, when it was last read whole, and
    // whether that is current by the rule the answers rest on.
    writeln!(
        out,
        "<section id=\"threats\">\n<h2>Vulnerabilities used in real attacks</h2>\n<p>{}</p>",
        esc(CATALOGUE_IS)
    )?;
    let failed = v1::FeedOutcome::try_from(t.outcome) == Ok(v1::FeedOutcome::Failed);
    match (t.read_at, t.entries) {
        (Some(at), Some(n)) => writeln!(
            out,
            "<p class=\"facts\"><strong>{}</strong> on the list · last read {}{}</p>",
            grouped(n as i64),
            esc(&utc(at)),
            if current { " · current" } else { "" }
        )?,
        _ if failed => out.push_str("<p class=\"quiet\">Never read in full, so which vulnerabilities attackers use is not known here.</p>\n"),
        _ => out.push_str("<p class=\"quiet\">This list has never been read, so which vulnerabilities attackers use is not known here, and nothing is compared with it.</p>\n"),
    }
    if let Some(why) =
        crate::vulnerabilities::read_not_current(t.read_at, now, crate::threats::CURRENT_FOR)
            .filter(|_| t.read_at.is_some())
    {
        writeln!(
            out,
            "<p class=\"quiet\">Not current: {}. Until it is read again, whether a vulnerability is used in attacks is not known.</p>",
            esc(&why)
        )?;
    }
    if failed {
        let reason =
            (t.reason_text.as_deref()).map_or(esc("no reason given"), |r| Said::given(r).html());
        writeln!(
            out,
            "<p class=\"quiet\">The latest reading of the list failed: {reason}.</p>"
        )?;
    }
    if t.read_at.is_some() {
        let compared: Vec<&str> = t.compared_ecosystems.iter().map(String::as_str).collect();
        writeln!(
            out,
            "<p>These are {}.</p>",
            esc(&crate::vulnerabilities::catalogue_said(&compared))
        )?;
    }
    out.push_str("</section>\n");

    for f in &fresh {
        let source = f.source.as_str();
        let eco = f.ecosystem.as_str();
        let h = held(source);
        let asked = (crate::osv::FEEDS.iter())
            .find(|feed| feed.source == source)
            .map_or("", |feed| feed.asked);
        writeln!(
            out,
            "<section id=\"{}\">\n<h2>Known vulnerabilities in {} packages</h2>\n<p>Records from OSV, the open database of published vulnerabilities, for {} packages, including packages known to be malicious. It is read {}.</p>",
            anchor(source),
            esc(eco),
            esc(eco),
            esc(asked)
        )?;
        // Counts exist only for a feed read whole.
        if let (Some(at), Some(records)) = (f.read_at, h.records) {
            writeln!(
                out,
                "<p class=\"facts\"><strong>{}</strong> {}, {} among them · last read {}{}</p>",
                grouped(records as i64),
                if records == 1 { "record" } else { "records" },
                counted(
                    h.malicious_records.unwrap_or_default() as i64,
                    "malicious package",
                    "malicious packages"
                ),
                esc(&utc(at)),
                if f.current { " · current" } else { "" }
            )?;
        }
        let said = match (f.read_at, f.current) {
            (None, _) => format!(
                "<p class=\"quiet\">Never read, so none of your {} packages is compared with it.</p>",
                esc(eco)
            ),
            (Some(_), false) => format!(
                "<p class=\"quiet\">Not current: {}. Until it is read again, a {} package it says nothing about is not known to be clear.</p>",
                esc(f.not_current_why.as_deref().unwrap_or("no reason given")),
                esc(eco)
            ),
            (Some(_), true) if t.compared_ecosystems.iter().any(|e| e == eco) => format!(
                "<p>Compared at the last check with the {} packages in your projects' lockfiles.</p>",
                esc(eco)
            ),
            (Some(_), true) => format!(
                "<p class=\"quiet\">No {} packages from your projects' lockfiles were compared with it at the last check.</p>",
                esc(eco)
            ),
        };
        writeln!(out, "{said}\n</section>")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    /// Totals of projects all compared in full, every one found, with `records` known.
    fn totals(records: u64) -> v1::VulnerabilityTotals {
        v1::VulnerabilityTotals {
            matched_this_store: true,
            projects_compared: 2,
            affected_records: records,
            projects_found: Some(v1::ProjectsFound {
                all: true,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn drawn(v: &v1::Vulnerabilities) -> String {
        page(v, &v1::Status::default(), NOW)
    }

    /// No false calm: "None is known" rests on the totals, every project compared in full
    /// (`Matched::all_compared`) and no record affecting one, never on the list being empty, which
    /// the contract cuts; the total past the cut is said. A place whose lockfiles were not read
    /// keeps "none" off the page, with why, cut where it is printed.
    #[test]
    fn none_is_known_rests_on_the_totals_never_on_the_list_being_empty() {
        let none = "None is known.";
        let calm = v1::Vulnerabilities {
            totals: Some(totals(0)),
            ..Default::default()
        };
        assert!(drawn(&calm).contains(none), "{}", drawn(&calm));
        // Records known, and none in the cut list.
        let cut = v1::Vulnerabilities {
            totals: Some(totals(2)),
            affected: Some(v1::AffectedPackages {
                items: vec![],
                total: 2,
            }),
            ..Default::default()
        };
        let said = drawn(&cut);
        assert!(
            !said.contains(none) && said.contains("And 2 more, not listed here."),
            "{said}"
        );
        // Not every project compared, or no totals at all.
        for t in [
            Some(v1::VulnerabilityTotals {
                unknown_packages: 1,
                ..totals(0)
            }),
            Some(v1::VulnerabilityTotals {
                projects_compared: 0,
                ..totals(0)
            }),
            None,
        ] {
            let v = v1::Vulnerabilities {
                totals: t,
                ..Default::default()
            };
            assert!(!drawn(&v).contains("None is known"), "{}", drawn(&v));
        }
        // A place not read, whose source's words hold a token: no "none", and the words cut.
        let token = format!(
            "{}{}",
            ["gh", "p_"].concat(),
            "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u"
        );
        let unread = v1::Vulnerabilities {
            totals: Some(totals(0)),
            unread: Some(v1::UnreadPlaces {
                items: vec![v1::UnreadPlace {
                    project_text: "~/dev/shop".to_string(),
                    ecosystem: "npm".to_string(),
                    why_text: Some(format!("a tool answered: t={token}")),
                    ..Default::default()
                }],
                total: 1,
            }),
            ..Default::default()
        };
        let said = drawn(&unread);
        assert!(
            !said.contains(none) && said.contains("may not be whole"),
            "{said}"
        );
        assert!(
            !said.contains(&token) && said.contains("a tool answered"),
            "{said}"
        );
    }

    /// The catalogue is current by the one rule the answers rest on, over when it was last read
    /// whole, never by its latest attempt: a failed attempt after a recent reading is current,
    /// an old reading whose latest attempt went well is not.
    #[test]
    fn the_catalogue_is_said_current_by_the_rule_the_answers_rest_on_and_not_by_its_latest_attempt()
    {
        let page = |read_at: i64, outcome: v1::FeedOutcome| {
            let r = v1::Status {
                threats: Some(v1::Threats {
                    outcome: outcome as i32,
                    entries: Some(1_234),
                    read_at: Some(read_at),
                    ..Default::default()
                }),
                ..Default::default()
            };
            threat_data(&r, NOW)
        };
        let failed = page(NOW - 60, v1::FeedOutcome::Failed);
        assert!(
            failed.contains("on the list · last read") && failed.contains(" · current</p>"),
            "{failed}"
        );
        assert!(!failed.contains("Not current"), "{failed}");
        let old = page(
            NOW - crate::threats::CURRENT_FOR - 1,
            v1::FeedOutcome::Unchanged,
        );
        assert!(
            !old.contains(" · current</p>") && old.contains("Not current"),
            "{old}"
        );
    }
}
