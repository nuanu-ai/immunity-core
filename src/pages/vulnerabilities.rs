//! The page of known vulnerabilities in the packages the projects use, drawn from what
//! `immunity vulnerabilities` answers, and the page of threat data, drawn from the status. "None
//! is known" rests on the totals (`text::Matched::all_compared` and `affected_records`), never on
//! the list being empty. The pages ask with `--all`, so the list is whole, and a list a client
//! was given cut is said to be cut. The
//! catalogue is said to be current by the one rule the answers rest on
//! (`vulnerabilities::catalogue_current_at` over `Threats.read_at`), never by the latest
//! attempt's outcome.

use super::{THREAT_DATA_TITLE, anchor, capital, grouped, names, said, top};
use crate::contract::v1;
use crate::covered::{self, Found};
use crate::secrets::{Name, Said};
use crate::view::{FOOT, Out, counted, esc, when};
use std::collections::HashMap;
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

/// What the list cannot claim, as safe HTML: the places whose lockfiles were not read, with why,
/// cut where it is printed, and each matched feed of vulnerability data that is not current.
/// `None` when nothing is short.
fn gap(v: &v1::Vulnerabilities, t: &v1::VulnerabilityTotals) -> Option<String> {
    let unread = v.unread.clone().unwrap_or_default();
    let mut said: Vec<String> = (unread.items.iter())
        .map(|p| {
            let why = (p.why_text.as_deref()).map_or(esc("not read in full"), said);
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

/// Every known vulnerability in packages the projects use, a row a record, from the answer of
/// `immunity vulnerabilities`; the status gives how many projects the store holds.
pub fn page(v: &v1::Vulnerabilities, r: &v1::Status, now: i64) -> String {
    let mut out = top(
        "Known vulnerabilities in packages your projects use",
        &format!("This page made {}", when(now, now)),
    );
    let _ = body(&mut out, v, r);
    out.push_str(FOOT);
    out
}

fn body(out: &mut String, v: &v1::Vulnerabilities, r: &v1::Status) -> Out {
    writeln!(
        out,
        "<section id=\"by-vulnerability\">\n<h2>By vulnerability</h2>\n<p class=\"muted\">{}</p>\n<p class=\"muted\">{}</p>",
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
    // One row a record, in the answer's order, the malicious and those used in attacks first:
    // every package and project it affects is in its row. The row says the record once, so
    // entries share it only where all it says of the record is the same: two feeds can hold
    // copies of one id that differ, and a row never says less than one of its entries.
    let none = v1::PackageRecord::default();
    let mut records: Vec<Vec<&v1::AffectedPackage>> = Vec::new();
    let mut at: HashMap<_, usize> = HashMap::new();
    for a in &affected.items {
        let r = a.record.as_ref().unwrap_or(&none);
        let said = (
            &r.id_text,
            &r.source,
            &r.label,
            &r.aliases_text,
            &r.summary_text,
        );
        match at.get(&said) {
            Some(&n) => records[n].push(a),
            None => {
                at.insert(said, records.len());
                records.push(vec![a]);
            }
        }
    }
    for of in &records {
        record_row(out, of)?;
    }
    // A list given without `--all` is cut at the contract's length: the total is said.
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

/// One record and everything it affects, as a row that opens in place. Its summary: the packages
/// and their releases, the record's id and label and what it is fixed in, whether it is used in
/// attacks, and in how many projects. Opened: the record once, then each package in each project
/// on a line of its own. Its entries give the record the same id, source, label, other ids and
/// summary; what it is fixed in and whether it is used in attacks are each entry's own. Used in
/// attacks is `PackageRecord.exploited` alone: used when any of its answers says so, not known
/// when any says nothing, else not listed.
fn record_row(out: &mut String, of: &[&v1::AffectedPackage]) -> Out {
    let record = of[0].record.clone().unwrap_or_default();
    // The packages, each once, with every release of it the record affects.
    let mut packages: Vec<(&str, Vec<String>)> = Vec::new();
    for a in of {
        let n = match packages.iter().position(|(p, _)| *p == a.package_text) {
            Some(n) => n,
            None => {
                packages.push((a.package_text.as_str(), Vec::new()));
                packages.len() - 1
            }
        };
        for r in &a.releases {
            if !packages[n].1.contains(&r.version_text) {
                packages[n].1.push(r.version_text.clone());
            }
        }
    }
    let thing: Vec<String> = (packages.iter())
        .map(|(p, versions)| match versions.is_empty() {
            true => Name::given(p).html(),
            false => format!(
                "{} <span class=\"v\">{}</span>",
                Name::given(p).html(),
                names(versions)
            ),
        })
        .collect();
    let exploited: Vec<Option<bool>> = (of.iter())
        .map(|a| a.record.as_ref().and_then(|r| r.exploited))
        .collect();
    // A record used in attacks has its dot and its word in the colour of what needs the person now.
    let (urgent, used, mark) = if exploited.contains(&Some(true)) {
        (" urgent", " now", "used in attacks")
    } else if exploited.contains(&None) {
        ("", "", "not known if used in attacks")
    } else {
        ("", "", "not listed as used in attacks")
    };
    // What it is fixed in, said once where every package it affects is fixed in the same.
    let fixed = (of.iter().map(|a| a.record.as_ref().map(|r| &r.fixed_text)))
        .all(|f| f == Some(&record.fixed_text))
        .then_some(&record.fixed_text)
        .filter(|f| !f.is_empty());
    let mut projects: Vec<&str> = of.iter().map(|a| a.project_text.as_str()).collect();
    projects.sort_unstable();
    projects.dedup();
    let projects = counted(projects.len() as i64, "project", "projects");
    writeln!(
        out,
        "<details class=\"fr vr{}\"><summary><span class=\"fw\">{}</span><span class=\"fk\"><span class=\"mono\">{}</span> {}{}</span><span class=\"att{used}\">{mark}</span><span class=\"fc\">{projects}</span><span class=\"fch\" aria-hidden=\"true\"></span></summary>\n<div class=\"fx\">",
        urgent,
        thing.join(", "),
        Name::given(&record.id_text).html(),
        label_words(&record.label),
        fixed.map_or(String::new(), |f| format!(
            " <span class=\"t2\">· fixed in <span class=\"mono\">{}</span></span>",
            names(f)
        )),
    )?;
    out.push_str("<div><dl class=\"facts\">");
    let mut facts: Vec<(&str, String)> = vec![
        ("Record", Name::given(&record.id_text).html()),
        ("Source", esc(&record.source)),
        ("Label", esc(label_words(&record.label))),
    ];
    if !record.aliases_text.is_empty() {
        facts.insert(1, ("Also known as", names(&record.aliases_text)));
    }
    if let Some(f) = fixed {
        facts.push(("Fixed in", names(f)));
    }
    for (k, v) in facts {
        write!(out, "<dt>{k}</dt><dd>{v}</dd>")?;
    }
    out.push_str("</dl></div>\n<div>");
    if let Some(summary) = &record.summary_text {
        writeln!(
            out,
            "<p class=\"wsh2\">{} said</p><p class=\"said\">{}</p>",
            esc(&record.source),
            Said::given(summary).html()
        )?;
    }
    writeln!(
        out,
        "</div>\n<div class=\"in\"><p class=\"wsh2\">In {projects}</p>\n<ul>"
    )?;
    for a in of {
        let versions: Vec<String> = a.releases.iter().map(|r| r.version_text.clone()).collect();
        let own_fix = (a.record.as_ref().map(|r| &r.fixed_text))
            .filter(|f| fixed.is_none() && !f.is_empty())
            .map_or(String::new(), |f| format!(" · fixed in {}", names(f)));
        writeln!(
            out,
            "<li><span class=\"p\">{}</span><span class=\"c\">{} {}{own_fix}</span></li>",
            Name::given(&a.project_text).html(),
            Name::given(&a.package_text).html(),
            names(&versions),
        )?;
    }
    out.push_str("</ul></div>\n</div>\n</details>\n");
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
    let mut out = top(
        THREAT_DATA_TITLE,
        &format!("This page made {}", when(now, now)),
    );
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
            when(at, now),
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
                when(at, now),
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

    /// Every record of the answer is one row, with every project and package it affects on a line
    /// of its own. Whether it is used in attacks is the record's `exploited` alone: used where any
    /// of its answers says so, the first or a later one, not known where any says nothing, not
    /// listed only where every one says no, whatever its label or its other ids.
    #[test]
    fn every_record_is_one_row_with_every_project_it_is_in_and_used_in_attacks_is_its_word_alone() {
        let item =
            |project: &str, package: &str, id: &str, exploited, fixed: &str| v1::AffectedPackage {
                project_text: project.to_string(),
                ecosystem: "npm".to_string(),
                package_text: package.to_string(),
                releases: vec![v1::PackageRelease {
                    version_text: "1.0.0".to_string(),
                    ..Default::default()
                }],
                record: Some(v1::PackageRecord {
                    id_text: id.to_string(),
                    aliases_text: vec!["CVE-2099-0001".to_string()],
                    label: "high".to_string(),
                    exploited,
                    fixed_text: vec![fixed.to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            };
        let items = vec![
            item("~/dev/one", "left-pad", "GHSA-a", Some(true), "2.0.0"),
            item("~/dev/two", "left-pad", "GHSA-a", None, "2.0.0"),
            item("~/dev/one", "right-pad", "GHSA-b", None, "2.0.0"),
            item("~/dev/one", "up-pad", "GHSA-b", None, "2.0.0"),
            item("~/dev/three", "evil-pad", "MAL-c", Some(false), "2.0.0"),
            item("~/dev/two", "left-pad", "GHSA-d", Some(false), "1.0.1"),
            item("~/dev/three", "other-pad", "GHSA-d", Some(false), "3.0.0"),
            item("~/dev/two", "down-pad", "GHSA-e", None, "2.0.0"),
            item("~/dev/three", "down-pad", "GHSA-e", Some(true), "2.0.0"),
        ];
        let page = drawn(&v1::Vulnerabilities {
            totals: Some(totals(5)),
            affected: Some(v1::AffectedPackages { total: 9, items }),
            ..Default::default()
        });
        let rows: Vec<&str> = page.split("<details class=\"fr vr").skip(1).collect();
        assert_eq!(rows.len(), 5, "{page}");
        // Each record: its id, the projects of its lines, how many projects, and its mark.
        let expect: [(&str, &[&str], i64, &str); 5] = [
            ("GHSA-a", &["one", "two"], 2, "used in attacks"),
            ("GHSA-b", &["one", "one"], 1, "not known if used in attacks"),
            ("MAL-c", &["three"], 1, "not listed as used in attacks"),
            (
                "GHSA-d",
                &["two", "three"],
                2,
                "not listed as used in attacks",
            ),
            ("GHSA-e", &["two", "three"], 2, "used in attacks"),
        ];
        for (row, (id, lines, n, mark)) in rows.iter().zip(expect) {
            assert!(row.contains(&format!(">{id}</bdi>")), "{row}");
            assert!(row.contains(&format!("\">{mark}</span>")), "{row}");
            let urgent = ["GHSA-a", "GHSA-e"].contains(&id);
            assert_eq!(row.starts_with(" urgent\""), urgent, "{row}");
            let count = counted(n, "project", "projects");
            assert!(
                row.contains(&format!("<span class=\"fc\">{count}</span>")),
                "{row}"
            );
            let drawn: Vec<&str> = (row.split("<li><span class=\"p\"><bdi class=\"src\">~/dev/"))
                .skip(1)
                .map(|l| &l[..l.find('<').unwrap()])
                .collect();
            assert_eq!(drawn, lines, "{row}");
        }
        // What a record is fixed in is said once where every package is fixed in the same, and
        // on each line where they differ.
        assert!(rows[0].contains("· fixed in <span class=\"mono\"><bdi class=\"src\">2.0.0"));
        assert!(
            !rows[3].contains("<span class=\"t2\">· fixed in"),
            "{}",
            rows[3]
        );
        for fixed in ["1.0.1", "3.0.0"] {
            assert!(rows[3].contains(&format!(" · fixed in <bdi class=\"src\">{fixed}")));
        }
    }

    /// No false calm: a row says its record once, so entries share a row only where all it says
    /// of the record is the same. Two feeds can hold copies of one id that differ, one read later
    /// than the other: each copy is a row of its own, with its own label, source, other ids or
    /// summary, its own project lines and its own count of projects.
    #[test]
    fn copies_of_one_record_id_that_differ_are_a_row_each_and_no_row_says_less_than_its_entries() {
        let entry = |project: &str, record: &v1::PackageRecord| v1::AffectedPackage {
            project_text: project.to_string(),
            ecosystem: "npm".to_string(),
            package_text: "lantern".to_string(),
            record: Some(record.clone()),
            ..Default::default()
        };
        let low = v1::PackageRecord {
            id_text: "GHSA-lantern".to_string(),
            source: "GitHub Advisory Database".to_string(),
            label: "low".to_string(),
            aliases_text: vec!["CVE-2099-0001".to_string()],
            summary_text: Some("the wick runs short".to_string()),
            exploited: Some(false),
            ..Default::default()
        };
        // What the other copy says that the first does not, as the page prints it.
        let other = [
            (
                "<dd>Critical</dd>",
                v1::PackageRecord {
                    label: "critical".to_string(),
                    ..low.clone()
                },
            ),
            (
                "<dd>OSV</dd>",
                v1::PackageRecord {
                    source: "OSV".to_string(),
                    ..low.clone()
                },
            ),
            (
                "CVE-2099-0002",
                v1::PackageRecord {
                    aliases_text: vec!["CVE-2099-0002".to_string()],
                    ..low.clone()
                },
            ),
            (
                "the wick burns out",
                v1::PackageRecord {
                    summary_text: Some("the wick burns out".to_string()),
                    ..low.clone()
                },
            ),
        ];
        for (said, copy) in other {
            let items = vec![
                entry("~/dev/one", &low),
                entry("~/dev/two", &low),
                entry("~/dev/three", &copy),
            ];
            let page = drawn(&v1::Vulnerabilities {
                totals: Some(totals(2)),
                affected: Some(v1::AffectedPackages { total: 3, items }),
                ..Default::default()
            });
            let rows: Vec<&str> = page.split("<details class=\"fr vr").skip(1).collect();
            assert_eq!(rows.len(), 2, "{said}: {page}");
            assert!(!rows[0].contains(said) && rows[1].contains(said), "{page}");
            for (row, lines, n) in [(rows[0], &["one", "two"][..], 2), (rows[1], &["three"], 1)] {
                assert!(row.contains(">GHSA-lantern</bdi>"), "{row}");
                let count = counted(n, "project", "projects");
                assert!(row.contains(&format!("<span class=\"fc\">{count}</span>")));
                let drawn: Vec<&str> = (row
                    .split("<li><span class=\"p\"><bdi class=\"src\">~/dev/"))
                .skip(1)
                .map(|l| &l[..l.find('<').unwrap()])
                .collect();
                assert_eq!(drawn, lines, "{row}");
            }
        }
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
