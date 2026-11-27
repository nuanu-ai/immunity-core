//! The page of what is beyond this Mac: the servers, each opening to what was read on it, the
//! person's other devices, other people's devices, and the machines the person set aside. It is
//! drawn from the answer of `immunity owner` (`Statements`, whose `machines` tells servers and
//! devices apart) and the answer of `immunity machine` (`Known`) for each server and each machine
//! set aside, and decides nothing again. What it says of a machine's readings, of when it was last
//! visited and read and of what is not known comes from `Known.coverage`; a machine is said to be
//! checked only when its latest visit there is full. A machine set aside is shown as its
//! statement says, with how the statement came. Text from a machine or a source is printed through
//! `secrets::Name` and `secrets::Said`, each in an element of its own; a reason `Known` gives
//! whole is cut here (`Said::of`).

use super::top;
use crate::contract::{unescape, v1};
use crate::secrets::{Name, Said};
use crate::view::{FOOT, MachineOf, Out, badge, esc, thead, utc, utc_age, utc_or};
use crate::{servers, tailnet};
use std::error::Error;
use std::fmt::Write;

/// The sections of devices: their anchor, heading, what they are, and their kind.
const DEVICES: [(&str, &str, &str, v1::MachineKind); 2] = [
    (
        "your-devices",
        "Your other devices",
        "Phones, tablets and computers on your private network that you do not log in to over SSH. They are not checked: this version looks at this Mac and at servers.",
        v1::MachineKind::OwnDevice,
    ),
    (
        "other-devices",
        "Other devices",
        "Other people's computers and phones seen in your private network, such as a colleague's laptop. They are not yours to check, and this program does not read them. Only a Tailscale network is looked at; devices in a network of another kind are not known here.",
        v1::MachineKind::OtherDevice,
    ),
];

/// What an empty list of machines says when the readings it rests on are whole.
const NONE_KNOWN: &str = "None known.";
const NONE_SEEN: &str = "None seen.";

/// The facts of a machine that say what it runs, in the order they are shown, with their labels.
const SYSTEM: [(&str, &str); 6] = [
    ("runs_os", "System"),
    ("runs_platform", "Platform"),
    ("runs_release", "Release"),
    ("release_codename", "Codename"),
    ("runs_kernel", "Kernel"),
    ("runs_kernel_package", "Kernel package"),
];

/// Names from `_text` fields, each in its own element, joined by commas.
fn names(all: &[String]) -> String {
    let shown: Vec<String> = all.iter().map(|n| Name::given(n).html()).collect();
    shown.join(", ")
}

/// A reason a message gives whole, cut where it is shown.
fn said(whole: &str) -> String {
    Said::of(&unescape(whole)).html()
}

/// Whether a reading is full; a value this build does not know is read as not full.
fn full(c: &v1::Coverage) -> bool {
    c.completeness == v1::Completeness::Full as i32
}

/// What a list cannot claim, from the readings `Statements.machines_not_read` names: `None`
/// when it names none, so the list says it is empty only then.
fn gap(not_read: &[&v1::Coverage]) -> Option<String> {
    if not_read.is_empty() {
        return None;
    }
    if not_read.iter().all(|c| c.observed_at.is_none()) {
        return Some("Not read yet, so what is here is not known.".to_string());
    }
    let each: Vec<String> = not_read
        .iter()
        .map(|c| {
            let last = c
                .last_full_at
                .map_or("never read in full".to_string(), |at| {
                    format!("last read in full {}", utc(at))
                });
            let why = match (c.observed_at, &c.reason_text) {
                (None, _) => return format!("{} (never read)", esc(&c.kind)),
                (Some(_), _) if full(c) => "not read at the latest check".to_string(),
                (Some(_), Some(reason)) => said(reason),
                (Some(_), None) => "not read in full".to_string(),
            };
            format!("{} ({why}; {last})", esc(&c.kind))
        })
        .collect();
    Some(format!(
        "Not read in full, so this list may not be whole: {}.",
        each.join("; ")
    ))
}

/// What a list rests on when it is not whole, and, for an empty list, that nothing is there only
/// when it is.
fn rests_on(out: &mut String, gap: Option<&str>, empty: bool, none: &str) {
    if let Some(said) = gap.or(empty.then_some(none)) {
        out.push_str(&format!("<p class=\"muted\">{said}</p>\n"));
    }
}

/// Servers, the person's other devices, other people's devices and the machines the person set
/// aside, each in a section of its own.
pub fn page(
    r: &v1::Status,
    s: &v1::Statements,
    machine: &MachineOf,
    now: i64,
) -> Result<String, Box<dyn Error>> {
    // When its "none" was established: the last full check, as on the page of this Mac.
    let checked_at = r.this_mac.as_ref().and_then(|m| m.checked_at);
    let mut out = top(
        "Beyond this Mac",
        &format!(
            "Last full check {} · this page made {}",
            utc_or(checked_at, "never"),
            utc(now)
        ),
    );
    // A kind this build does not know is read as a server.
    let of = |kind: v1::MachineKind| -> Vec<&v1::KnownMachine> {
        let kind_of = |m: &&v1::KnownMachine| match v1::MachineKind::try_from(m.kind) {
            Ok(k @ (v1::MachineKind::OwnDevice | v1::MachineKind::OtherDevice)) => k,
            _ => v1::MachineKind::Server,
        };
        s.machines.iter().filter(|m| kind_of(m) == kind).collect()
    };
    let all: Vec<&v1::Coverage> = s.machines_not_read.iter().collect();
    let private: Vec<&v1::Coverage> = (all.iter().copied())
        .filter(|c| c.reader == tailnet::READER)
        .collect();
    let (all, private) = (gap(&all), gap(&private));

    let servers = of(v1::MachineKind::Server);
    out.push_str("<section id=\"servers\">\n<h2>Servers</h2>\n<p class=\"muted\">Machines you log in to over SSH, as your SSH settings, the list of machines SSH has connected to and the server check name them, and those your private network shows as yours. They are checked only when you run the server check; this program never connects to them by itself. Open one to see what was read on it.</p>\n");
    rests_on(&mut out, all.as_deref(), servers.is_empty(), NONE_KNOWN);
    for w in s.statements.iter() {
        let Some(seen) = &w.seen_after else { continue };
        writeln!(
            out,
            "<p class=\"alert\">You said {} is {} on {}, and it was seen alive after that, {}: {}. It is counted as a server again and still not offered for the server check.</p>",
            Name::given(&w.machine_text).html(),
            esc(&w.said),
            utc(w.at),
            utc(seen.at),
            Name::given(&seen.what_text).html()
        )?;
    }
    for m in &servers {
        let known = m.entities_text.first().map(|id| machine(id)).transpose()?;
        let known = known.flatten();
        let names = (
            m.machine_text.as_str(),
            &m.names_text[..],
            &m.known_from[..],
        );
        block(&mut out, names, known.as_ref(), None, now)?;
    }
    // Never guessed: a server the private network alone knows, without a system, says so.
    match servers.iter().filter(|m| m.system_not_given).count() {
        0 => {}
        1 => out.push_str("<p class=\"muted\">1 of them is known only from your private network, which does not say what system it runs, so it is counted as a server.</p>\n"),
        n => writeln!(
            out,
            "<p class=\"muted\">{n} of them are known only from your private network, which does not say what system they run, so they are counted as servers.</p>"
        )?,
    }
    out.push_str("</section>\n");

    for (anchor, heading, about, kind) in DEVICES {
        writeln!(
            out,
            "<section id=\"{anchor}\">\n<h2>{heading}</h2>\n<p class=\"muted\">{about}</p>"
        )?;
        let own = kind == v1::MachineKind::OwnDevice;
        devices(&mut out, &of(kind), private.as_deref(), own)?;
        out.push_str("</section>\n");
    }

    out.push_str("<section id=\"retired\">\n<h2>Retired or not yours</h2>\n<p class=\"muted\">Machines you said are retired or not yours. They are not checked, and what was read on them before is kept.</p>\n");
    let aside: Vec<&v1::Statement> = (s.statements.iter())
        .filter(|w| w.seen_after.is_none())
        .collect();
    if aside.is_empty() {
        out.push_str("<p class=\"muted\">None.</p>\n");
    }
    for w in aside {
        let known = machine(&w.entity_text)?;
        let names = (w.machine_text.as_str(), &w.names_text[..], &[][..]);
        block(&mut out, names, known.as_ref(), Some(w), now)?;
    }
    out.push_str("</section>\n");
    out.push_str(FOOT);
    Ok(out)
}

/// A table of devices, with their system for the person's own.
fn devices(out: &mut String, list: &[&v1::KnownMachine], gap: Option<&str>, own: bool) -> Out {
    rests_on(out, gap, list.is_empty(), NONE_SEEN);
    if list.is_empty() {
        return Ok(());
    }
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    match own {
        true => thead(out, &["Device", "System", "Also known as"]),
        false => thead(out, &["Device", "Also known as"]),
    }
    for m in list {
        write!(
            out,
            "<tr><td class=\"mono\">{}</td>",
            Name::given(&m.machine_text).html()
        )?;
        if own {
            let system = m.system_text.as_deref().map(|t| Name::given(t).html());
            write!(out, "<td>{}</td>", system.unwrap_or_default())?;
        }
        writeln!(out, "<td class=\"mono\">{}</td></tr>", names(&m.names_text))?;
    }
    out.push_str("</tbody></table></div>\n");
    Ok(())
}

/// A reading's badge, from how much it read and, when it read nothing, why: a reading that was
/// not given or has no reader in this version did not fail.
fn reading_badge(out: &mut String, c: &v1::Coverage) -> Out {
    let word = match v1::Completeness::try_from(c.completeness) {
        Ok(v1::Completeness::Full) => "full",
        Ok(v1::Completeness::Partial) => "partial",
        _ => match c.cause.map(v1::Cause::try_from) {
            Some(Ok(v1::Cause::NotGiven)) => "not given",
            Some(Ok(v1::Cause::NoReader)) => "no reader in this version",
            _ => "none",
        },
    };
    match word {
        "full" | "partial" | "none" => badge(out, word, c.reason_text.as_deref()),
        quiet => Ok(write!(out, "<span class=\"badge quiet\">{quiet}</span>")?),
    }
}

/// The statement that sets a machine aside, with how it came and why.
fn statement(out: &mut String, word: Option<&v1::Statement>) -> Out {
    let Some(w) = word else { return Ok(()) };
    write!(
        out,
        "<p>You said it is {}, {}.",
        esc(&w.said),
        crate::finding_text::given_by(w.via)
    )?;
    if !w.reason_text.is_empty() {
        write!(out, " Why: {}.", Said::given(&w.reason_text).html())?;
    }
    out.push_str("</p>\n");
    Ok(())
}

/// One machine, opening to what `immunity machine` knows of it: its latest visit by the server
/// check, what it runs, every reading of it with how much it read, and what is on it. With the
/// statement that sets it aside, as the statement says it. `names` is the name it is shown by,
/// its other names, and the kinds of the readings that name it.
fn block(
    out: &mut String,
    (name, others, known_from): (&str, &[String], &[String]),
    k: Option<&v1::Known>,
    word: Option<&v1::Statement>,
    now: i64,
) -> Out {
    write!(
        out,
        "<details class=\"machine\">\n<summary><strong>{}</strong>",
        Name::given(name).html()
    )?;
    // A machine set aside is shown as its statement says, whatever its answer: who set it aside
    // and how is said where it is listed, so an answer through an agent is seen.
    let mut meta: Vec<String> = Vec::new();
    if let Some(w) = word {
        write!(out, " <span class=\"badge good\">{}</span>", esc(&w.said))?;
        let agent = (w.via == v1::Via::Agent as i32)
            .then(|| format!(", {}", crate::finding_text::given_by(w.via)));
        meta.push(format!(
            "you said so {}{}",
            utc(w.at),
            agent.unwrap_or_default()
        ));
    }
    let Some(k) = k else {
        if word.is_none() {
            out.push_str(" <span class=\"badge bad\">not known</span>");
        }
        for said in &meta {
            write!(out, " <span class=\"muted\">· {said}</span>")?;
        }
        out.push_str("</summary>\n<div class=\"inner\">\n");
        statement(out, word)?;
        out.push_str("<p class=\"alert\">immunity machine gives no answer about it, so nothing of what was read on it is known here.</p>\n</div>\n</details>\n");
        return Ok(());
    };
    let own: Vec<&str> = (k.thing.iter().map(|t| t.id_text.as_str()))
        .chain(k.same_as.iter().map(|e| e.id_text.as_str()))
        .collect();
    let readings: Vec<&v1::Coverage> = (k.coverage.iter())
        .filter(|c| own.contains(&c.scope_text.as_str()))
        .collect();
    let is_visit = |c: &v1::Coverage| c.reader == servers::READER && c.kind == servers::VISIT;
    let visit = (readings.iter().copied())
        .filter(|c| is_visit(c))
        .max_by_key(|c| c.observed_at);
    // Checked only when the latest visit is one that was made and read in full.
    let (class, state) = match visit.filter(|c| c.observed_at.is_some()) {
        None => ("bad", "never checked"),
        Some(c) if full(c) => ("good", "checked"),
        Some(c) if c.reason_text.as_deref() == Some(servers::NOT_COMPLETE) => {
            ("bad", "did not finish")
        }
        Some(_) => ("bad", "could not be opened"),
    };
    // The server check no longer visits a machine set aside: its state is its statement's.
    if word.is_none() {
        write!(out, " <span class=\"badge {class}\">{state}</span>")?;
    }
    // A finding in a state this build does not know is read as open.
    let closed = [
        v1::FindingState::Expected,
        v1::FindingState::Seen,
        v1::FindingState::Cleared,
    ];
    let open = (k.findings.iter())
        .filter(|f| !closed.iter().any(|s| *s as i32 == f.state))
        .count();
    if open > 0 {
        write!(
            out,
            " <span class=\"badge bad\">{}</span>",
            crate::view::plural(open, "finding needs a look", "findings need a look")
        )?;
    }
    // Read when a reading of substance read something; a full visit alone read nothing of it.
    let read_at = (readings.iter())
        .filter(|c| !is_visit(c) && c.completeness != v1::Completeness::None as i32)
        .filter_map(|c| c.observed_at)
        .max();
    // One time is said once: the visit only when it is not the latest reading too.
    if let Some(at) = visit
        .and_then(|c| c.observed_at)
        .filter(|at| Some(*at) != read_at)
    {
        meta.push(format!("visited {}", utc(at)));
    }
    meta.push(match read_at {
        Some(at) => format!("read {}", utc_age(at, now)),
        None => "nothing read".to_string(),
    });
    writeln!(
        out,
        " <span class=\"muted\">· {}</span></summary>\n<div class=\"inner\">",
        meta.join(" · ")
    )?;

    statement(out, word)?;
    if !others.is_empty() {
        writeln!(
            out,
            "<p class=\"muted\">Also known as {}.</p>",
            names(others)
        )?;
    }
    if !known_from.is_empty() {
        writeln!(
            out,
            "<p class=\"muted\">Known from {}.</p>",
            esc(&known_from.join(", "))
        )?;
    }
    if let Some(c) = visit.filter(|c| c.observed_at.is_some() && !full(c)) {
        let reason = unescape(c.reason_text.as_deref().unwrap_or_default());
        write!(
            out,
            "<p class=\"alert\">The latest visit failed {}: {}.",
            utc(c.observed_at.unwrap_or_default()),
            Said::of(reason.trim_end_matches('.')).html()
        )?;
        // Never asked of a machine the person said is retired or not theirs.
        if let Some(advice) = crate::sweep::advice(&reason).filter(|_| word.is_none()) {
            write!(out, " {advice}")?;
        }
        out.push_str("</p>\n");
    }
    let facts = |subject: &str, predicate: &str| -> Vec<String> {
        (k.facts.iter())
            .filter(|f| f.subject_text == subject && f.predicate == predicate)
            .map(|f| f.object_text.clone())
            .collect()
    };
    let system: Vec<String> = SYSTEM
        .iter()
        .filter_map(|(predicate, label)| {
            let values: Vec<String> = own.iter().flat_map(|id| facts(id, predicate)).collect();
            (!values.is_empty()).then(|| format!("{label} {}", names(&values)))
        })
        .collect();
    if !system.is_empty() {
        writeln!(out, "<p class=\"muted\">{}</p>", system.join(" · "))?;
    }

    let shown: Vec<&&v1::Coverage> = readings.iter().filter(|c| !is_visit(c)).collect();
    if shown.is_empty() {
        out.push_str("<p class=\"alert\">Nothing was ever read on this machine itself.</p>\n");
    } else {
        out.push_str("<ul class=\"readings\">\n");
        // A reason that is the failed visit's own is said once, in the alert above.
        let visit_failed = (visit.and_then(|c| c.reason_text.as_deref()))
            .map(|r| format!("{}{}", servers::VISIT_FAILED, unescape(r)));
        for c in shown {
            write!(out, "<li>{} ", esc(&c.kind))?;
            reading_badge(out, c)?;
            let reason = c.reason_text.as_deref().map(unescape);
            if let Some(reason) = reason.filter(|r| Some(r) != visit_failed.as_ref()) {
                write!(out, " {}", Said::of(&reason).html())?;
            }
            if let Some(at) = c.observed_at {
                write!(
                    out,
                    " <span class=\"muted nowrap\">{}</span>",
                    utc_age(at, now)
                )?;
            }
            out.push_str("</li>\n");
        }
        out.push_str("</ul>\n");
    }

    let parts = |ty: &str| -> Vec<&str> {
        (k.parts.iter())
            .filter(|p| p.r#type == ty)
            .map(|p| p.id_text.as_str())
            .collect()
    };
    let packages = parts("component");
    if !packages.is_empty() {
        writeln!(
            out,
            "<h3>{}</h3>\n<div class=\"scroll\"><table class=\"dense\">",
            crate::view::counted(packages.len() as i64, "package", "packages")
        )?;
        thead(out, &["Name", "Ecosystem", "Version", "Built from"]);
        for id in packages {
            let (ecosystem, name) = crate::view::component_name(id);
            writeln!(
                out,
                "<tr><td>{}</td><td class=\"nowrap\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td></tr>",
                Name::given(name).html(),
                Name::given(ecosystem).html(),
                names(&facts(id, "has_version")),
                names(&facts(id, "built_from"))
            )?;
        }
        out.push_str("</tbody></table></div>\n");
    }
    // Containers by name with their image, projects by their path, which `immunity project` asks.
    for (ty, heading) in [("container", "Containers"), ("checkout", "Projects")] {
        let list: Vec<String> = (parts(ty).into_iter())
            .map(|id| {
                let name = match crate::known::place_of(id) {
                    Some((_, rel)) => rel,
                    None => id.rsplit('/').next().unwrap_or(id),
                };
                let mut item = Name::given(name).html();
                for image in facts(id, "runs_image") {
                    item.push_str(&format!(" · {}", Name::given(&image).html()));
                }
                format!("<li>{item}</li>\n")
            })
            .collect();
        if !list.is_empty() {
            writeln!(
                out,
                "<h3>{heading}</h3>\n<ul class=\"readings\">\n{}</ul>",
                list.concat()
            )?;
        }
    }
    out.push_str("</div>\n</details>\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_900_000_000;

    fn reading(kind: &str, completeness: v1::Completeness, at: Option<i64>) -> v1::Coverage {
        v1::Coverage {
            reader: servers::READER.to_string(),
            kind: kind.to_string(),
            scope_text: "machine:web-1".to_string(),
            completeness: completeness as i32,
            observed_at: at,
            ..Default::default()
        }
    }

    /// What `immunity machine machine:web-1` answers: the readings given and no part.
    fn known(coverage: Vec<v1::Coverage>) -> v1::Known {
        v1::Known {
            thing: Some(v1::Entity {
                id_text: "machine:web-1".to_string(),
                r#type: "machine".to_string(),
            }),
            coverage,
            ..Default::default()
        }
    }

    fn server(name: &str) -> v1::KnownMachine {
        v1::KnownMachine {
            machine_text: name.to_string(),
            entities_text: vec![format!("machine:{name}")],
            kind: v1::MachineKind::Server as i32,
            ..Default::default()
        }
    }

    /// The page with these statements and machines, every machine answered with `k`.
    fn drawn(s: &v1::Statements, k: Option<v1::Known>) -> String {
        let machine = move |_: &str| Ok(k.clone());
        page(&v1::Status::default(), s, &machine, NOW).unwrap()
    }

    fn with_servers(names: &[&str]) -> v1::Statements {
        v1::Statements {
            machines: names.iter().map(|n| server(n)).collect(),
            ..Default::default()
        }
    }

    /// The summary line of the one machine on a page.
    fn summary(page: &str) -> &str {
        let at = page.find("<summary>").unwrap();
        &page[at..at + page[at..].find("</summary>").unwrap()]
    }

    #[test]
    fn a_server_is_said_to_be_checked_only_when_its_latest_visit_in_the_answer_was_made_and_full() {
        // "Checked" is calm. It rests on the visit `immunity machine` gives, never on the server
        // being listed: a visit made by rule, one not full, and one of a completeness this build
        // does not know are each not checked.
        use v1::Completeness as C;
        let s = with_servers(&["web-1"]);
        let visit = |c: C, at: Option<i64>| {
            summary(&drawn(
                &s,
                Some(known(vec![reading(servers::VISIT, c, at)])),
            ))
            .to_string()
        };
        assert!(visit(C::Full, Some(NOW)).contains("<span class=\"badge good\">checked</span>"));
        for (c, at) in [
            (C::None, None),
            (C::Full, None),
            (C::Partial, Some(NOW)),
            (C::Unspecified, Some(NOW)),
        ] {
            let said = visit(c, at);
            assert!(!said.contains(">checked<"), "{c:?} {at:?}: {said}");
        }
        assert!(visit(C::None, None).contains("never checked"));
        // Of a machine known under two ids, the latest visit under either is the one that counts.
        let mut two = known(vec![
            reading(servers::VISIT, C::Full, Some(NOW - 60)),
            reading(servers::VISIT, C::None, Some(NOW)),
        ]);
        two.coverage[1].scope_text = "machine:203.0.113.5".to_string();
        two.same_as.push(v1::Entity {
            id_text: "machine:203.0.113.5".to_string(),
            r#type: "machine".to_string(),
        });
        let said = summary(&drawn(&s, Some(two))).to_string();
        assert!(said.contains("could not be opened"), "{said}");
        // A machine of a kind this build does not know is listed as a server.
        let mut odd = with_servers(&["web-1"]);
        odd.machines[0].kind = 99;
        let page = drawn(&odd, Some(known(Vec::new())));
        assert!(
            page[page.find("<section id=\"servers\"").unwrap()
                ..page.find("<section id=\"your-devices\"").unwrap()]
                .contains("<strong><bdi class=\"src\">web-1</bdi></strong>"),
            "{page}"
        );
        assert!(summary(&drawn(&s, Some(known(Vec::new())))).contains("never checked"));
        // A server whose answer could not be had says nothing of what was read on it.
        let none = drawn(&s, None);
        assert!(
            !none.contains(">checked<") && none.contains("not known"),
            "{none}"
        );
    }

    #[test]
    fn a_server_is_said_to_have_been_read_only_at_a_reading_that_read_something() {
        // A failed visit writes readings that read nothing: their time is not a time the server
        // was read.
        use v1::Completeness as C;
        let s = with_servers(&["web-1"]);
        let page = |readings| summary(&drawn(&s, Some(known(readings)))).to_string();
        let failed = page(vec![
            reading("system packages", C::None, Some(NOW)),
            reading(servers::VISIT, C::None, Some(NOW)),
        ]);
        assert!(
            failed.contains("nothing read") && !failed.contains("· read "),
            "{failed}"
        );
        let earlier = page(vec![
            reading("system packages", C::Partial, Some(NOW - 86_400)),
            reading("system release", C::None, Some(NOW)),
        ]);
        assert!(
            earlier.contains(&format!("read {}", utc(NOW - 86_400))),
            "{earlier}"
        );
        // A full visit whose readings of substance read nothing read nothing of the server.
        let empty = page(vec![
            reading("system packages", C::None, Some(NOW)),
            reading(servers::VISIT, C::Full, Some(NOW)),
        ]);
        assert!(
            empty.contains(&format!("visited {} · nothing read", utc(NOW))),
            "{empty}"
        );
    }

    #[test]
    fn a_list_of_machines_says_it_is_empty_only_when_no_reading_it_rests_on_is_named_not_read() {
        // "None known" over a reading that failed reads as "looked, and there is none".
        let mut s = v1::Statements::default();
        let empty = drawn(&s, None);
        assert!(
            empty.contains("<p class=\"muted\">None known.</p>"),
            "{empty}"
        );
        assert_eq!(
            empty.matches("<p class=\"muted\">None seen.</p>").count(),
            2
        );
        let mut ssh = reading("ssh configuration", v1::Completeness::None, Some(NOW));
        ssh.reader = crate::ssh_config::READER.to_string();
        ssh.reason_text = Some("Permission denied".to_string());
        s.machines_not_read = vec![ssh];
        let page = drawn(&s, None);
        assert!(!page.contains("None known."), "{page}");
        assert!(page.contains("may not be whole: ssh configuration (<bdi class=\"src\">Permission denied</bdi>; never read in full)."), "{page}");
        // The devices rest on the private network alone, which was read.
        assert_eq!(page.matches("None seen.").count(), 2, "{page}");
        // One read in full before the latest run says so, with when.
        let mut stale = reading("known hosts", v1::Completeness::Full, Some(NOW - 7200));
        stale.last_full_at = Some(NOW - 7200);
        s.machines_not_read = vec![stale];
        let page = drawn(&s, None);
        assert!(
            page.contains(&format!(
                "known hosts (not read at the latest check; last read in full {})",
                utc(NOW - 7200)
            )),
            "{page}"
        );
        let mut never = reading("tailnet peers", v1::Completeness::None, None);
        never.reader = tailnet::READER.to_string();
        s.machines_not_read = vec![never];
        let page = drawn(&s, None);
        assert_eq!(
            page.matches("Not read yet, so what is here is not known.")
                .count(),
            3,
            "{page}"
        );
        assert!(
            !page.contains("None seen.") && !page.contains("None known."),
            "{page}"
        );
    }

    #[test]
    fn a_machine_set_aside_is_shown_as_its_statement_says_with_who_said_it() {
        // An agent's statement quiets a machine only where it is seen, with that it came
        // through the agent, so the person can take it back.
        let word = |via: v1::Via, seen: bool| v1::Statement {
            machine_text: "old-box".to_string(),
            entity_text: "machine:old-box".to_string(),
            said: "not mine".to_string(),
            via: via as i32,
            at: NOW - 3600,
            reason_text: "A client's server".to_string(),
            seen_after: seen.then(|| v1::SeenAfter {
                at: NOW,
                what_text: "servers read containers on old-box".to_string(),
            }),
            ..Default::default()
        };
        let s = v1::Statements {
            statements: vec![word(v1::Via::Agent, false)],
            ..Default::default()
        };
        let page = drawn(&s, Some(known(Vec::new())));
        let aside = &page[page.find("<section id=\"retired\"").unwrap()..];
        assert!(
            !aside.contains("never checked</span>")
                && summary(aside).contains(&format!(
                    "<span class=\"badge good\">not mine</span> <span class=\"muted\">· you said so {}, through your agent ·",
                    utc(NOW - 3600)
                ))
                && aside.contains(
                    "You said it is not mine, through your agent. Why: <bdi class=\"src\">A client&#39;s server</bdi>."
                ),
            "{aside}"
        );
        // One given in the app says when on its line, and how inside.
        let s = v1::Statements {
            statements: vec![word(v1::Via::App, false)],
            ..Default::default()
        };
        let page = drawn(&s, Some(known(Vec::new())));
        let line = summary(&page[page.find("<section id=\"retired\"").unwrap()..]);
        assert!(
            line.contains(&format!("· you said so {} ·", utc(NOW - 3600))),
            "{line}"
        );
        // Without an answer about the machine, the statement is still drawn whole.
        let s = v1::Statements {
            statements: vec![word(v1::Via::Agent, false)],
            ..Default::default()
        };
        let page = drawn(&s, None);
        let aside = &page[page.find("<section id=\"retired\"").unwrap()..];
        assert!(
            summary(aside).contains(&format!("you said so {}, through your agent", utc(NOW - 3600)))
                && aside.contains("You said it is not mine, through your agent. Why: <bdi class=\"src\">A client&#39;s server</bdi>.")
                && aside.contains("gives no answer about it"),
            "{aside}"
        );
        // Its failed visit keeps its reason and never asks the person to connect to it.
        let why = "Host key verification failed.";
        let mut visit = reading(servers::VISIT, v1::Completeness::None, Some(NOW));
        visit.reason_text = Some(why.to_string());
        let mut k = known(vec![visit]);
        k.thing.as_mut().unwrap().id_text = "machine:old-box".to_string();
        k.coverage[0].scope_text = "machine:old-box".to_string();
        let page = drawn(&s, Some(k));
        let aside = &page[page.find("<section id=\"retired\"").unwrap()..];
        assert!(
            aside.contains("Host key verification failed")
                && !aside.contains(crate::sweep::advice(why).unwrap()),
            "{aside}"
        );
        // One that something seen since contradicts sets nothing aside, and says so.
        let s = v1::Statements {
            statements: vec![word(v1::Via::App, true)],
            ..Default::default()
        };
        let page = drawn(&s, Some(known(Vec::new())));
        let aside = &page[page.find("<section id=\"retired\"").unwrap()..];
        assert!(aside.contains("<p class=\"muted\">None.</p>"), "{aside}");
        assert!(
            page.contains("<p class=\"alert\">You said <bdi class=\"src\">old-box</bdi> is not mine on ")
                && page.contains("<bdi class=\"src\">servers read containers on old-box</bdi>. It is counted as a server again"),
            "{page}"
        );
    }

    #[test]
    fn a_time_is_said_once_on_the_line_of_a_machine() {
        // A full visit is the latest reading: "visited" beside "read" would say one time twice.
        use v1::Completeness as C;
        let s = with_servers(&["web-1"]);
        let line = |readings| summary(&drawn(&s, Some(known(readings)))).to_string();
        let full = line(vec![
            reading("system packages", C::Full, Some(NOW)),
            reading(servers::VISIT, C::Full, Some(NOW)),
        ]);
        assert!(
            !full.contains("visited") && full.contains(&format!("· read {}", utc(NOW))),
            "{full}"
        );
        let failed = line(vec![
            reading("system packages", C::Full, Some(NOW - 86_400)),
            reading(servers::VISIT, C::None, Some(NOW)),
        ]);
        assert!(
            failed.contains(&format!(
                "· visited {} · read {}",
                utc(NOW),
                utc(NOW - 86_400)
            )),
            "{failed}"
        );
    }

    #[test]
    fn the_reason_a_failed_visit_gives_is_said_once_and_a_reading_that_was_not_given_is_not_said_to_have_failed()
     {
        // Each reading of a failed visit carries its reason; the alert says it, and a reading
        // whose own reason differs keeps it. A reading the core was not given read nothing and
        // did not fail.
        use v1::Completeness as C;
        let why = "Host key verification failed.";
        let mut visit = reading(servers::VISIT, C::None, Some(NOW));
        visit.reason_text = Some(why.to_string());
        let mut packages = reading("system packages", C::None, Some(NOW));
        packages.reason_text = Some(format!("{}{why}", servers::VISIT_FAILED));
        let mut release = reading("system release", C::None, Some(NOW));
        release.reason_text = Some("the file of this server could not be read".to_string());
        let mut aside = reading("sweep of a machine set aside", C::None, None);
        aside.reason_text = Some("the owner set it aside".to_string());
        aside.cause = Some(v1::Cause::NotGiven as i32);
        let mut kept = reading("kept packages", C::None, Some(NOW));
        kept.cause = Some(v1::Cause::NoReader as i32);
        let page = drawn(
            &with_servers(&["web-1"]),
            Some(known(vec![visit, packages, release, aside, kept])),
        );
        assert!(
            page.contains(
                "kept packages <span class=\"badge quiet\">no reader in this version</span>"
            ),
            "{page}"
        );
        assert_eq!(
            page.matches("Host key verification failed").count(),
            1,
            "{page}"
        );
        assert!(
            page.contains(
                "system packages <span class=\"badge bad\">could not be read</span> <span class=\"muted"
            ),
            "{page}"
        );
        assert!(
            page.contains("the file of this server could not be read"),
            "{page}"
        );
        assert!(
            page.contains(
                "sweep of a machine set aside <span class=\"badge quiet\">not given</span>"
            ),
            "{page}"
        );
    }

    #[test]
    fn a_reason_the_answer_gives_whole_is_cut_where_the_page_shows_it() {
        // `Known` gives a reading's reason whole, as its source said it: a token in it reaches
        // the page as a mark.
        let token = format!(
            "{}{}",
            ["gh", "p_"].concat(),
            "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u"
        );
        let said = format!("refused ?t={token}");
        let mut visit = reading(servers::VISIT, v1::Completeness::None, Some(NOW));
        visit.reason_text = Some(said.clone());
        let mut packages = reading("system packages", v1::Completeness::None, Some(NOW));
        packages.reason_text = Some(said.clone());
        let mut ssh = reading("ssh configuration", v1::Completeness::None, Some(NOW));
        ssh.reason_text = Some(said);
        let s = v1::Statements {
            machines: vec![server("web-1")],
            machines_not_read: vec![ssh],
            ..Default::default()
        };
        let page = drawn(&s, Some(known(vec![visit, packages])));
        let mark = crate::secrets::mark("gitleaks:github-pat", 40);
        assert!(!page.contains(&token), "{page}");
        assert_eq!(page.matches(&format!("?t={mark}")).count(), 3, "{page}");
    }

    #[test]
    fn text_from_a_machine_reaches_the_page_only_through_the_printer_each_in_an_element_of_its_own()
    {
        // Names, systems, packages and facts are written by whoever controls the machine.
        let evil = "<img src=x onerror=alert(1)>\u{202e}";
        let mut s = with_servers(&[evil]);
        s.machines[0].names_text = vec![evil.to_string()];
        s.machines.push(v1::KnownMachine {
            machine_text: evil.to_string(),
            kind: v1::MachineKind::OwnDevice as i32,
            system_text: Some(evil.to_string()),
            ..Default::default()
        });
        let mut k = known(vec![reading(
            servers::VISIT,
            v1::Completeness::Full,
            Some(NOW),
        )]);
        let package = format!("component:machine:web-1/deb/{evil}");
        k.parts.push(v1::Entity {
            id_text: package.clone(),
            r#type: "component".to_string(),
        });
        for (subject, predicate) in [
            ("machine:web-1", "runs_os"),
            (package.as_str(), "has_version"),
        ] {
            k.facts.push(v1::Fact {
                subject_text: subject.to_string(),
                predicate: predicate.to_string(),
                object_text: evil.to_string(),
                ..Default::default()
            });
        }
        let page = drawn(&s, Some(k));
        let shown = Name::given(evil).html();
        assert!(
            !page.contains("<img") && !page.contains('\u{202e}'),
            "{page}"
        );
        assert_eq!(page.matches(shown.as_str()).count(), 7, "{page}");
    }

    #[test]
    fn findings_on_a_machine_are_counted_from_its_answer_and_none_is_never_said_to_be_none() {
        // A state this build does not know is open. No line says a machine has no finding.
        let s = with_servers(&["web-1"]);
        let mut k = known(Vec::new());
        for state in [
            v1::FindingState::Open as i32,
            99,
            v1::FindingState::Seen as i32,
        ] {
            k.findings.push(v1::FindingRef {
                state,
                ..Default::default()
            });
        }
        let page = drawn(&s, Some(k));
        assert!(summary(&page).contains("<span class=\"badge bad\">2 findings need a look</span>"));
        let page = drawn(&s, Some(known(Vec::new())));
        let body = &page[page.find("<section id=\"servers\"").unwrap()..];
        assert!(!body.contains("finding"), "{body}");
    }
}
