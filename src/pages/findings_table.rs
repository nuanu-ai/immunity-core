//! The table of findings on the summary, drawn from what `immunity findings` answers and, for
//! each finding a row opens, what `immunity finding <id>` answers (`view::Answers`): nothing here
//! reads the store or decides again what the messages say. A finding of the core and the
//! response layer's own finding about the same rule and thing are one row, joined by what the
//! messages name: the rule a `verdict.suspicious` finding's verdicts were about
//! (`VerdictGiven.rule`) and the thing (`about_text`). Every finding open or answered is in
//! exactly one row. The tabs count findings as the status does, each finding of a pair one.
//! Text from the Mac or a source in a row is printed through `secrets::Name` and
//! `secrets::Said`.

use super::{COPY, capital};
use crate::contract::v1;
use crate::secrets::{Name, Said};
use crate::view::{self, Answers, counted, esc, esc_said};
use std::error::Error;
use std::fmt::Write;

/// At most this many things that need a look are shown in full, so the summary stays small.
const ITEMS_SHOWN: usize = 100;

/// A finding as the table takes it: as the list gives it, its reference, and whether it is open,
/// else answered with its answer in force. Any other finding, cleared or no longer hidden by an
/// answer while not open, is not in the table.
#[derive(Clone, Copy)]
struct Listed<'a> {
    l: &'a v1::ListedFinding,
    r: &'a v1::FindingRef,
    open: bool,
}

/// Whether a finding in this state is open: any state but expected, seen and cleared, so a state
/// the reader does not know is read as open (`common.proto`). One predicate for every page.
pub(crate) fn is_open(state: i32) -> bool {
    use v1::FindingState as S;
    !matches!(S::try_from(state), Ok(S::Expected | S::Seen | S::Cleared))
}

impl<'a> Listed<'a> {
    fn of(l: &'a v1::ListedFinding) -> Option<Listed<'a>> {
        let r = l.finding.as_ref()?;
        let open = is_open(r.state);
        let in_force = l.answer.as_ref().is_some_and(|a| a.in_force);
        (open || in_force).then_some(Listed { l, r, open })
    }

    /// Its id on the page: as it is while open, and after `answered-` while answered.
    fn anchor(&self) -> String {
        match self.open {
            true => esc(&self.r.id),
            false => format!("answered-{}", esc(&self.r.id)),
        }
    }
}

/// One row of the table: one thing. Its finding, the response layer's own findings about the same
/// thing, and the other findings of its group drawn in it.
struct FindingRow<'a> {
    item: Listed<'a>,
    under: Vec<Listed<'a>>,
    /// The other findings of the item's group (`ListedFinding.group`) in its state, none with a
    /// verdict or a pair: the row is their folder.
    siblings: Vec<Listed<'a>>,
}

impl FindingRow<'_> {
    /// How many findings the row holds.
    fn weight(&self) -> usize {
        1 + self.siblings.len() + self.under.len()
    }

    /// The row is in Open while any finding in it is open, and in Answered while any is
    /// answered: a verdict never takes a finding out of Open.
    fn open(&self) -> bool {
        self.item.open || self.under.iter().any(|u| u.open)
    }

    fn answered(&self) -> bool {
        !self.item.open || self.under.iter().any(|u| !u.open)
    }

    /// It needs the person now: an open finding in it, the core's or the response layer's,
    /// is one Immunity Core marks urgent.
    fn urgent(&self) -> bool {
        let urgent = |f: &Listed| f.open && f.r.urgent;
        urgent(&self.item) || self.under.iter().any(urgent)
    }
}

/// The rows, open first in the list's order, then the answered, the latest answer first. A
/// finding of `verdict.suspicious` is drawn in the row of the core's finding of the rule its
/// verdicts were about and of the same thing, once, and is not a row of its own; one with no
/// such partner is a row of its own, so every finding is in exactly one row. `subject` gives
/// that rule for a finding of `verdict.suspicious`.
fn finding_rows<'a>(
    all: &[Listed<'a>],
    subject: &dyn Fn(&str) -> rusqlite::Result<Option<String>>,
) -> rusqlite::Result<Vec<FindingRow<'a>>> {
    let verdict = |f: &Listed| f.r.rule.as_deref() == Some(crate::verdict::RULE);
    let mut nested = std::collections::BTreeSet::new();
    let mut under: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    for (k, own) in all.iter().enumerate().filter(|(_, f)| verdict(f)) {
        let Some(rule) = subject(&own.r.id)? else {
            continue;
        };
        // Never a finding of the response layer as the core's: one about the verdict rule would
        // otherwise pair with itself and be folded out of sight.
        let partner = all.iter().position(|core| {
            !verdict(core)
                && core.r.rule.as_deref() == Some(rule.as_str())
                && core.r.about_text == own.r.about_text
        });
        if let Some(n) = partner {
            nested.insert(k);
            under.entry(n).or_default().push(k);
        }
    }
    let rows = (all.iter().enumerate())
        .filter(|(n, _)| !nested.contains(n))
        .map(|(n, f)| FindingRow {
            item: *f,
            under: (under.get(&n).into_iter().flatten())
                .map(|k| all[*k])
                .collect(),
            siblings: Vec::new(),
        });
    // A row of a group in the same state as the first row of that group goes into the first's
    // row, so the answer its summary shows is every member's. A row with anything under it or
    // with the response layer's word is never folded nor folded into, so every finding stays in
    // exactly one row.
    fn key<'b>(r: &FindingRow<'b>) -> Option<(&'b str, i32)> {
        let alone = r.under.is_empty() && verdict_word(r.item.l).is_none();
        Some((r.item.l.group.as_deref().filter(|_| alone)?, r.item.r.state))
    }
    let mut out: Vec<FindingRow> = Vec::new();
    for row in rows {
        match out
            .iter_mut()
            .find(|o| key(&row).is_some() && key(o) == key(&row))
        {
            Some(first) => first.siblings.push(row.item),
            None => out.push(row),
        }
    }
    Ok(out)
}

/// The findings as a table with three tabs, Open, Answered and All, each with its count of
/// findings, a pair two, as the status counts them. The tabs are links within the page, and the
/// stylesheet shows the rows of the one in the address (`:target`), Open when none is; a browser
/// that cannot select by what an element holds shows every row, so nothing is hidden by a
/// browser's age. The open rows are in two groups, as the panel has them: what needs the person
/// now, then what is to look at; then the answered. Each row opens in place to its facts and who
/// said what.
pub(super) fn table(out: &mut String, a: &Answers, now: i64) -> Result<(), Box<dyn Error>> {
    let mut listed: Vec<Listed> = a.findings.findings.iter().filter_map(Listed::of).collect();
    let at = |f: &Listed| f.l.answer.as_ref().map_or(0, |a| a.given_at);
    listed.sort_by(|x, y| {
        (y.open.cmp(&x.open)).then_with(|| match x.open || y.open {
            true => std::cmp::Ordering::Equal,
            false => at(y).cmp(&at(x)).then_with(|| x.r.id.cmp(&y.r.id)),
        })
    });
    let subject = |id: &str| -> rusqlite::Result<Option<String>> {
        use v1::evidence::Body;
        Ok((a.finding)(id)?.and_then(|f| match f.evidence?.body? {
            Body::VerdictGiven(v) => Some(v.rule),
            _ => None,
        }))
    };
    let rows = finding_rows(&listed, &subject)?;
    let open = listed.iter().filter(|f| f.open).count();
    let answered = listed.len() - open;
    writeln!(
        out,
        "<section id=\"findings\" class=\"findings\">\n<div class=\"wsh\"><h2>Findings</h2><nav class=\"tabs\" aria-label=\"Findings\"><a id=\"open\" href=\"#open\">Open <span class=\"tn\">{}</span></a><a id=\"answered\" href=\"#answered\">Answered <span class=\"tn\">{}</span></a><a id=\"all\" href=\"#all\">All <span class=\"tn\">{}</span></a></nav></div>",
        counted(open as i64, "", "").trim_end(),
        counted(answered as i64, "", "").trim_end(),
        counted(listed.len() as i64, "", "").trim_end(),
    )?;
    if open == 0 {
        out.push_str("<p class=\"empty open\">Nothing is open. A change in what is watched shows here when it is found.</p>\n");
    }
    if answered == 0 {
        out.push_str("<p class=\"empty answered\">Nothing is marked seen or expected now.</p>\n");
    }
    let (now_rows, rest): (Vec<&FindingRow>, Vec<&FindingRow>) =
        rows.iter().partition(|r| r.urgent());
    let (look, done): (Vec<&FindingRow>, Vec<&FindingRow>) =
        rest.into_iter().partition(|r| r.open());
    // The open rows drawn, the urgent first, and the answered, each cut at `ITEMS_SHOWN`.
    let open_cut = now_rows.len().min(ITEMS_SHOWN);
    let look_cut = look.len().min(ITEMS_SHOWN - open_cut);
    if !rows.is_empty() {
        out.push_str("<div class=\"fh open answered\" aria-hidden=\"true\"><span>Thing</span><span>What happened</span><span>Response layer</span><span class=\"fs\">Seen</span><span></span></div>\n");
        for (group, class, rows) in [
            // The one place on the page in the colour of what needs the person now.
            ("Needs you now", "open now", &now_rows[..open_cut]),
            ("To look at", "open", &look[..look_cut]),
            ("Answered", "answered", &done[..done.len().min(ITEMS_SHOWN)]),
        ] {
            if rows.is_empty() {
                continue;
            }
            writeln!(out, "<p class=\"fg {class}\">{group}</p>")?;
            for row in rows {
                finding_row(out, a, row, now)?;
            }
        }
    }
    // What is not drawn, in findings as the tabs count them.
    let weight = |rows: &[&FindingRow]| rows.iter().map(|r| r.weight()).sum::<usize>();
    let urgent = weight(&now_rows[open_cut..]);
    let hidden = urgent + weight(&look[look_cut..]);
    if hidden > 0 {
        // Urgent ones come first, so the rest are the mildest unless urgent ones overflow.
        let which = match urgent {
            0 => "the mildest".to_string(),
            u => format!("{} of them urgent", counted(u as i64, "", "").trim_end()),
        };
        writeln!(
            out,
            "<p class=\"meta more open\">{} more, {which}; <span class=\"mono\">immunity findings</span> lists them.</p>",
            counted(hidden as i64, "", "").trim_end()
        )?;
    }
    let answered_hidden = weight(&done[done.len().min(ITEMS_SHOWN)..]);
    if answered_hidden > 0 {
        writeln!(
            out,
            "<p class=\"meta more answered\">{} more answered; <span class=\"mono\">immunity findings --all</span> lists them.</p>",
            counted(answered_hidden as i64, "", "").trim_end()
        )?;
    }
    out.push_str("</section>\n");
    Ok(())
}

/// The response layer's verdict as one word: suspicious when any of its verdicts is, harmless
/// when every one is harmless; `None` with no verdict.
fn verdict_word(l: &v1::ListedFinding) -> Option<&'static str> {
    let v = l.verdicts.as_ref()?;
    let rule = l.finding.as_ref().and_then(|r| r.rule.as_deref());
    if rule == Some(crate::verdict::RULE) || v.suspicious > 0 {
        Some("Suspicious")
    } else if v.total > 0 {
        Some("Harmless")
    } else {
        None
    }
}

/// A name from the Mac as data, in an element of its own (`Name::html`).
fn named(s: &str) -> String {
    format!("<span class=\"mono\">{}</span>", Name::given(s).html())
}

/// The thing a finding is about, as HTML: in the program's words for a finding whose thing no
/// name from the Mac says, the item of places read for the first time; else the package and its
/// releases, the program or file a rule matched, else where it is, each a name.
fn thing_of(l: &v1::ListedFinding, f: Option<&v1::Finding>) -> String {
    if let Some(thing) = &l.thing {
        return esc(thing);
    }
    let name = |s: &str| Name::given(s).html();
    use v1::evidence::Body;
    let events: &[v1::Event] = match f.and_then(|f| f.evidence.as_ref()?.body.as_ref()) {
        Some(Body::VulnerablePackage(p)) => {
            if let Some(package) = &p.package_text {
                let releases: Vec<String> =
                    p.releases.iter().map(|r| name(&r.version_text)).collect();
                return format!("{} {}", name(package), releases.join(", "))
                    .trim_end()
                    .to_string();
            }
            &[]
        }
        Some(Body::PublishedRuleMatched(p)) => &p.events,
        Some(Body::VerdictGiven(v)) => &v.events,
        _ => &[],
    };
    use v1::event::Body as E;
    match events.first().and_then(|e| e.body.as_ref()) {
        Some(E::ProgramStart(s)) => {
            if let Some(p) = &s.process {
                return name(&p.executable_text);
            }
        }
        Some(E::FileEvent(e)) => return name(&e.path_text),
        None => {}
    }
    let about = l.finding.as_ref().map_or("", |r| r.about_text.as_str());
    name(
        Some(l.where_text.as_str())
            .filter(|w| !w.is_empty())
            .unwrap_or(about),
    )
}

/// One row, one thing: the thing as data, its kind and what happened, the response layer's word
/// as plain text, and when it was last seen. It opens to the facts and voices of each finding in
/// it, each with the command that answers it.
fn finding_row(
    out: &mut String,
    a: &Answers,
    row: &FindingRow,
    now: i64,
) -> Result<(), Box<dyn Error>> {
    let i = row.item;
    let whole = (a.finding)(&i.r.id)?;
    // The kind in the words a person reads, the same as the app's, and what happened to a place.
    let mut kind = i.l.kind_title.clone();
    if let Some(change) = i.l.change {
        kind.push_str(" · ");
        kind.push_str(crate::finding_text::change_said(change));
    }
    // A group's row is its folder, with how many findings it holds.
    let members: Vec<Listed> = std::iter::once(i).chain(row.siblings.clone()).collect();
    let folder = i.l.folder_text.as_deref().filter(|_| members.len() > 1);
    if folder.is_some() {
        kind.push_str(&format!(
            " · {}",
            counted(members.len() as i64, "finding", "findings")
        ));
    }
    let answer = i.l.answer.as_ref().filter(|_| !i.open).map(|a| {
        let said = match a.until_at {
            Some(u) => format!("expected until {}", view::when(u, now)),
            None => "seen".to_string(),
        };
        format!(
            "<span class=\"ans\">Answered: {said} {}</span>",
            esc(crate::finding_text::given_by(a.via))
        )
    });
    writeln!(
        out,
        "<details class=\"fr{}{}{}{}\" id=\"{}\">\n<summary><span class=\"fw\">{}</span><span class=\"fk\">{}{}</span><span class=\"fv\">{}</span><span class=\"fs\">{}</span><span class=\"fch\" aria-hidden=\"true\"></span></summary>\n<div class=\"fx\">",
        if row.open() { " open" } else { "" },
        if row.answered() { " answered" } else { "" },
        if row.urgent() { " urgent" } else { "" },
        // The mark of the response layer's word, the word's own colour (`.fr.suspicious .fv`).
        match verdict_word(i.l) {
            Some("Suspicious") => " suspicious",
            Some("Harmless") => " harmless",
            _ => "",
        },
        i.anchor(),
        folder.map_or_else(|| thing_of(i.l, whole.as_ref()), |f| Name::given(f).html()),
        esc(&kind),
        answer.unwrap_or_default(),
        verdict_word(i.l).map_or("<span class=\"none\">—</span>".to_string(), |w| format!(
            "<span class=\"src\">Response layer: </span>{w}"
        )),
        view::when(i.l.last_seen_at, now),
    )?;
    if folder.is_none() {
        finding_body(out, i, whole.as_ref(), now)?;
    }
    // Each finding of a group under its own thing, the first by the row's own id.
    for (k, m) in members.iter().enumerate().filter(|_| folder.is_some()) {
        let anchor = match k {
            0 => String::new(),
            _ => format!(" id=\"{}\"", m.anchor()),
        };
        let whole = (a.finding)(&m.r.id)?;
        writeln!(
            out,
            "<div class=\"also\"{anchor}>\n<p class=\"wsh2\">{}</p>",
            thing_of(m.l, whole.as_ref())
        )?;
        finding_body(out, *m, whole.as_ref(), now)?;
        out.push_str("</div>\n");
    }
    for c in &row.under {
        writeln!(
            out,
            "<div class=\"also\" id=\"{}\">\n<p class=\"wsh2\">The response layer's own finding about it</p>",
            c.anchor()
        )?;
        let whole = (a.finding)(&c.r.id)?;
        finding_body(out, *c, whole.as_ref(), now)?;
        out.push_str("</div>\n");
    }
    out.push_str("</div>\n</details>\n");
    Ok(())
}

/// What one finding says in an opened row: on the left its facts, where first, then the evidence
/// as `immunity finding <id>` gives it; on the right who said what, each voice named: the rule's
/// authors, the response layer, the person's answer, Immunity Core's own words, and what to do. Under
/// them, when it was seen and the command an agent reads it with.
fn finding_body(
    out: &mut String,
    i: Listed,
    f: Option<&v1::Finding>,
    now: i64,
) -> Result<(), Box<dyn Error>> {
    let mut facts: Vec<(&str, String)> = vec![("Where", named(&i.l.where_text))];
    // A finding of a rule this build does not have names the rule as the store keeps it: the
    // one thing beside where it is that says what found it.
    if i.l.kind == crate::findings::KEPT_KIND {
        facts.push(("Rule", named(i.r.rule.as_deref().unwrap_or_default())));
    }
    // What the source said, as data beside the sentences, cut as it is printed.
    if let Some(value) = f.and_then(|f| f.value_text.as_deref()) {
        let said = Said::of(&crate::contract::unescape(value)).html();
        facts.push(("Source said", format!("<span class=\"said\">{said}</span>")));
    }
    let mut voices: Vec<Voice> = Vec::new();
    if let Some(f) = f {
        evidence(f, &mut facts, &mut voices, now);
    }
    if let Some(t) = f.and_then(|f| f.technique_text.as_deref()) {
        facts.push(("ATT&amp;CK", named(t)));
    }
    out.push_str("<div>");
    dl(out, &facts);
    out.push_str("</div>\n<div><p class=\"wsh2\">Who said what</p><div class=\"voices\">");
    voices.push(Voice {
        name: "Immunity Core".to_string(),
        said: esc(f.map_or(&i.l.title, |f| &f.title)),
        detail: esc(f.map_or("", |f| &f.meaning)),
        quote: None,
    });
    voices.push(Voice {
        name: "What to do".to_string(),
        said: format!(
            "<span class=\"advice\">{}</span>",
            esc(f.map_or("", |f| &f.advice))
        ),
        detail: String::new(),
        quote: None,
    });
    for v in &voices {
        write!(
            out,
            "<div class=\"voice\"><div class=\"vn\">{}</div><div class=\"vs\">{}</div>",
            v.name, v.said
        )?;
        if !v.detail.is_empty() {
            write!(out, "<div class=\"vd\">{}</div>", v.detail)?;
        }
        if let Some(q) = &v.quote {
            write!(
                out,
                "\n<blockquote class=\"quote\">{}</blockquote>\n",
                esc_said(q)
            )?;
        }
        out.push_str("</div>");
    }
    out.push_str("</div></div>\n");
    let (first, last) = (i.l.first_seen_at, i.l.last_seen_at);
    let seen = match first != last {
        true => format!(
            "First seen {} · last seen {}",
            view::when(first, now),
            view::when(last, now)
        ),
        false => format!("Seen {}", view::when(last, now)),
    };
    let command = format!("immunity finding {} --json", i.r.id);
    writeln!(
        out,
        "<div class=\"fxb\"><span>{seen}</span><span>For your agent <span class=\"cmd\"><span class=\"mono\">{}</span>{COPY}</span></span></div>",
        esc(&command)
    )?;
    Ok(())
}

/// One voice of "Who said what": who, what they said and a quieter line, all safe HTML, and a
/// quote of their own words, escaped when it is written.
struct Voice {
    name: String,
    said: String,
    detail: String,
    quote: Option<String>,
}

/// Text from the Mac as data, in an element of its own.
fn data(s: &str) -> String {
    format!("<span class=\"mono\">{}</span>", esc(s))
}

/// Arguments as they come cut, each apart.
fn arguments(args: &[String]) -> String {
    let args: Vec<String> = args
        .iter()
        .map(|a| format!("<span class=\"arg\">{}</span>", esc_said(a)))
        .collect();
    format!("<span class=\"mono\">{}</span>", args.join(" "))
}

/// One event a rule matched: for a program start its program, each argument apart, its folder
/// and the program that started it; for a file event the file, what was done, from where and by
/// which program. Arguments come cut, as `immunity finding` prints them (`matches::event_cut`).
fn event_facts(e: &v1::Event, now: i64) -> Vec<(&'static str, String)> {
    use v1::event::Body;
    let mut facts = Vec::new();
    match e.body.as_ref() {
        Some(Body::ProgramStart(s)) => {
            if let Some(at) = s.happened_at {
                facts.push(("When", view::when(at, now)));
            }
            if let Some(p) = &s.process {
                facts.push(("Program", data(&p.executable_text)));
            }
            if !s.args_text.is_empty() {
                facts.push(("Arguments", arguments(&s.args_text)));
            }
            if let Some(wd) = &s.working_directory_text {
                facts.push(("Folder", data(wd)));
            }
            if let Some(p) = &s.instigator {
                facts.push(("Started by", data(&p.executable_text)));
            }
        }
        Some(Body::FileEvent(f)) => {
            if let Some(at) = f.happened_at {
                facts.push(("When", view::when(at, now)));
            }
            facts.push(("File", data(&f.path_text)));
            let action = match v1::FileAction::try_from(f.action) {
                Ok(v1::FileAction::Create) => "created",
                Ok(v1::FileAction::Rename) => "renamed",
                _ => "not known",
            };
            facts.push(("Done", action.to_string()));
            if let Some(from) = &f.source_text {
                facts.push(("From", data(from)));
            }
            if let Some(p) = &f.instigator {
                facts.push(("By", data(&p.executable_text)));
            }
        }
        None => {}
    }
    facts
}

/// Facts as a list of terms and values; each value is already safe.
fn dl(out: &mut String, facts: &[(&str, String)]) {
    if facts.is_empty() {
        return;
    }
    out.push_str("<dl class=\"facts\">");
    for (k, v) in facts {
        let _ = write!(out, "<dt>{k}</dt><dd>{v}</dd>");
    }
    out.push_str("</dl>\n");
}

/// A process a sample saw, as `DetachedProcess` gives it, each fact only where the finding has
/// it.
fn process_facts(p: &v1::DetachedProcess, facts: &mut Vec<(&str, String)>, now: i64) {
    if let Some(pid) = p.pid {
        facts.push(("Process id", data(&pid.to_string())));
    }
    if let Some(start) = p.start_micros {
        facts.push(("Started", view::when(start.div_euclid(1_000_000), now)));
    }
    if !p.args_text.is_empty() {
        facts.push(("Arguments", arguments(&p.args_text)));
    }
    if let Some(wd) = &p.working_directory_text {
        facts.push(("Folder", data(wd)));
    }
    for (label, l) in [
        ("Parent", &p.parent),
        ("Session led by", &p.session_leader),
        ("Group led by", &p.process_group_leader),
    ] {
        if let Some(l) = l {
            let signed = l
                .signed_by_text
                .as_deref()
                .map_or("signer not known".to_string(), |s| {
                    format!("signed by {}", data(s))
                });
            let said = format!("{}, pid {}, {signed}", data(&l.executable_text), l.pid);
            facts.push((label, said));
        }
    }
}

/// A finding's evidence as `immunity finding <id>` gives it, from the same message: what it rests
/// on by its kind as facts, and as voices the rule's authors, the response layer's verdicts with
/// their reasons quoted, and the person's answer with who gave it and why. Every value from the
/// Mac is escaped and set apart.
fn evidence(f: &v1::Finding, facts: &mut Vec<(&str, String)>, voices: &mut Vec<Voice>, now: i64) {
    use v1::evidence::Body;
    let word = |s: &str| format!("<span class=\"w\">{}</span>", esc(s));
    match f.evidence.as_ref().and_then(|e| e.body.as_ref()) {
        Some(Body::PlaceChanged(p)) => {
            facts.push((
                "What happened",
                word(crate::finding_text::change_said(p.change)),
            ));
            if let Some(at) = p.read_as_before_at {
                let (before, after) = crate::finding_text::READ_AS_BEFORE;
                let said = format!("{} {} {}", word(before), view::when(at, now), word(after));
                facts.push(("Read back", said));
            }
            if p.presence_only == Some(true) {
                facts.push((
                    "Watched",
                    word(&format!(
                        "only for presence: {}",
                        crate::watched::PRESENCE_ONLY
                    )),
                ));
            }
            if p.change == v1::Change::NotRead as i32 {
                let latest = f.rests_on.last().map(|b| b.run_id.as_str());
                let why = f
                    .rests_on
                    .iter()
                    .rev()
                    .take_while(|b| Some(b.run_id.as_str()) == latest)
                    .find(|b| b.entry == "not_read")
                    .and_then(|b| b.new_value_text.as_deref());
                facts.push(("Why", why.map_or(word("the store gives no reason"), data)));
            }
            let runs = p.runs.iter().map(|t| ("Runs", t));
            for (label, t) in runs.chain(p.started_by.iter().map(|t| ("Run by", t))) {
                let said = word(crate::finding_text::tie_said(t.state));
                let when = view::when(t.recorded_at, now);
                facts.push((label, format!("{} {said} {when}", data(&t.path_text))));
                if let Some(signer) = &t.signed_by_text {
                    facts.push(("Signer", data(signer)));
                }
            }
            if let Some(b) = crate::finding_text::signer_entry(f) {
                let (until, from) = crate::finding_text::SIGNER_SAID;
                let when = view::when(b.recorded_at, now);
                for (label, said, value) in [
                    ("Signer before", until, &b.old_value_text),
                    ("Signer after", from, &b.new_value_text),
                ] {
                    if let Some(value) = value {
                        facts.push((label, format!("{} {} {when}", data(value), word(said))));
                    }
                }
            }
            for b in f.rests_on.iter().filter(|b| b.entry == "place_first_read") {
                if let Some(place) = &b.subject_text {
                    facts.push(("First read", data(place)));
                }
            }
        }
        Some(Body::ChangedInPlace(p)) => {
            match (&p.became_text, &p.files) {
                (Some(value), _) => facts.push(("It became", data(value))),
                // The files that changed, as the text names them; where a folder changed whole,
                // its path is from the Mac and its number of files is Immunity Core's.
                (None, Some(files)) => {
                    let (counts, entries) = crate::finding_text::files_said(files);
                    facts.push(("Files", word(&counts)));
                    for (label, x) in entries {
                        let shown = match x.folder {
                            true => {
                                let n = i64::try_from(x.files).unwrap_or(i64::MAX);
                                let n = word(&format!("({})", counted(n, "file", "files")));
                                format!("{} {n}", data(&format!("{}/", x.path_text)))
                            }
                            false => data(&x.path_text),
                        };
                        facts.push((label, shown));
                    }
                }
                (None, None) => {
                    if let Some(b) = f.rests_on.iter().rev().find(|b| {
                        b.entry == "changed" && b.predicate.as_deref() == Some("has_digest")
                    }) {
                        facts.push((
                            "Digest before",
                            data(b.old_value_text.as_deref().unwrap_or("not known")),
                        ));
                        facts.push((
                            "Digest after",
                            data(b.new_value_text.as_deref().unwrap_or("not known")),
                        ));
                    }
                }
            }
        }
        Some(Body::IndicatorMatched(p)) => {
            if let Some(value) = &p.indicators_text {
                facts.push(("Matched", data(value)));
            }
            if let Some(port) = p.port {
                facts.push(("Port", data(&port.to_string())));
            }
            if let Some(transport) = &p.transport {
                facts.push(("Transport", word(transport)));
            }
            if let Some(p) = &p.process {
                process_facts(p, facts, now);
            }
        }
        Some(Body::DetachedProcess(p)) => process_facts(p, facts, now),
        Some(Body::VulnerablePackage(p)) => {
            if let Some(why) = p.no_longer_found {
                let said = crate::finding_text::no_longer_found_said(why);
                let as_then = crate::finding_text::as_then(p);
                facts.push(("No longer found", word(&format!("{said}{as_then}"))));
                if let Some(at) = p.no_longer_found_at {
                    facts.push(("Since", view::when(at, now)));
                }
            }
            if let Some(name) = &p.package_text {
                facts.push(("Package", data(name)));
            }
            for r in &p.releases {
                facts.push(("Version", data(&r.version_text)));
                facts.push(("Declared at", data(&r.at_text)));
            }
            for r in &p.records {
                facts.push(("Record", data(&r.id_text)));
                if !r.fixed_text.is_empty() {
                    facts.push(("Fixed in", data(&r.fixed_text.join(", "))));
                }
                voices.push(Voice {
                    name: esc(&r.source),
                    said: r.summary_text.as_deref().map_or(String::new(), data),
                    detail: String::new(),
                    quote: None,
                });
            }
        }
        Some(Body::PublishedRuleMatched(p)) => {
            let rule = p.rule.clone().unwrap_or_default();
            if let Some(n) = p.matches {
                facts.push(("Matched", word(&counted(n as i64, "time", "times"))));
            }
            for (i, e) in p.events.iter().enumerate() {
                // Beside the latest, the first is the event that raised the finding.
                if i == 0 && p.events.len() > crate::events::EVIDENCE {
                    facts.push(("Raised by", "the event below".to_string()));
                }
                facts.extend(event_facts(e, now));
            }
            voices.push(Voice {
                name: format!("Published rule · {}", esc(&rule.set)),
                said: format!("<span class=\"src\">{}</span>", esc(&rule.title_text)),
                detail: if rule.level == v1::Level::NotStated as i32 {
                    String::new()
                } else {
                    format!(
                        "its authors rate it {}",
                        esc(&crate::text::word::<v1::Level>(rule.level))
                    )
                },
                quote: None,
            });
        }
        Some(Body::VerdictGiven(v)) => {
            facts.push(("About the rule", data(&v.rule)));
            for e in &v.events {
                facts.extend(event_facts(e, now));
            }
        }
        None => {}
    }
    if let Some(v) = &f.verdicts {
        for listed in &v.listed {
            let verdict = listed.verdict.clone().unwrap_or_default();
            let mut said = capital(&crate::text::word::<v1::VerdictKind>(verdict.kind));
            if let Some(c) = verdict.confidence {
                let _ = write!(said, ", how sure: {}", crate::text::word::<v1::Level>(c));
            }
            if listed.event_gone {
                said.push_str(
                    ". Its event was no longer in the log, so Immunity Core could not check that the rule matched it",
                );
            }
            voices.push(Voice {
                name: "Response layer".to_string(),
                said: esc(&said),
                detail: view::when(listed.recorded_at, now),
                quote: Some(verdict.reason_text.clone()),
            });
        }
    }
    // The earlier occurrence by its id, answered or not; the person's answer, then its answer.
    let earlier = (f.earlier.as_ref()).and_then(|e| Some((e.answer.as_ref(), e.finding.as_ref()?)));
    if let Some((_, r)) = earlier {
        facts.push(("Earlier", esc(&r.id)));
    }
    let then = earlier.and_then(|(a, r)| Some((a?, r)));
    let answers = f.answer.as_ref().map(|a| (a, None));
    for (a, before) in answers.into_iter().chain(then.map(|(a, r)| (a, Some(r)))) {
        let said = match a.until_at {
            Some(u) => format!("Expected until {}", view::when(u, now)),
            None => "Seen".to_string(),
        };
        let name = match v1::Via::try_from(a.via) {
            Ok(v1::Via::Agent) => "Your agent",
            _ => "Your answer",
        };
        voices.push(Voice {
            name: match before {
                Some(r) => format!("{name} before, to {}", esc(&r.id)),
                None => name.to_string(),
            },
            said,
            detail: format!(
                "answered {} {}",
                view::when(a.given_at, now),
                esc(crate::finding_text::given_by(a.via))
            ),
            quote: a.reason_text.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_prints_names_and_what_a_source_said_as_text_cut_and_its_command_escaped_beside_the_copy_button()
     {
        // A file on the Mac may have been written for a person or an agent to read. Its name,
        // the thing's id and what a source said reach the page through the printer alone: a tag
        // is shown as text, a character that reorders text is written out, a secret is cut,
        // and the command an agent reads stays one escaped command with the fixed button after
        // it.
        let secret = ["invented", "-pass", "-word"].concat();
        let listed = v1::ListedFinding {
            finding: Some(v1::FindingRef {
                id: "<b>\"x".to_string(),
                rule: Some("watched.shell-profile".to_string()),
                about_text: "<i>about".to_string(),
                state: v1::FindingState::Open as i32,
                ..Default::default()
            }),
            kind_title: "Shell startup file".to_string(),
            where_text: "~/<img src=x>\u{202e}".to_string(),
            first_seen_at: 1,
            last_seen_at: 1,
            ..Default::default()
        };
        let whole = v1::Finding {
            title: "Invented title".to_string(),
            value_text: Some(format!("<script>said</script> --password={secret}")),
            ..Default::default()
        };
        let answers = Answers {
            findings: v1::Findings {
                findings: vec![listed],
                ..Default::default()
            },
            finding: Box::new(move |_| Ok(Some(whole.clone()))),
            rules: v1::Rules::default(),
        };
        let mut out = String::new();
        table(&mut out, &answers, 0).unwrap();
        for raw in ["<b>", "<i>", "<img", "<script", "\u{202e}", secret.as_str()] {
            assert!(!out.contains(raw), "{raw}: {out}");
        }
        assert!(
            out.contains(
                "<span class=\"fw\"><bdi class=\"src\">~/&lt;img src=x&gt;\\u{202e}</bdi></span>"
            ),
            "{out}"
        );
        assert!(
            out.contains("<span class=\"said\"><bdi class=\"src\">&lt;script&gt;said&lt;/script&gt; --password=\\cut{"),
            "{out}"
        );
        let line = &out[out.find("<div class=\"fxb\">").unwrap()..];
        assert!(
            line.contains(&format!(
                "For your agent <span class=\"cmd\"><span class=\"mono\">immunity finding &lt;b&gt;&quot;x --json</span>{COPY}</span></span>"
            )),
            "{line}"
        );
    }

    #[test]
    fn every_finding_is_in_one_row_whatever_its_state_or_rule_and_what_the_cut_leaves_out_is_counted_in_findings()
     {
        // No finding is folded out of sight: one in a state this build does not know is open,
        // and the response layer's finding about its own finding is a row of its own. What the
        // cut leaves out is told in findings as the tabs count them, a pair two.
        let listed = |id: &str, rule: &str, about: &str, state: i32| v1::ListedFinding {
            finding: Some(v1::FindingRef {
                id: id.to_string(),
                rule: Some(rule.to_string()),
                about_text: about.to_string(),
                state,
                ..Default::default()
            }),
            ..Default::default()
        };
        let open = v1::FindingState::Open as i32;
        let mut all: Vec<v1::ListedFinding> = (0..ITEMS_SHOWN)
            .map(|n| {
                listed(
                    &format!("f{n}"),
                    "watched.shell-profile",
                    &format!("a{n}"),
                    99,
                )
            })
            .collect();
        all.push(listed("core", "sigma:x", "thing", open));
        all.push(listed("own", crate::verdict::RULE, "thing", open));
        all.push(listed("self", crate::verdict::RULE, "self", open));
        let about = |rule: &str| v1::Finding {
            evidence: Some(v1::Evidence {
                body: Some(v1::evidence::Body::VerdictGiven(v1::VerdictGiven {
                    rule: rule.to_string(),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        };
        let answers = Answers {
            findings: v1::Findings {
                findings: all,
                ..Default::default()
            },
            finding: Box::new(move |id| {
                Ok(match id {
                    "own" => Some(about("sigma:x")),
                    "self" => Some(about(crate::verdict::RULE)),
                    _ => None,
                })
            }),
            rules: v1::Rules::default(),
        };
        let mut out = String::new();
        table(&mut out, &answers, 0).unwrap();
        let tab = format!("Open <span class=\"tn\">{}</span>", ITEMS_SHOWN + 3);
        assert!(out.contains(&tab), "{out}");
        assert!(out.contains(">3 more, the mildest;"), "{out}");
    }

    #[test]
    fn a_package_no_longer_found_says_why_first_and_its_kept_names_stay_escaped() {
        let f = v1::Finding {
            evidence: Some(v1::Evidence {
                body: Some(v1::evidence::Body::VulnerablePackage(
                    v1::VulnerablePackage {
                        package_text: Some("<b>left-pad".to_string()),
                        no_longer_found: Some(v1::NoLongerFound::ProjectGone as i32),
                        no_longer_found_at: Some(1_800_000_000 - 3600),
                        ..Default::default()
                    },
                )),
            }),
            ..Default::default()
        };
        let (mut facts, mut voices) = (Vec::new(), Vec::new());
        evidence(&f, &mut facts, &mut voices, 1_800_000_000);
        let names: Vec<&str> = facts.iter().map(|(k, _)| *k).collect();
        assert_eq!(names, ["No longer found", "Since", "Package"]);
        assert!(
            facts[0]
                .1
                .contains("the project is no longer on this Mac; what follows")
        );
        assert!(facts[2].1.contains("&lt;b&gt;left-pad") && !facts[2].1.contains("<b>"));
    }

    #[test]
    fn a_finding_with_two_signer_entries_says_the_latest_entry_s_two_values_with_its_time_and_nothing_of_the_first()
     {
        let (now, first, latest) = (1_800_000_000, 1_800_000_000 - 7200, 1_800_000_000 - 3600);
        let signed = |at: i64, old: &str, new: &str| v1::JournalEntry {
            recorded_at: at,
            entry: "changed".to_string(),
            predicate: Some("signed_by".to_string()),
            old_value_text: Some(old.to_string()),
            new_value_text: Some(new.to_string()),
            ..Default::default()
        };
        let f = v1::Finding {
            answered_at: now,
            evidence: Some(v1::Evidence {
                body: Some(v1::evidence::Body::PlaceChanged(v1::PlaceChanged {
                    change: v1::Change::Changed as i32,
                    ..Default::default()
                })),
            }),
            rests_on: vec![
                signed(first, "apple", "first signer"),
                signed(latest, "second before", "second after"),
            ],
            ..Default::default()
        };
        let text = crate::finding_text::finding(&f, &crate::screen::Screen::pipe());
        for line in [
            format!(
                "    Signer       until the reading of {}: \"second before\"\n",
                view::utc(latest)
            ),
            format!(
                "                 from the reading of {}: \"second after\"\n",
                view::utc(latest)
            ),
        ] {
            assert!(text.contains(&line), "{line}\n{text}");
        }
        let (mut facts, mut voices) = (Vec::new(), Vec::new());
        evidence(&f, &mut facts, &mut voices, now);
        let signers: Vec<(&str, String)> = (facts.iter())
            .filter(|(k, _)| k.starts_with("Signer"))
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let at = view::when(latest, now);
        assert_eq!(
            signers,
            [
                (
                    "Signer before",
                    format!(
                        "{} <span class=\"w\">until the reading of</span> {at}",
                        data("second before")
                    )
                ),
                (
                    "Signer after",
                    format!(
                        "{} <span class=\"w\">from the reading of</span> {at}",
                        data("second after")
                    )
                ),
            ]
        );
        for page_or_text in [text, format!("{signers:?}")] {
            assert!(!page_or_text.contains("first signer") && !page_or_text.contains("apple"));
            assert!(!page_or_text.contains(&view::utc(first)));
        }
    }

    #[test]
    fn a_published_rule_s_event_that_raised_its_finding_is_named_so_only_beside_the_latest() {
        // The message holds the event that raised the finding first only when it holds more
        // than the latest: then, and only then, the page says which it is.
        let raised = |n: usize| {
            let start = v1::Event {
                body: Some(v1::event::Body::ProgramStart(v1::ProgramStart::default())),
            };
            let f = v1::Finding {
                evidence: Some(v1::Evidence {
                    body: Some(v1::evidence::Body::PublishedRuleMatched(
                        v1::PublishedRuleMatched {
                            events: vec![start; n],
                            ..Default::default()
                        },
                    )),
                }),
                ..Default::default()
            };
            let (mut facts, mut voices) = (Vec::new(), Vec::new());
            evidence(&f, &mut facts, &mut voices, 0);
            facts.iter().position(|(k, _)| *k == "Raised by")
        };
        assert_eq!(raised(crate::events::EVIDENCE), None);
        assert_eq!(raised(crate::events::EVIDENCE + 1), Some(0));
    }
}
