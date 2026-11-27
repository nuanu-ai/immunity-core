//! The page of what was read and how completely, drawn from the coverage summary the status gives
//! (`CoverageSummary`, what `immunity status --coverage` prints): how many readings there were at
//! their latest run and how many were full, the machines that could not be reached, and the
//! readings that were not full, in groups of one class, reader, kind and reason; a reading that
//! had nothing to read is full, and is counted and not listed, as `--coverage` lists it. A person
//! looks here for what was not read, so nothing unread goes quiet: where the message holds fewer
//! machines or groups than there are, the page says how many more, from the message's own counts.
//! Names and reasons are printed through `secrets::Name` and `secrets::Said`.

use super::{COVERAGE_TITLE, grouped, top};
use crate::contract::v1;
use crate::secrets::{Name, Said};
use crate::view::{FOOT, Out, cell, counted, esc, thead, utc, utc_or};
use std::fmt::Write;

/// The page, from the status alone.
pub fn page(r: &v1::Status, now: i64) -> String {
    let checked_at = r.this_mac.as_ref().and_then(|m| m.checked_at);
    let mut out = top(
        COVERAGE_TITLE,
        &format!(
            "Last full check {} · this page made {}",
            utc_or(checked_at, "never"),
            utc(now)
        ),
    );
    let _ = body(&mut out, r);
    out.push_str(FOOT);
    out
}

/// A class of readings as a person reads it. One this build does not know is read as failed, as
/// the schema says.
fn class_words(class: i32) -> &'static str {
    match v1::ReadingClass::try_from(class) {
        Ok(v1::ReadingClass::NoReader) => "no reader in this version",
        Ok(v1::ReadingClass::NotGiven) => "not given by its source",
        Ok(v1::ReadingClass::ReadNothing) => "nothing to read",
        _ => "failed",
    }
}

/// Whether the page may say that every reading was full. All of these hold: a full check has
/// finished; the summary counts at least one reading and every one is full without a note; no
/// machine could not be reached and no reading is implied by one; no group of readings is
/// listed or counted; and the latest finished check made again every reading an earlier one
/// made. Anything else, an empty summary or a class this build does not know among them, is
/// never calm.
fn all_full(r: &v1::Status, c: &v1::CoverageSummary) -> bool {
    let checked = r.this_mac.as_ref().is_some_and(|m| m.checked_at.is_some());
    checked
        && c.readings > 0
        && c.full == c.readings
        && c.unreached_total == 0
        && c.unreached.is_empty()
        && c.implied_by_unreached == 0
        && c.problems.is_empty()
        && c.problems_total == 0
        && not_repeated(r) == 0
}

/// How many readings an earlier check made that the latest finished one did not make again.
fn not_repeated(r: &v1::Status) -> u64 {
    (r.last_finished_run.as_ref())
        .and_then(|f| f.readings.as_ref())
        .map_or(0, |x| x.not_repeated)
}

fn body(out: &mut String, r: &v1::Status) -> Out {
    out.push_str("<section id=\"coverage\">\n<p class=\"muted\">What the other pages say is only as good as this.</p>\n");
    if r.running {
        out.push_str("<p class=\"alert\">A check is running now. This page shows what was read before it.</p>\n");
    }
    // A check that died: nothing it read is in the store, whatever the readings below say.
    if let Some(at) = (r.last_run.as_ref())
        .filter(|l| l.finished_at.is_none() && !r.running)
        .map(|l| l.started_at)
    {
        writeln!(
            out,
            "<p class=\"alert\">The latest check started {} and never finished. Nothing it read is in the store.</p>",
            utc(at)
        )?;
    }
    let Some(c) = &r.coverage else {
        // Why the status gives none, in its own words.
        let why = (r.not_computed.iter())
            .find(|n| n.section == "coverage")
            .map_or("the status gives no account of it", |n| n.reason.as_str());
        writeln!(
            out,
            "<p class=\"alert\">What was read is not known: {}.</p>\n</section>",
            esc(why)
        )?;
        return Ok(());
    };
    writeln!(
        out,
        "<p>{} at their latest run: {} full, {} partial and {} that read nothing. Of those not plainly full, {} failed, {} have no reader in this version, {} were not given by their source, {} had nothing to read, and {} failed on {}.</p>",
        counted(c.readings as i64, "reading", "readings"),
        grouped(c.full as i64),
        grouped(c.partial as i64),
        grouped(c.none as i64),
        grouped(c.failed as i64),
        grouped(c.no_reader as i64),
        grouped(c.not_given as i64),
        grouped(c.read_nothing as i64),
        grouped(c.implied_by_unreached as i64),
        counted(
            c.unreached_total as i64,
            "machine that could not be reached",
            "machines that could not be reached"
        ),
    )?;
    let checked = r.this_mac.as_ref().is_some_and(|m| m.checked_at.is_some());
    if all_full(r, c) {
        out.push_str("<p class=\"ok\">Every reading was full at its latest run.</p>\n");
    } else if !checked {
        out.push_str(
            "<p class=\"alert\">No full check has finished, so what was read is not known.</p>\n",
        );
    } else if c.readings == 0 {
        out.push_str(
            "<p class=\"alert\">The status counts no reading, so what was read is not known.</p>\n",
        );
    } else if c.full < c.readings {
        writeln!(
            out,
            "<p class=\"alert\">{} of {} were not plainly full at their latest run. What they cover may be out of date or missing.</p>",
            grouped((c.readings - c.full) as i64),
            counted(c.readings as i64, "reading", "readings"),
        )?;
    } else {
        out.push_str("<p class=\"alert\">Not every reading is known to be full and current.</p>\n");
    }
    if c.partial > 0 {
        writeln!(
            out,
            "<p class=\"alert\">{} of them {} partial: what they saw was added, but what disappeared there cannot be seen. Removals there are unknown.</p>",
            grouped(c.partial as i64),
            if c.partial == 1 { "was" } else { "were" }
        )?;
    }
    let stale = not_repeated(r);
    if stale > 0 {
        writeln!(
            out,
            "<p class=\"alert\">The latest finished check did not read again all that earlier checks read: {}, and what they hold may be out of date.</p>",
            esc(&crate::overview::not_repeated(stale))
        )?;
    }
    unreached(out, c)?;
    groups(out, c)?;
    out.push_str("</section>\n");
    Ok(())
}

/// The machines whose latest visit failed, each with when its visits began to fail and why, and
/// how many more there are than the message lists.
fn unreached(out: &mut String, c: &v1::CoverageSummary) -> Out {
    if c.unreached_total == 0 && c.unreached.is_empty() {
        return Ok(());
    }
    out.push_str("<h2>Machines that could not be reached</h2>\n");
    if !c.unreached.is_empty() {
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        thead(out, &["Machine", "Failing since", "Why"]);
        for u in &c.unreached {
            out.push_str("<tr class=\"bad\">");
            cell(out, "mono", &Name::given(&u.scope_text).html())?;
            cell(out, "nowrap", &esc(&utc(u.since_at)))?;
            cell(out, "", &reason(u.reason_text.as_deref()))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    let more = c.unreached_total.saturating_sub(c.unreached.len() as u64);
    if more > 0 {
        writeln!(
            out,
            "<p class=\"alert\">{} could not be reached and {} not listed here.</p>",
            counted(more as i64, "more machine", "more machines"),
            if more == 1 { "is" } else { "are" }
        )?;
    }
    Ok(())
}

/// The readings that were not full, a row for each group of one class, reader, kind and reason:
/// how many readings, the places the message gives as examples and how many more, and why. Then
/// how many groups, and how many readings in them, the message does not list.
fn groups(out: &mut String, c: &v1::CoverageSummary) -> Out {
    let nothing = v1::ReadingClass::ReadNothing as i32;
    let rows: Vec<&v1::ReadingGroup> = c.problems.iter().filter(|g| g.class != nothing).collect();
    let hidden = c.problems_total.saturating_sub(c.problems.len() as u64);
    if rows.is_empty() && hidden == 0 {
        return Ok(());
    }
    out.push_str("<h2>Readings that were not full</h2>\n");
    if !rows.is_empty() {
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        thead(
            out,
            &["Class", "Reader", "What", "Readings", "For example", "Why"],
        );
        for g in rows {
            let failed = class_words(g.class) == "failed";
            out.push_str(if failed { "<tr class=\"bad\">" } else { "<tr>" });
            cell(out, "", &esc(class_words(g.class)))?;
            cell(out, "", &esc(&g.reader))?;
            cell(out, "", &esc(&g.kind))?;
            cell(out, "num", &grouped(g.count as i64))?;
            let mut examples: Vec<String> = (g.examples_text.iter())
                .map(|e| Name::given(e).html())
                .collect();
            let more = g.count.saturating_sub(g.examples_text.len() as u64);
            if more > 0 && !examples.is_empty() {
                examples.push(format!("and {} more", grouped(more as i64)));
            }
            match examples.is_empty() {
                true => cell(out, "", "the status names no place")?,
                false => cell(out, "mono", &examples.join(", "))?,
            }
            cell(out, "", &reason(g.reason_text.as_deref()))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    if hidden > 0 {
        // The readings of the groups not listed: those of every class, less those listed. When
        // the counts leave none for them, they disagree, and how many there are is not said.
        let all = c.failed + c.no_reader + c.not_given + c.read_nothing;
        let listed: u64 = c.problems.iter().map(|g| g.count).sum();
        let groups = counted(hidden as i64, "more group", "more groups");
        let verb = if hidden == 1 { "is" } else { "are" };
        match all > listed {
            true => writeln!(
                out,
                "<p class=\"alert\">{groups} of readings, {} among them, {verb} not listed here.</p>",
                counted((all - listed) as i64, "reading", "readings"),
            )?,
            false => writeln!(
                out,
                "<p class=\"alert\">{groups} of readings {verb} not listed here, and how many readings they hold is not known.</p>",
            )?,
        }
    }
    Ok(())
}

/// Why, as the message gives it, cut by its builder; or that it gives none.
fn reason(said: Option<&str>) -> String {
    said.map_or("no reason given".to_string(), |r| Said::given(r).html())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A summary whose message lists `listed` of `total` groups, each of two readings of which
    /// one is an example, and `machines` of `away` machines that could not be reached.
    fn summary(listed: u64, total: u64, machines: u64, away: u64) -> v1::Status {
        let group = |i: u64| v1::ReadingGroup {
            class: v1::ReadingClass::Failed as i32,
            reader: "invented".to_string(),
            kind: format!("invented kind {i}"),
            reason_text: Some(format!("invented reason {i}")),
            count: 2,
            examples_text: vec![format!("machine:mac/place-{i}")],
        };
        let machine = |i: u64| v1::Unreached {
            scope_text: format!("machine:server-{i}"),
            since_at: 1_800_000_000,
            reason_text: None,
        };
        v1::Status {
            coverage: Some(v1::CoverageSummary {
                readings: 2 * total + 10,
                full: 10,
                none: 2 * total,
                failed: 2 * total,
                problems: (0..listed).map(group).collect(),
                problems_total: total,
                unreached: (0..machines).map(machine).collect(),
                unreached_total: away,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn what_the_message_does_not_list_is_counted_on_the_page_and_never_dropped() {
        // A person looks here for what was not read: a group or a machine the message holds no
        // row for is still counted, with the readings in the groups left out.
        let mut status = summary(2, 5, 1, 4);
        // A group that had nothing to read is full: counted, never a row.
        if let Some(c) = status.coverage.as_mut() {
            c.problems.push(v1::ReadingGroup {
                class: v1::ReadingClass::ReadNothing as i32,
                kind: "invented empty kind".to_string(),
                count: 1,
                ..Default::default()
            });
            c.problems_total += 1;
            c.read_nothing += 1;
            // A group whose every reading is an example names no more.
            c.problems.push(v1::ReadingGroup {
                class: v1::ReadingClass::Failed as i32,
                kind: "invented single kind".to_string(),
                count: 1,
                examples_text: vec!["machine:mac/single".to_string()],
                ..Default::default()
            });
            (c.problems_total, c.failed) = (c.problems_total + 1, c.failed + 1);
        }
        let page = page(&status, 1_800_000_100);
        assert!(!page.contains("invented empty kind"), "{page}");
        assert!(
            page.contains("<bdi class=\"src\">machine:mac/single</bdi></td>")
                && !page.contains("and 0 more"),
            "{page}"
        );
        // A reading that failed is marked as one.
        assert!(page.contains("<tr class=\"bad\"><td>failed</td>"), "{page}");
        assert!(
            page.contains("3 more groups of readings, 6 readings among them, are not listed here."),
            "{page}"
        );
        assert!(
            page.contains("3 more machines could not be reached and are not listed here."),
            "{page}"
        );
        // Each group listed: its examples through the printer, how many more, and why.
        assert!(
            page.contains("<bdi class=\"src\">machine:mac/place-1</bdi>, and 1 more")
                && page.contains("<bdi class=\"src\">invented reason 1</bdi>")
                && page.contains("<bdi class=\"src\">machine:server-0</bdi>"),
            "{page}"
        );
        assert!(!page.contains("Every reading was full"), "{page}");
        // A message that lists every group and machine says nothing of more.
        let whole = super::page(&summary(5, 5, 4, 4), 1_800_000_100);
        assert!(!whole.contains("not listed here"), "{whole}");
    }

    /// A status after a full check whose three readings were all full, and nothing else.
    fn calm() -> v1::Status {
        v1::Status {
            this_mac: Some(v1::ThisMac {
                checked_at: Some(1_800_000_000),
                ..Default::default()
            }),
            coverage: Some(v1::CoverageSummary {
                readings: 3,
                full: 3,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    const FULL: &str = "Every reading was full";

    #[test]
    fn a_page_says_every_reading_was_full_only_when_nothing_at_all_says_otherwise() {
        // False calm: the green line beside a reading, a machine, a group or a check that says
        // something was not read, or with nothing to rest on.
        let said = |change: &dyn Fn(&mut v1::Status)| {
            let mut r = calm();
            change(&mut r);
            page(&r, 1_800_000_100)
        };
        fn c(r: &mut v1::Status) -> &mut v1::CoverageSummary {
            r.coverage.as_mut().unwrap()
        }
        assert!(said(&|_| {}).contains(FULL));
        let failed = v1::ReadingGroup {
            class: v1::ReadingClass::Failed as i32,
            count: 1,
            ..Default::default()
        };
        type Change<'a> = &'a dyn Fn(&mut v1::Status);
        let cases: [(&str, Change); 11] = [
            ("not plainly full", &|r| c(r).full = 2),
            ("a group listed", &|r| c(r).problems = vec![failed.clone()]),
            ("a group counted", &|r| c(r).problems_total = 1),
            ("an unknown class", &|r| {
                c(r).problems = vec![v1::ReadingGroup {
                    class: 99,
                    ..failed.clone()
                }]
            }),
            ("a machine counted", &|r| c(r).unreached_total = 1),
            ("a machine listed", &|r| {
                c(r).unreached = vec![v1::Unreached::default()]
            }),
            ("an implied reading", &|r| c(r).implied_by_unreached = 1),
            ("no reading", &|r| (c(r).readings, c(r).full) = (0, 0)),
            ("no full check", &|r| r.this_mac = None),
            ("a check without a time", &|r| {
                r.this_mac.as_mut().unwrap().checked_at = None
            }),
            ("readings not repeated", &|r| {
                r.last_finished_run = Some(v1::FinishedCheck {
                    readings: Some(v1::CheckReadings {
                        not_repeated: 2,
                        ..Default::default()
                    }),
                    ..Default::default()
                })
            }),
        ];
        for (case, change) in cases {
            let page = said(change);
            assert!(!page.contains(FULL), "{case}: {page}");
        }
        // What each says instead.
        assert!(said(&|r| c(r).full = 2).contains("1 of 3 readings were not plainly full"));
        assert!(
            said(&|r| r.this_mac = None)
                .contains("No full check has finished, so what was read is not known.")
        );
        assert!(
            said(&|r| (c(r).readings, c(r).full) = (0, 0))
                .contains("The status counts no reading, so what was read is not known.")
        );
        assert!(
            said(&|r| c(r).implied_by_unreached = 1)
                .contains("Not every reading is known to be full and current.")
        );
        let unknown = said(&|r| {
            c(r).problems = vec![v1::ReadingGroup {
                class: 99,
                ..failed.clone()
            }]
        });
        assert!(
            unknown.contains("<tr class=\"bad\"><td>failed</td>"),
            "{unknown}"
        );
        let stale = said(cases[10].1);
        assert!(
            stale.contains("did not read again all that earlier checks read: 2 earlier readings were not repeated,"),
            "{stale}"
        );
        // No summary at all is not known, never calm.
        let none = page(&v1::Status::default(), 1_800_000_000);
        assert!(
            !none.contains(FULL) && none.contains("is not known"),
            "{none}"
        );
    }

    #[test]
    fn a_running_check_is_said_above_what_was_read_before_it() {
        // The numbers are those of what is stored; a check running now may change them.
        let mut r = calm();
        r.running = true;
        let page = page(&r, 1_800_000_100);
        let running = page.find("A check is running now. This page shows what was read before it.");
        assert!(
            running.is_some_and(|at| page.find(FULL).is_some_and(|full| at < full)),
            "{page}"
        );
        assert!(!super::page(&calm(), 1_800_000_100).contains("is running now"));
    }

    #[test]
    fn a_hidden_group_is_never_said_to_hold_no_reading_and_a_group_with_no_place_says_so() {
        // The message's counts disagree when the groups it lists hold as many readings as the
        // classes count: the page then says the hidden groups' readings are not known.
        let mut r = summary(5, 6, 0, 0);
        if let Some(c) = r.coverage.as_mut() {
            c.failed = 10;
            c.problems[0].examples_text.clear();
        }
        let page = page(&r, 1_800_000_100);
        assert!(
            page.contains("1 more group of readings is not listed here, and how many readings they hold is not known.")
                && !page.contains("0 readings"),
            "{page}"
        );
        assert!(
            page.contains("<td>the status names no place</td>"),
            "{page}"
        );
    }

    #[test]
    fn a_check_that_died_is_said_and_one_that_runs_or_finished_is_not() {
        // Nothing a check that died read is in the store, whatever its readings say.
        let said = |finished_at: Option<i64>, running: bool| {
            let last_run = Some(v1::CheckMark {
                started_at: 1_800_000_000,
                finished_at,
                ..Default::default()
            });
            let status = v1::Status {
                last_run,
                running,
                ..Default::default()
            };
            page(&status, 1_800_000_100).contains("never finished")
        };
        assert!(said(None, false));
        assert!(!said(None, true) && !said(Some(1_800_000_050), false));
    }
}
