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

fn body(out: &mut String, r: &v1::Status) -> Out {
    out.push_str("<section id=\"coverage\">\n<p class=\"muted\">What the other pages say is only as good as this.</p>\n");
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
    let not_full = c.partial + c.none;
    if not_full == 0 {
        out.push_str("<p class=\"ok\">Every reading was full at its latest run.</p>\n");
    } else {
        writeln!(
            out,
            "<p class=\"alert\">{} of {} were not full at their latest run. What they cover may be out of date or missing.</p>",
            grouped(not_full as i64),
            counted(c.readings as i64, "reading", "readings"),
        )?;
    }
    if c.partial > 0 {
        writeln!(
            out,
            "<p class=\"alert\">{} of them {} partial: what they saw was added, but what disappeared there cannot be seen. Removals there are unknown.</p>",
            grouped(c.partial as i64),
            if c.partial == 1 { "was" } else { "were" }
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
            cell(out, "mono", &examples.join(", "))?;
            cell(out, "", &reason(g.reason_text.as_deref()))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    if hidden > 0 {
        // The readings of the groups not listed: those of every class, less those listed.
        let all = c.failed + c.no_reader + c.not_given + c.read_nothing;
        let listed: u64 = c.problems.iter().map(|g| g.count).sum();
        writeln!(
            out,
            "<p class=\"alert\">{} of readings, {} among them, {} not listed here.</p>",
            counted(hidden as i64, "more group", "more groups"),
            counted(all.saturating_sub(listed) as i64, "reading", "readings"),
            if hidden == 1 { "is" } else { "are" }
        )?;
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

    #[test]
    fn a_page_says_every_reading_was_full_only_when_none_was_partial_or_read_nothing() {
        // False calm: "every reading was full" over a reading that was partial or failed.
        let full = v1::CoverageSummary {
            readings: 3,
            full: 3,
            ..Default::default()
        };
        let said = |c: v1::CoverageSummary| {
            page(
                &v1::Status {
                    coverage: Some(c),
                    ..Default::default()
                },
                1_800_000_000,
            )
        };
        assert!(said(full.clone()).contains("Every reading was full"));
        for c in [
            v1::CoverageSummary {
                partial: 1,
                ..full.clone()
            },
            v1::CoverageSummary {
                none: 1,
                ..full.clone()
            },
        ] {
            let page = said(c);
            assert!(
                !page.contains("Every reading was full")
                    && page.contains("1 of 3 readings were not full"),
                "{page}"
            );
        }
        // No summary at all is not known, never calm.
        let none = page(&v1::Status::default(), 1_800_000_000);
        assert!(
            !none.contains("Every reading was full") && none.contains("is not known"),
            "{none}"
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
