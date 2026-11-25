//! The last section of the summary: what this version does not read here. Every limit the status
//! holds is told in it once, and nowhere else on the pages, in one section that starts
//! collapsed. A limit is a thing not covered that the message does not mark a fault
//! (`Uncovered.fault`, taken by `pages::sorted`); this file decides nothing of that, and its
//! words are the catalogue's (`covered.rs`). Every name and what a source said goes through the
//! page's own escaping (`pages::apart`), as on every page.

use crate::covered::{Uncovered, YOU};
use crate::view::{Out, counted, esc};
use std::fmt::Write;

/// The section's anchor.
pub const ANCHOR: &str = "not-read-here";

/// The groups the limits are told in, by the status's scope of each (`covered::SCOPES`). One of a
/// scope not named here is told on this Mac, so none is left out.
const GROUPS: [(&str, &str); 4] = [
    ("On this Mac", "this_mac"),
    ("In your projects", "projects"),
    ("Beyond this Mac", "servers"),
    (crate::pages::THREAT_DATA_TITLE, "threats"),
];

/// The section, when the status holds a limit: its title with how many, then one line for each
/// limit in the order of the status, grouped by where it holds.
pub fn section(out: &mut String, limits: &[&Uncovered]) -> Out {
    if limits.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "<section id=\"{ANCHOR}\">\n<details>\n<summary class=\"wsh\"><h2>What this version does not read here</h2><span class=\"n\">{}</span></summary>",
        esc(&counted(limits.len() as i64, "thing", "things"))
    )?;
    let group = |u: &Uncovered| (GROUPS.iter().position(|(_, s)| *s == u.scope)).unwrap_or(0);
    for (i, (title, _)) in GROUPS.iter().enumerate() {
        let list: Vec<&Uncovered> = (limits.iter().copied()).filter(|u| group(u) == i).collect();
        if list.is_empty() {
            continue;
        }
        writeln!(
            out,
            "<p class=\"wg\">{}</p>\n<ul class=\"limits\">",
            esc(title)
        )?;
        for u in list {
            line(out, u)?;
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</details>\n</section>\n");
    Ok(())
}

/// One limit: its title, the things it names with what their source said, as data, and what the
/// person can do where the person can do something.
fn line(out: &mut String, u: &Uncovered) -> Out {
    write!(out, "<li id=\"{}\">{}", esc(u.cause.id), esc(&u.title()))?;
    let apart = crate::pages::apart(u);
    let shown = apart.len().min(crate::pages::EXAMPLES_SHOWN);
    if shown > 0 {
        write!(
            out,
            " <span class=\"mono\">{}</span>",
            apart[..shown].join("; ")
        )?;
    }
    if apart.len() > shown {
        write!(
            out,
            " <span class=\"muted\">and {} more</span>",
            apart.len() - shown
        )?;
    }
    if u.cause.who == YOU {
        write!(out, "<span class=\"advice\">{}</span>", esc(u.cause.advice))?;
    }
    out.push_str("</li>\n");
    Ok(())
}
