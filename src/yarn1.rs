//! The grammar of `yarn.lock` as Yarn 1 writes it, which is Yarn's own and not YAML: a port of
//! Yarn's parser, `src/lockfile/parse.js` of github.com/yarnpkg/yarn at commit c2dda503. This is
//! our own code because no tested implementation of the grammar exists for Rust: the one crate
//! for it, `yarn-lock-parser`, skips what it does not understand without saying so, and the
//! lockfile library of a package manager that reads it, `aube-lockfile`, brings 19 crates. It is
//! tested on Yarn's own test file, `tests/yarn1/lockfile.js`.
//!
//! The tokens and the tree are Yarn's. Where Yarn repairs, guesses or falls back, this reader
//! refuses the file:
//! - an error of the grammar, where Yarn parses the file again as YAML;
//! - a key given twice at one level, where Yarn keeps the later value;
//! - a line indented deeper than its place, after which Yarn drops the rest of the file;
//! - all three merge-conflict markers in the text, where Yarn reads both sides and merges them;
//! - a carriage return not followed by a line feed, after which Yarn does not read the next
//!   line's spaces as indentation and a comment runs on to the next line feed;
//! - a lone surrogate in a quoted string's escapes, which `JSON.parse` takes and `serde_json`
//!   does not;
//! - a top-level key whose value is not a block, which Yarn takes as a pointer to another key:
//!   refused one layer up, where the tree becomes entries (`lockfiles::yarn1`).
//!
//! A comment `yarn lockfile v<N>` with N other than 1 stops the reading, as Yarn stops at a
//! later version; Yarn reads a version 0 on, and here it is a version without a reader.
//!
//! The tree is built without recursion and dropped without it, so the depth of an attacker's
//! indentation costs heap, never stack; every step consumes a token, so the work is linear in
//! the length of the text. Indexing is by `get`, or below a position already read.
//!
//! What would replace this reader: a tested implementation of this grammar that refuses what it
//! does not understand.

use std::collections::HashSet;

/// One key or several keys sharing one value, as Yarn writes `a@^1, a@^1.2:`.
pub struct Entry {
    pub keys: Vec<String>,
    pub value: Value,
}

/// A value as Yarn's tokens give it: a number is its digits as written. The lockfile reader
/// needs only text; the tests compare the others with Yarn's own trees.
pub enum Value {
    Text(String),
    #[allow(dead_code)]
    Number(String),
    #[allow(dead_code)]
    Bool(bool),
    Block(Vec<Entry>),
}

/// Drops a deep tree from a list of its own, not by recursion.
impl Drop for Value {
    fn drop(&mut self) {
        let Value::Block(entries) = self else { return };
        let mut stack = std::mem::take(entries);
        while let Some(mut entry) = stack.pop() {
            if let Value::Block(inner) = &mut entry.value {
                stack.append(inner);
            }
        }
    }
}

/// A file read by the grammar: the version a comment `yarn lockfile v<N>` names, if one does,
/// and the top level.
pub struct Lockfile {
    pub version: Option<String>,
    pub entries: Vec<Entry>,
}

enum Tok {
    Newline,
    Indent(usize),
    Text(String),
    Number(String),
    Bool(bool),
    Colon,
    Comma,
    Eof,
}

/// Tokens, each with the line it is on.
type Tokens = Vec<(Tok, usize)>;

/// Reads `text`. At a comment naming a version other than 1 it stops and gives that version
/// with no entries, since the rest may be in another grammar; Yarn 1 stops there too.
pub fn parse(text: &str) -> Result<Lockfile, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if ["<<<<<<<", "=======", ">>>>>>>"]
        .iter()
        .all(|m| text.contains(m))
    {
        return Err("it holds merge-conflict markers".to_string());
    }
    let (tokens, version) = tokens(text)?;
    if version.as_deref().is_some_and(|v| v != "1") {
        return Ok(Lockfile {
            version,
            entries: Vec::new(),
        });
    }
    Ok(Lockfile {
        version,
        entries: tree(&tokens)?,
    })
}

/// Yarn's `tokenise`, with each token's line; comments are read for a version and left out.
fn tokens(text: &str) -> Result<(Tokens, Option<String>), String> {
    let b = text.as_bytes();
    let (mut i, mut line, mut version) = (0, 1, None);
    let mut out = Vec::new();
    // Yarn reads spaces as indentation only right after `\n` or `\r\n`.
    let mut line_start = false;
    while let Some(&c) = b.get(i) {
        let start = i;
        let at = line;
        let tok = match c {
            b'\n' | b'\r' => {
                if c == b'\r' && b.get(i + 1) != Some(&b'\n') {
                    return Err(format!(
                        "line {line}: a carriage return not followed by a line feed"
                    ));
                }
                i += if c == b'\r' { 2 } else { 1 };
                line += 1;
                Some(Tok::Newline)
            }
            b'#' => {
                let end = b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(b.len(), |p| i + p);
                let raw = &text[i + 1..end];
                if raw.strip_suffix('\r').unwrap_or(raw).contains('\r') {
                    return Err(format!(
                        "line {line}: a carriage return not followed by a line feed"
                    ));
                }
                let comment = raw.trim();
                if let Some(n) = comment.strip_prefix("yarn lockfile v")
                    && !n.is_empty()
                    && n.bytes().all(|c| c.is_ascii_digit())
                {
                    version = Some(n.to_string());
                    if n != "1" {
                        return Ok((out, version));
                    }
                }
                i = end;
                None
            }
            b' ' if line_start => {
                let n = b[i..].iter().take_while(|&&c| c == b' ').count();
                if n % 2 == 1 {
                    return Err(format!("line {line}: an odd number of spaces"));
                }
                i += n;
                Some(Tok::Indent(n / 2))
            }
            b' ' => {
                i += 1;
                None
            }
            b'"' => {
                // Closed by the first `"` not escaped by exactly one backslash, at `j - 1`. The
                // character before it is at least the opening quote, at `start`, so a backslash
                // there is past `start` and `j - 3` is at least `start` too.
                let mut j = i + 1;
                while let Some(&q) = b.get(j) {
                    j += 1;
                    if q == b'"' && !(b[j - 2] == b'\\' && b[j - 3] != b'\\') {
                        break;
                    }
                }
                i = j;
                let decoded = serde_json::from_str::<String>(&text[start..j])
                    .map_err(|_| format!("line {line}: a quoted string that is not JSON"))?;
                Some(Tok::Text(decoded))
            }
            b'0'..=b'9' => {
                i += b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
                Some(Tok::Number(text[start..i].to_string()))
            }
            _ if b[i..].starts_with(b"true") => {
                i += 4;
                Some(Tok::Bool(true))
            }
            _ if b[i..].starts_with(b"false") => {
                i += 5;
                Some(Tok::Bool(false))
            }
            b':' => {
                i += 1;
                Some(Tok::Colon)
            }
            b',' => {
                i += 1;
                Some(Tok::Comma)
            }
            c if c.is_ascii_alphabetic() || matches!(c, b'/' | b'.' | b'-') => {
                i += b[i..]
                    .iter()
                    .take_while(|c| !matches!(c, b':' | b' ' | b'\n' | b'\r' | b','))
                    .count();
                Some(Tok::Text(text[start..i].to_string()))
            }
            _ => return Err(format!("line {line}: a character Yarn does not read here")),
        };
        line_start = c == b'\n' || c == b'\r';
        out.extend(tok.map(|t| (t, at)));
    }
    out.push((Tok::Eof, line));
    Ok((out, version))
}

/// One level of the tree being read: its entries and the keys it holds.
#[derive(Default)]
struct Level {
    entries: Vec<Entry>,
    seen: HashSet<String>,
}

/// Yarn's `Parser.parse`, with a stack of levels in place of its recursion. `open[k]` holds the
/// keys whose block is `levels[k + 1]`.
fn tree(tokens: &[(Tok, usize)]) -> Result<Vec<Entry>, String> {
    let end = (Tok::Eof, tokens.last().map_or(1, |t| t.1));
    let at = |i: usize| tokens.get(i).unwrap_or(&end);
    let (mut i, mut levels, mut open) = (0, vec![Level::default()], Vec::<Vec<String>>::new());
    loop {
        let indent = levels.len() - 1;
        let (tok, line) = at(i);
        let close = match tok {
            Tok::Newline => {
                i += 1;
                match at(i).0 {
                    _ if indent == 0 => false,
                    Tok::Indent(n) if n == indent => {
                        i += 1;
                        false
                    }
                    _ => true,
                }
            }
            Tok::Indent(n) if *n == indent => {
                i += 1;
                false
            }
            Tok::Indent(_) | Tok::Eof => true,
            Tok::Text(first) => {
                let mut keys = vec![first.clone()];
                i += 1;
                while let Tok::Comma = at(i).0 {
                    let Tok::Text(key) = &at(i + 1).0 else {
                        return Err(format!("line {}: a comma not followed by a key", at(i).1));
                    };
                    keys.push(key.clone());
                    i += 2;
                }
                let level = levels.last_mut().ok_or("no level")?;
                for key in &keys {
                    if key.is_empty() {
                        return Err(format!("line {line}: an empty key"));
                    }
                    if !level.seen.insert(key.clone()) {
                        return Err(format!("line {line}: the key {key:?} given twice"));
                    }
                }
                let colon = matches!(at(i).0, Tok::Colon);
                i += usize::from(colon);
                let value = match &at(i).0 {
                    Tok::Text(t) => Value::Text(t.clone()),
                    Tok::Number(n) => Value::Number(n.clone()),
                    Tok::Bool(b) => Value::Bool(*b),
                    _ if colon => {
                        open.push(keys);
                        levels.push(Level::default());
                        continue;
                    }
                    _ => return Err(format!("line {line}: a key with no value")),
                };
                level.entries.push(Entry { keys, value });
                i += 1;
                false
            }
            _ => return Err(format!("line {line}: a token Yarn does not read here")),
        };
        if !close {
            continue;
        }
        // Each closed block is its keys' value one level up; that level closes too when it is
        // not the top and the next token is not an indentation, as Yarn returns from both.
        loop {
            let done = levels.pop().ok_or("no level")?;
            let Some(keys) = open.pop() else {
                return match at(i) {
                    (Tok::Eof, _) => Ok(done.entries),
                    (_, line) => Err(format!(
                        "line {line}: a line indented deeper than its place"
                    )),
                };
            };
            let parent = levels.last_mut().ok_or("no level")?;
            parent.entries.push(Entry {
                keys,
                value: Value::Block(done.entries),
            });
            if levels.len() == 1 || matches!(at(i).0, Tok::Indent(_)) {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Entry, Value, parse};
    use serde_json::{Value as Json, json};

    /// The tree as Yarn's parser gives it: every key of an entry holds its value.
    fn json(entries: &[Entry]) -> Json {
        let mut object = serde_json::Map::new();
        for entry in entries {
            let value = match &entry.value {
                Value::Text(t) => Json::from(t.as_str()),
                Value::Number(n) => Json::from(n.parse::<u64>().unwrap()),
                Value::Bool(b) => Json::from(*b),
                Value::Block(inner) => json(inner),
            };
            for key in &entry.keys {
                object.insert(key.clone(), value.clone());
            }
        }
        Json::Object(object)
    }

    /// What the reader gives for `text`: the tree, or its refusal's words.
    fn read(text: &str) -> Result<Json, String> {
        parse(text).map(|l| json(&l.entries))
    }

    /// Checks each row: the tree it must give, or words its refusal must hold.
    fn check(rows: &[(&str, &str, Result<Json, &str>)]) {
        for (name, text, expected) in rows {
            match (read(text), expected) {
                (Ok(tree), Ok(want)) => assert_eq!(&tree, want, "{name}"),
                (Err(reason), Err(words)) => assert!(reason.contains(words), "{name}: {reason}"),
                (got, _) => panic!("{name}: {got:?}"),
            }
        }
    }

    #[test]
    fn the_reader_gives_what_yarns_own_tests_expect_or_refuses_where_yarn_repairs() {
        let bar = json!({"foo": {"bar": {"yes": "no"}}, "bar": {"yes": "no"}});
        let merge = "merge-conflict markers";
        check(&[
            // Yarn reads this only through its fallback to YAML.
            ("line 22", "foo:\n  bar\n", Err("a key with no value")),
            ("line 24", "foo \"bar\"", Ok(json!({"foo": "bar"}))),
            ("line 25", "\"foo\" \"bar\"", Ok(json!({"foo": "bar"}))),
            ("line 26", "foo \"bar\"", Ok(json!({"foo": "bar"}))),
            (
                "line 28",
                "foo:\n  bar \"bar\"",
                Ok(json!({"foo": {"bar": "bar"}})),
            ),
            (
                "line 29",
                "foo:\n  bar:\n  foo \"bar\"",
                Ok(json!({"foo": {"bar": {}, "foo": "bar"}})),
            ),
            (
                "line 30",
                "foo:\n  bar:\n    foo \"bar\"",
                Ok(json!({"foo": {"bar": {"foo": "bar"}}})),
            ),
            (
                "line 31",
                "foo:\r\n  bar:\r\n    foo \"bar\"",
                Ok(json!({"foo": {"bar": {"foo": "bar"}}})),
            ),
            (
                "line 32",
                "foo:\n  bar:\n    yes no\nbar:\n  yes no",
                Ok(bar.clone()),
            ),
            (
                "line 44",
                "foo:\r\n  bar:\r\n    yes no\r\nbar:\r\n  yes no",
                Ok(bar),
            ),
            (
                "line 60",
                "a, b:\n  foo bar\n",
                Ok(json!({"a": {"foo": "bar"}, "b": {"foo": "bar"}})),
            ),
            (
                "line 260",
                "\na:\n  no \"yes\"\n\n<<<<<<< HEAD\nb:\n  foo \"bar\"\n=======\nc:\n  bar \"foo\"\n>>>>>>> branch-a\n\nd:\n  yes \"no\"\n",
                Err(merge),
            ),
            (
                "line 288",
                "a:\r\n  no \"yes\"\r\n\r\n<<<<<<< HEAD\r\nb:\r\n  foo \"bar\"\r\n=======\r\nc:\r\n  bar \"foo\"\r\n>>>>>>> branch-a\r\n\r\nd:\r\n  yes \"no\"\r\n",
                Err(merge),
            ),
            (
                "line 303",
                "\na:\n  no \"yes\"\n\n<<<<<<< HEAD\nb:\n  foo \"bar\"\n=======\nc:\n  bar \"foo\"\n>>>>>>> branch-a\n\nd:\n  yes \"no\"\n\n<<<<<<< HEAD\ne:\n  foo \"bar\"\n=======\nf:\n  bar \"foo\"\n>>>>>>> branch-b\n",
                Err(merge),
            ),
            (
                "line 340",
                "\n<<<<<<< HEAD\nb:\n  foo: \"bar\n=======\nc:\n  bar \"foo\"\n>>>>>>> branch-a\n",
                Err(merge),
            ),
            (
                "line 356",
                "\n<<<<<<< HEAD\nb:\n  foo \"bar\"\n||||||| common ancestor\nd:\n  yes \"no\"\n=======\nc:\n  bar \"foo\"\n>>>>>>> branch-a\n",
                Err(merge),
            ),
        ]);
    }

    #[test]
    fn the_reader_gives_yarns_tree_and_refuses_what_yarn_would_repair_guess_or_drop() {
        let header = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n";
        let entry = json!({"left-pad@^1.3.0": {"version": "1.3.0", "resolved": "https://example.com/l.tgz#ab"}});
        let plain =
            "left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"https://example.com/l.tgz#ab\"\n";
        let deep = format!("{header}a:\n  b:\n    c:\n      d true\n      e 12\n  f false\n");
        let truncated = "a:\n  version \"1\"\n\n  resolved \"x\"\n";
        check(&[
            ("plain", &format!("{header}{plain}"), Ok(entry.clone())),
            (
                "crlf",
                &format!("{header}{plain}").replace('\n', "\r\n"),
                Ok(entry.clone()),
            ),
            (
                "bom",
                &format!("\u{feff}{header}{plain}"),
                Ok(entry.clone()),
            ),
            (
                "comments",
                &format!("# a\n{plain}# b\n").replace("1.3.0\"", "1.3.0\" # c"),
                Ok(entry),
            ),
            (
                "grouped and scoped",
                "\"@sc/a@^1\", \"@sc/a@^1.2\":\n  version \"1.2.0\"\n",
                Ok(json!({"@sc/a@^1": {"version": "1.2.0"}, "@sc/a@^1.2": {"version": "1.2.0"}})),
            ),
            (
                "escapes",
                "\"a\\u0040b\\\"\": \"x\\\\\"\n",
                Ok(json!({"a@b\"": "x\\"})),
            ),
            (
                "nested",
                &deep,
                Ok(json!({"a": {"b": {"c": {"d": true, "e": 12}}, "f": false}})),
            ),
            (
                "twice at the top",
                "a:\n  x \"1\"\na:\n  x \"2\"\n",
                Err("given twice"),
            ),
            ("twice in a group", "a, a:\n  x \"1\"\n", Err("given twice")),
            (
                "twice in a block",
                "a:\n  x \"1\"\n  x \"2\"\n",
                Err("given twice"),
            ),
            ("deeper", truncated, Err("indented deeper")),
            (
                "deeper at depth",
                "a:\n  b:\n    c \"1\"\n      d \"2\"\n",
                Err("indented deeper"),
            ),
            (
                "merge",
                "<<<<<<< a\n=======\n>>>>>>> b\n",
                Err("merge-conflict"),
            ),
            // A quote after two backslashes closes the string, and the line goes on.
            (
                "escaped backslash",
                "a \"x\\\\\" b \"y\"\n",
                Ok(json!({"a": "x\\", "b": "y"})),
            ),
            ("one marker", "a \"=======\"\n", Ok(json!({"a": "======="}))),
            ("lone cr", "a:\r  x \"1\"\n", Err("carriage return")),
            (
                "lone cr in a comment",
                "# a\r  b\nx \"1\"\n",
                Err("carriage return"),
            ),
            ("odd", "a:\n   x \"1\"\n", Err("odd number")),
            ("tab", "a:\n\tx \"1\"\n", Err("does not read here")),
            ("unclosed", "a \"x\n", Err("not JSON")),
            ("surrogate", "a \"\\ud800\"\n", Err("not JSON")),
            ("empty key", "\"\":\n  x \"1\"\n", Err("empty key")),
            ("comma", "a, :\n", Err("comma")),
            ("no value", "a\n", Err("no value")),
            ("stray colon", ":\n", Err("does not read here")),
        ]);
        // A version comment other than 1 stops the reading, wherever it is.
        for (text, version) in [
            (format!("{header}{plain}"), Some("1")),
            ("# yarn lockfile v2\n{{{\n".to_string(), Some("2")),
            (format!("{plain}#  yarn lockfile v10 \n["), Some("10")),
            (plain.to_string(), None),
            (format!("# yarn lockfile v\n{plain}"), None),
            (format!("# yarn lockfile v1 beta\n{plain}"), None),
        ] {
            let read = parse(&text).unwrap();
            assert_eq!(read.version.as_deref(), version, "{text}");
            assert_eq!(read.entries.is_empty(), version.is_some_and(|v| v != "1"));
        }
    }

    #[test]
    fn an_indentation_as_deep_as_the_file_allows_is_read_and_dropped_on_a_small_stack() {
        // Depth costs heap, never stack: 2,000 levels on a stack of 64 KiB, where a recursive
        // parser or drop would need more than 32 bytes a level.
        let depth = 2_000;
        let text: String = (0..depth)
            .map(|d| format!("{}k:\n", "  ".repeat(d)))
            .collect();
        let levels = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let mut read = parse(&text).unwrap().entries;
                let mut levels = 0;
                while let Some(Entry {
                    value: Value::Block(inner),
                    ..
                }) = read.first_mut()
                {
                    let next = std::mem::take(inner);
                    read = next;
                    levels += 1;
                }
                drop(parse(&text));
                levels
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(levels, depth);
    }
}
