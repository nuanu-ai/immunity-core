//! Promises of `immunity findings` and `immunity finding <id>` as commands of the contract: the
//! core's own findings, whole, as the response layer reads them to give a verdict, and the id of
//! the store every message of the contract carries. Each test runs the real binary over an
//! invented home folder and system root, so nothing of the Mac it runs on is read and the
//! network is never asked.
//!
//! Each kind of evidence is read through the contract where it is raised: a watched place in
//! `tests/promises.rs`, a process and a connection in `tests/processes.rs`, a published rule's
//! program starts and file events in `tests/event_level.rs`, a vulnerable package in
//! `tests/vulnerability_data.rs`; the others are here.

mod common;

use immunity_contract::v1;
use prost::Message;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// An invented estate: a home folder, a system root and a store beside them.
struct Estate(PathBuf);

impl Estate {
    fn new(tag: &str) -> Estate {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "immunity-findings-{tag}-{}-{nanos}",
            std::process::id()
        ));
        for dir in ["home", "system", "empty"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("brew.json"), r#"{"formulae": [], "casks": []}"#).unwrap();
        // Made real, as the readers make the home folder real: the temporary folder is a link.
        Estate(std::fs::canonicalize(root).unwrap())
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn system(&self) -> PathBuf {
        self.0.join("system")
    }

    fn store(&self) -> PathBuf {
        self.0.join("store.db")
    }

    fn put(&self, path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// `immunity <args> --store <this store>`, as it ran.
    fn immunity(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_immunity"))
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.0)
            .args(args)
            .arg("--store")
            .arg(self.store())
            .output()
            .unwrap()
    }

    /// A full run, with every outside source pointed at nothing.
    fn run(&self) {
        let (empty, none) = (self.0.join("empty"), self.0.join("none"));
        let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.0)
            .args(["run", "--machine-name", "mac", "--store"])
            .arg(self.store())
            .arg("--system-root")
            .arg(self.system())
            .arg("--brew-input")
            .arg(self.0.join("brew.json"))
            .arg("--osv-crates-input")
            .arg(&none)
            .arg("--osv-npm-input")
            .arg(&none)
            .arg("--osv-pypi-input")
            .arg(&none)
            .arg("--tailscale")
            .arg(&none)
            .arg("--threats-input")
            .arg(&none)
            .arg("--checkouts-root")
            .arg(self.home())
            .arg("--sessions-root")
            .arg(&empty)
            .arg("--servers-input")
            .arg(&empty)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A command of the contract with `--json`, which must answer: its message.
    fn json(&self, args: &[&str]) -> Value {
        let mut args = args.to_vec();
        args.push("--json");
        let out = self.immunity(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// One finding whole.
    fn finding(&self, id: &str) -> Value {
        self.json(&["finding", id])
    }

    /// The result of `immunity status --json`.
    fn status(&self) -> Value {
        let out = self.immunity(&["status", "--json"]);
        serde_json::from_slice::<Value>(&out.stdout)
            .unwrap()
            .clone()
    }

    /// What the status shows of the open finding of this rule.
    fn shown(&self, rule: &str) -> Value {
        looks(&self.status())
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["rule"] == rule)
            .unwrap_or_else(|| panic!("no {rule} in {:#}", self.status()))
            .clone()
    }
}

impl Drop for Estate {
    fn drop(&mut self) {
        common::remove(&self.0);
    }
}

/// A finding read through the contract says what the status says of it: the core's words, where
/// it is, and its reference.
fn carries_what_the_status_shows(whole: &Value, item: &Value) {
    for part in ["title", "meaning", "advice", "kind", "where_text"] {
        assert_eq!(whole[part], item[part], "{part}");
    }
    for part in ["id", "rule", "state", "severity", "confidence", "urgent"] {
        assert_eq!(whole["finding"][part], item[part], "{part}");
    }
    assert_eq!(whole["technique_text"], item["technique_text"]);
}

/// A checkout with an editor task file whose task runs on `run_on`.
fn tasks(e: &Estate, run_on: &str) {
    e.put(
        &e.home().join("dev/shop/.git/HEAD"),
        "ref: refs/heads/main\n",
    );
    e.put(
        &e.home().join("dev/shop/.vscode/tasks.json"),
        &format!(
            "{{\n  \"version\": \"2.0.0\",\n  \"tasks\": [{{\"label\": \"setup\", \"command\": \"node setup.js\", \"runOptions\": {{\"runOn\": \"{run_on}\"}}}}]\n}}\n"
        ),
    );
}

/// A task set to run when the folder is opened, in a project the store already held.
fn a_task_run_on_opening(tag: &str) -> Estate {
    let e = Estate::new(tag);
    tasks(&e, "default");
    e.run();
    tasks(&e, "folderOpen");
    e.run();
    e
}

/// The id of the one open finding of this rule.
fn id_of(e: &Estate, rule: &str) -> String {
    e.shown(rule)["id"].as_str().unwrap().to_string()
}

#[test]
fn a_place_where_code_runs_by_itself_is_read_whole_with_what_changed_and_what_it_rests_on() {
    // The response layer judges a finding from what the core kept of it: what changed, and the
    // journal entries it rests on, which hold the digest of the part that counts, never its text.
    let e = a_task_run_on_opening("autorun");
    let id = id_of(&e, "autorun.folder-open");
    let whole = e.finding(&id);
    carries_what_the_status_shows(&whole, &e.shown("autorun.folder-open"));
    assert_eq!(whole["where_text"], "~/dev/shop/.vscode/tasks.json");
    assert_eq!(
        whole["evidence"],
        json!({ "place_changed": { "change": "new", "presence_only": false } })
    );
    // The part that runs by itself is still there, as the check that found it read it.
    assert_eq!(whole["thing_now"]["presence"], "held");
    let rests = whole["rests_on"].as_array().unwrap();
    assert!(
        rests.iter().any(|r| r["predicate"] == "has_content"
            && r["new_value_text"]
                .as_str()
                .is_some_and(|v| v.starts_with("sha256:"))),
        "{rests:#?}"
    );
    assert!(!whole.to_string().contains("node setup.js"));
    assert_eq!(whole["format"], 1);
    // Each entry is the journal's own, field for field, oldest first.
    let s = |v: &Value| match v {
        Value::Null => "NULL".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let given: Vec<String> = rests
        .iter()
        .map(|r| {
            [
                "seq",
                "recorded_at",
                "run_id",
                "entry",
                "reader",
                "kind",
                "predicate",
                "subject_text",
                "old_value_text",
                "new_value_text",
            ]
            .map(|k| s(&r[k]))
            .join("|")
        })
        .collect();
    let kept: Vec<String> = rusqlite::Connection::open(e.store())
        .unwrap()
        .prepare(
            "SELECT j.seq, j.at, j.run_id, j.entry, IFNULL(j.reader, 'NULL'), IFNULL(j.kind, 'NULL'),
                    IFNULL(j.predicate, 'NULL'), IFNULL(j.subject, 'NULL'),
                    IFNULL(j.old_value, 'NULL'), IFNULL(j.new_value, 'NULL')
             FROM finding_basis b JOIN journal j ON j.seq = b.journal
             WHERE b.finding = ?1 ORDER BY j.seq",
        )
        .unwrap()
        .query_map([&id], |r| {
            Ok((0..10)
                .map(|i| match r.get_ref(i).unwrap() {
                    rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                    other => other.as_str().unwrap().to_string(),
                })
                .collect::<Vec<_>>()
                .join("|"))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(given, kept);
    assert_eq!(rests.len(), 3);
    assert_eq!(whole["finding"]["about_text"], rests[0]["subject_text"]);

    // Changed again while it is open: the same finding, last seen later, its latest change.
    common::next_second();
    e.put(
        &e.home().join("dev/shop/.vscode/tasks.json"),
        "{\"version\": \"2.0.0\", \"tasks\": [{\"label\": \"setup\", \"command\": \"make\", \"runOptions\": {\"runOn\": \"folderOpen\"}}]}\n",
    );
    e.run();
    let again = e.finding(&id);
    let rests = again["rests_on"].as_array().unwrap();
    assert_eq!(
        again["evidence"],
        json!({ "place_changed": { "change": "changed", "presence_only": false } })
    );
    assert_eq!(again["first_seen_at"], rests[0]["recorded_at"]);
    assert_eq!(again["last_seen_at"], rests[rests.len() - 1]["recorded_at"]);
    assert!(again["last_seen_at"].as_i64() > again["first_seen_at"].as_i64());
}

#[test]
fn a_removed_watched_file_s_finding_carries_the_digest_the_file_had() {
    // A shell profile, a Git hook and the login hook key of the login window's preferences read
    // once, then removed: each finding that it is gone rests on the digest it had, of the file
    // or of the key's value, and a pipe watched only for presence has none to show.
    let e = Estate::new("gone-digest");
    let (profile, hook, prefs) = (
        e.home().join(".zshrc"),
        e.home().join("dev/shop/.git/hooks/pre-commit"),
        e.home()
            .join("Library/Preferences/com.apple.loginwindow.plist"),
    );
    let login_window = |entries: &str| {
        e.put(
            &prefs,
            &format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>{entries}</dict></plist>\n"
            ),
        )
    };
    e.put(
        &e.home().join("dev/shop/.git/HEAD"),
        "ref: refs/heads/main\n",
    );
    e.put(&profile, "export A=1\n");
    e.put(&hook, "#!/bin/sh\n");
    login_window("<key>LoginHook</key><string>/Users/example/hook.sh</string>");
    let pipe = e.home().join(".bash_profile");
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&pipe)
            .status()
            .unwrap()
            .success()
    );
    e.run();
    // Changed once before it goes: only the digest it had last is the one it goes with.
    common::next_second();
    e.put(&profile, "export A=2\n");
    e.run();
    let digests: Vec<(String, String)> = rusqlite::Connection::open(e.store())
        .unwrap()
        .prepare(
            "SELECT subject, object FROM assertion
             WHERE layer = 'live' AND predicate = 'has_content'
               AND (object GLOB 'sha256:*' OR object GLOB 'value sha256:*')",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(digests.len(), 3, "{digests:?}");
    common::next_second();
    for gone in [&profile, &hook, &pipe] {
        std::fs::remove_file(gone).unwrap();
    }
    login_window("");
    e.run();
    let listed = e.json(&["findings"]);
    let gone: Vec<Value> = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| e.finding(f["finding"]["id"].as_str().unwrap()))
        .filter(|f| f["evidence"]["place_changed"]["change"] == "gone")
        .collect();
    assert_eq!(gone.len(), 4, "{listed:#}");
    for (file, digest) in &digests {
        let whole = gone
            .iter()
            .find(|f| f["finding"]["about_text"] == *file)
            .unwrap_or_else(|| panic!("no finding about {file}: {listed:#}"));
        let held: Vec<&Value> = whole["rests_on"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["predicate"] == "has_content" && r["entry"] == "removed")
            .collect();
        assert_eq!(held.len(), 1, "{whole:#}");
        assert_eq!(held[0]["old_value_text"], *digest);
        assert!(held[0]["new_value_text"].is_null());
    }
    let presence = gone
        .iter()
        .find(|f| f["evidence"]["place_changed"]["presence_only"] == true)
        .unwrap();
    assert!(
        !presence["rests_on"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["predicate"] == "has_content"),
        "{presence:#}"
    );
    // The status says each is gone, and none of them changed.
    let watched = &e.status()["watched"]["since_last_reading"];
    assert_eq!(
        (&watched["gone"], &watched["changed"]),
        (&json!(4), &json!(0))
    );
}

/// An application whose executable is a copy of `/usr/bin/true` and whose code is a script in
/// its resources, signed ad hoc as a developer's build would be.
fn application(e: &Estate) -> PathBuf {
    let app = e.system().join("Applications/Ledger.app");
    let contents = app.join("Contents");
    e.put(
        &contents.join("Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n<key>CFBundleIdentifier</key><string>org.example.ledger</string>\n<key>CFBundleExecutable</key><string>Ledger</string>\n<key>CFBundlePackageType</key><string>APPL</string>\n<key>CFBundleShortVersionString</key><string>5.2</string>\n</dict></plist>\n",
    );
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    std::fs::copy("/usr/bin/true", contents.join("MacOS/Ledger")).unwrap();
    e.put(&contents.join("Resources/app/main.js"), "start();\n");
    let out = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-"])
        .arg(&app)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    app
}

#[test]
fn software_changed_in_place_says_what_its_seal_became_and_what_it_was() {
    let e = Estate::new("seal");
    let app = application(&e);
    e.run();
    let main = app.join("Contents/Resources/app/main.js");
    e.put(&main, "start();\nrequire('/tmp/agent.js');\n");
    e.run();
    let item = e.shown("integrity.app-seal");
    let whole = e.finding(item["id"].as_str().unwrap());
    carries_what_the_status_shows(&whole, &item);
    let became = &whole["evidence"]["changed_in_place"]["became_text"];
    assert_eq!(*became, item["value_text"]);
    assert!(
        became.as_str().unwrap().starts_with("does not verify"),
        "{became}"
    );
    let text = String::from_utf8(
        e.immunity(&["finding", item["id"].as_str().unwrap()])
            .stdout,
    )
    .unwrap();
    assert!(
        text.lines()
            .any(|l| l.trim_start().starts_with("Became       does not verify")),
        "{text}"
    );
    // What it was is in the journal entry it rests on.
    let seal = whole["rests_on"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["predicate"] == "has_seal")
        .unwrap()
        .clone();
    assert_eq!(
        (
            &seal["entry"],
            &seal["old_value_text"],
            &seal["new_value_text"]
        ),
        (&json!("changed"), &json!("verifies"), became)
    );
}

#[test]
fn an_indicator_match_of_a_file_names_the_indicators_it_matched_and_no_process_and_keeps_its_advice()
 {
    let e = Estate::new("indicator");
    let profile = e.home().join(".zshrc");
    e.put(&profile, "export PATH=/opt/x:$PATH\n");
    let out = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .arg(&profile)
        .output()
        .unwrap();
    let hash = String::from_utf8(out.stdout).unwrap()[..64].to_string();
    e.put(
        &e.store().with_file_name("indicators.json"),
        &format!(
            r#"[{{"kind": "file:hashes.'SHA-256'", "value": "{hash}", "note_text": "invented"}}]"#
        ),
    );
    e.run();
    let item = e.shown("indicator.match");
    let whole = e.finding(item["id"].as_str().unwrap());
    carries_what_the_status_shows(&whole, &item);
    assert_eq!(
        whole["evidence"]["indicator_matched"]["indicators_text"],
        format!("[file:hashes.'SHA-256' = '{hash}']")
    );
    // A watched file: the reading of its place read it.
    assert_eq!(whole["thing_now"]["presence"], "held");
    assert_eq!(
        whole["evidence"]["indicator_matched"]["indicators_text"],
        item["value_text"]
    );
    let text = String::from_utf8(
        e.immunity(&["finding", item["id"].as_str().unwrap()])
            .stdout,
    )
    .unwrap();
    assert!(
        text.contains(&format!(
            "    Matched      [file:hashes.'SHA-256' = '{hash}']\n"
        )),
        "{text}"
    );
    // A file is not a process: nothing of a connection is said, and the advice is the file's.
    let matched = &whole["evidence"]["indicator_matched"];
    for field in ["process", "port", "transport"] {
        assert!(matched[field].is_null(), "{field}: {matched}");
    }
    assert!(
        !text.contains("Connection") && !text.contains("Process"),
        "{text}"
    );
    assert_eq!(
        whole["advice"],
        "Do not open or run what is named here; find out how it got there, and treat this Mac as affected until you know."
    );
}

#[test]
fn a_finding_the_person_answered_says_so_with_who_why_and_until_when_and_reopened_says_none() {
    // A verdict about a finding the person already answered must know it: the answer, who gave
    // it, the reason and how long it holds, in the list and in the finding whole.
    let e = a_task_run_on_opening("answered");
    let id = id_of(&e, "autorun.folder-open");
    let read = e.finding(&id)["journal_seq"].to_string();
    let out = e.immunity(&[
        "finding",
        &id,
        "expected",
        "--reason",
        "my own build task",
        "--days",
        "7",
        "--via",
        "agent",
        "--journal-seq",
        &read,
    ]);
    assert!(out.status.success());
    let whole = e.finding(&id);
    let answer = &whole["answer"];
    assert_eq!(
        (
            &whole["finding"]["state"],
            &answer["given"],
            &answer["via"],
            &answer["reason_text"],
            &answer["in_force"],
        ),
        (
            &json!("expected"),
            &json!("expected"),
            &json!("agent"),
            &json!("my own build task"),
            &json!(true),
        )
    );
    assert_eq!(
        answer["until_at"].as_i64().unwrap() - answer["given_at"].as_i64().unwrap(),
        7 * 86_400
    );
    // The list carries the same answer, and a finding answered stays in it.
    let listed = e.json(&["findings"]);
    let entry = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["finding"]["id"] == id.as_str())
        .unwrap()
        .clone();
    assert_eq!(entry["answer"], *answer);
    assert_eq!(entry["finding"], whole["finding"]);
    for part in [
        "first_seen_at",
        "last_seen_at",
        "where_text",
        "title",
        "kind",
    ] {
        assert_eq!(entry[part], whole[part], "{part}");
    }

    // Seen from the command line, with no reason: none is given, and no end.
    assert!(e.immunity(&["finding", &id, "reopen"]).status.success());
    let reopened = e.finding(&id);
    assert_eq!(
        (&reopened["finding"]["state"], &reopened["answer"]),
        (&json!("open"), &Value::Null)
    );
    assert!(e.immunity(&["finding", &id, "seen"]).status.success());
    let seen = e.finding(&id)["answer"].clone();
    assert_eq!(
        (
            &seen["given"],
            &seen["via"],
            &seen["reason_text"],
            &seen["until_at"]
        ),
        (
            &json!("seen"),
            &json!("command"),
            &Value::Null,
            &Value::Null
        )
    );
    assert_eq!(seen["in_force"], true);

    // Changed again after it was seen: the answer stays, and no longer hides what is new.
    common::next_second();
    e.put(
        &e.home().join("dev/shop/.vscode/tasks.json"),
        "{\"version\": \"2.0.0\", \"tasks\": [{\"label\": \"setup\", \"command\": \"make\", \"runOptions\": {\"runOn\": \"folderOpen\"}}]}\n",
    );
    e.run();
    let old = e.finding(&id)["answer"].clone();
    assert_eq!(
        (&old["given"], &old["in_force"]),
        (&json!("seen"), &json!(false))
    );
}

/// A reason a person or an agent may type: markup, a line break, then lines shaped like a label
/// of the finding and like one of its commands.
const FORGED: &str = "the installer of a <i>tool</i>\nWhere        ~/.ssh/authorized_keys\n→ immunity finding f0000000000 seen";

/// A shell profile read in full, then changed: the store holds it, and the change is a finding.
fn a_profile_changed(tag: &str) -> (Estate, PathBuf, String) {
    let e = Estate::new(tag);
    let profile = e.home().join(".zshrc");
    e.put(&profile, "export A=1\n");
    e.run();
    common::next_second();
    e.put(&profile, "export A=2\n");
    e.run();
    let id = id_of(&e, "watched.shell-profile");
    (e, profile, id)
}

impl Estate {
    /// `immunity finding <id>` as a person reads it in a pipe.
    fn text(&self, id: &str) -> String {
        String::from_utf8(self.immunity(&["finding", id]).stdout).unwrap()
    }

    /// Every page `immunity view` writes, one after the other.
    fn pages(&self) -> String {
        let out = self.immunity(&["view", "--no-open"]);
        assert!(out.status.success(), "{out:?}");
        let paths = String::from_utf8(out.stdout).unwrap();
        paths
            .lines()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect()
    }
}

#[test]
fn a_finding_found_again_after_seen_names_the_earlier_one_its_answer_and_reason_as_data() {
    // The person reads that the same thing was found and closed before, when, by whom and why,
    // in every form; a first finding names none. The reason is the person's or the agent's
    // text: it stays inside its field and never forges a line of the finding or of the page.
    let (e, profile, first) = a_profile_changed("again");
    let whole = e.finding(&first);
    assert!(whole["earlier"].is_null(), "{whole:#}");
    assert!(!e.text(&first).contains("Earlier"));
    // An occurrence before it that the core closed, which nobody answered, as of a package
    // cleared by an upgrade: named in every form, with no answer.
    rusqlite::Connection::open(e.store())
        .unwrap()
        .execute(
            "INSERT INTO finding (id, rule, about, occurrence, state, first_seen_at,
                                  first_seen_run, last_seen_at, last_seen_run)
             SELECT 'f00000000aa', rule, about, 0, 'cleared', 1, 'r', 1, 'r' FROM finding
             WHERE id = ?1",
            [&first],
        )
        .unwrap();
    let closed = &e.finding(&first)["earlier"];
    assert_eq!(
        (&closed["finding"]["id"], &closed["answer"]),
        (&json!("f00000000aa"), &Value::Null)
    );
    assert!(
        e.text(&first)
            .contains("  Earlier       f00000000aa, cleared\n")
    );
    assert!(e.pages().contains("<dt>Earlier</dt><dd>f00000000aa</dd>"));
    let read = whole["journal_seq"].to_string();
    let answer = [
        "finding",
        &first,
        "seen",
        "--reason",
        FORGED,
        "--via",
        "agent",
        "--journal-seq",
        &read,
    ];
    assert!(e.immunity(&answer).status.success());
    common::next_second();
    e.put(&profile, "export A=3\n");
    e.run();
    let again = id_of(&e, "watched.shell-profile");
    assert_ne!(again, first);
    let earlier = &e.finding(&again)["earlier"];
    assert_eq!(
        (
            &earlier["finding"]["id"],
            &earlier["finding"]["state"],
            &earlier["answer"]["given"],
            &earlier["answer"]["via"],
            &earlier["answer"]["reason_text"],
        ),
        (
            &json!(first),
            &json!("seen"),
            &json!("seen"),
            &json!("agent"),
            &json!(FORGED.replace('\n', "\\u{a}"))
        )
    );
    // The same answer the earlier finding gives, whole.
    assert_eq!(earlier["answer"], e.finding(&first)["answer"]);
    let text = e.text(&again);
    let said = format!("  Earlier       {first}, seen, given ");
    assert!(
        text.lines()
            .any(|l| l.starts_with(&said) && l.ends_with(" through your agent")),
        "{text}"
    );
    assert!(
        text.contains("  Said then     the installer of a <i>tool</i>"),
        "{text}"
    );
    for line in text.lines() {
        assert!(
            !line.trim_start().starts_with("Where        ~/.ssh"),
            "{text}"
        );
        assert!(
            !line.starts_with("→ immunity finding f0000000000"),
            "{text}"
        );
    }
    let page = e.pages();
    assert!(page.contains(&format!("Your agent before, to {first}")));
    assert!(page.contains("the installer of a &lt;i&gt;tool&lt;/i&gt;"));
    assert!(!page.contains(FORGED) && !page.contains("\n→ immunity finding f0"));
    // Found a third time, after a seen from the command line with no reason: only the latest
    // earlier one is named, and it came from the command line.
    assert!(e.immunity(&["finding", &again, "seen"]).status.success());
    common::next_second();
    e.put(&profile, "export A=4\n");
    e.run();
    let third = e.finding(&id_of(&e, "watched.shell-profile"))["earlier"].clone();
    assert_eq!(
        (&third["finding"]["id"], &third["answer"]["via"]),
        (&json!(again), &json!("command"))
    );
    assert!(third["answer"]["reason_text"].is_null());
}

#[test]
fn a_watched_entry_is_there_only_as_the_latest_reading_of_its_place_read_it_and_never_gone_by_a_retraction()
 {
    // A shell profile and a Git hook in the folder the checkout's configuration names, each
    // changed after a first check. Then the profile is removed and the configuration names
    // another folder, and then the checkout goes. No reading records that it looked for either and found nothing, so neither
    // is ever said to be gone: not known, last found by the check that read them.
    let e = Estate::new("now");
    let (profile, hook) = (
        e.home().join(".zshrc"),
        e.home().join("dev/tree/first/pre-commit"),
    );
    e.put(
        &e.home().join("dev/tree/.git/HEAD"),
        "ref: refs/heads/main\n",
    );
    let config = e.home().join("dev/tree/.git/config");
    e.put(&config, "[core]\n hooksPath = first\n");
    // A hook in the checkout's own folder, still watched while the configuration names another.
    let kept = e.home().join("dev/tree/.git/hooks/post-merge");
    e.put(&kept, "# 1\n");
    e.put(&e.home().join("dev/tree/second/pre-push"), "# other\n");
    for path in [&profile, &hook] {
        e.put(path, "# 1\n");
    }
    e.run();
    common::next_second();
    for path in [&profile, &hook, &kept] {
        e.put(path, "# 2\n");
    }
    e.run();
    let shell = id_of(&e, "watched.shell-profile");
    let hooks = e.json(&["findings"])["findings"].clone();
    let hook_of = |name: &str| {
        let f = (hooks.as_array().unwrap().iter())
            .find(|f| f["finding"]["about_text"].as_str().unwrap().ends_with(name))
            .unwrap();
        f["finding"]["id"].as_str().unwrap().to_string()
    };
    let (git, kept) = (hook_of("first/pre-commit"), hook_of("hooks/post-merge"));
    let now = |id: &str| e.finding(id)["thing_now"].clone();
    let found = now(&shell);
    assert_eq!(found["presence"], "held", "{found}");
    let at = found["at"].as_i64().unwrap();
    assert_eq!(
        (&now(&git)["presence"], &now(&git)["at"]),
        (&json!("held"), &json!(at))
    );
    assert!(
        e.text(&shell)
            .contains("    Now          there when last read, ")
    );
    let page = e.pages();
    assert!(page.contains("<dt>Now</dt><dd><span class=\"w\">found there by a reading, <time "));
    assert!(!page.contains("still"), "{page}");
    common::next_second();
    std::fs::remove_file(&profile).unwrap();
    e.put(&config, "[core]\n hooksPath = second\n");
    e.run();
    let unknown = (json!("unknown"), json!(at));
    for id in [&shell, &git] {
        let n = now(id);
        assert_eq!((n["presence"].clone(), n["at"].clone()), unknown, "{id}");
        let text = e.text(id);
        assert!(text.contains("    Now          not known whether it is there; last found "));
        assert!(!text.contains("no longer there"), "{text}");
    }
    common::next_second();
    common::remove(&e.home().join("dev/tree/.git"));
    e.run();
    let n = now(&git);
    assert_eq!((n["presence"].clone(), n["at"].clone()), unknown);
    // The hook its own folder held was read until the checkout went, and no reading since.
    let n = now(&kept);
    assert_eq!(n["presence"], "unknown", "{n}");
    assert!(n["at"].as_i64() > Some(at));
    // The line decides nothing: each finding stays open until the person answers it.
    for id in [&shell, &git] {
        assert_eq!(e.finding(id)["finding"]["state"], "open");
    }
}

#[test]
fn a_startup_program_looked_for_and_not_found_is_no_longer_there_and_not_known_once_not_looked_at()
{
    // The one record of a thing found absent is a program a startup item names, looked for at
    // its path at each check. A program recorded as not there is never said to be there.
    let e = Estate::new("target");
    let folder = e.system().join("usr/local/bin");
    let runner = folder.join("runner");
    e.put(&runner, "#!/bin/sh\nexit 0\n");
    e.put(
        &e.home().join("Library/LaunchAgents/org.example.item.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
         <key>Label</key><string>org.example.item</string><key>ProgramArguments</key>\
         <array><string>/usr/local/bin/runner</string></array></dict></plist>\n",
    );
    e.run();
    common::next_second();
    e.put(&runner, "#!/bin/sh\nexit 1\n");
    e.run();
    let id = id_of(&e, "watched.startup-target");
    let now = || e.finding(&id)["thing_now"].clone();
    let there = now();
    assert_eq!(there["presence"], "held", "{there}");
    use std::os::unix::fs::PermissionsExt;
    let mode = |path: &Path, mode| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    common::next_second();
    mode(&runner, 0o000);
    e.run();
    mode(&runner, 0o644);
    let unread = now();
    assert_eq!(
        (&unread["presence"], &unread["at"]),
        (&json!("unknown"), &there["at"])
    );
    common::next_second();
    std::fs::remove_file(&runner).unwrap();
    e.run();
    let gone = now();
    assert_eq!(gone["presence"], "gone", "{gone}");
    assert!(gone["at"].as_i64() > there["at"].as_i64());
    assert!(e.text(&id).contains(
        "    Now          no longer there: a reading that looked found nothing at its path, "
    ));
    assert!(
        e.pages()
            .contains("<span class=\"w\">a reading that looked found nothing at its path, <time ")
    );
    // Its folder shut: the latest check did not look, so whether it is there is not known, last
    // found by the check that read it.
    common::next_second();
    mode(&folder, 0o000);
    e.run();
    mode(&folder, 0o755);
    let unknown = now();
    assert_eq!(
        (&unknown["presence"], &unknown["at"]),
        (&json!("unknown"), &there["at"])
    );
}

#[test]
fn an_indicator_match_of_a_file_no_reading_records_by_itself_says_nothing_of_what_is_there_now() {
    // Nothing records a lockfile by itself, so nothing is said of whether it is there, also once
    // the indicator it matched leaves the list.
    let e = Estate::new("lockfile");
    e.put(
        &e.home().join("dev/shop/.git/HEAD"),
        "ref: refs/heads/main\n",
    );
    e.put(
        &e.home().join("dev/shop/package-lock.json"),
        r#"{"name": "shop", "lockfileVersion": 3, "packages": {"": {"name": "shop"},
            "node_modules/a": {"version": "1.0.0", "resolved": "https://relay.example/a.tgz"}}}"#,
    );
    let list = |entries: &str| e.put(&e.store().with_file_name("indicators.json"), entries);
    list(r#"[{"kind": "domain-name:value", "value": "relay.example"}]"#);
    e.run();
    let id = id_of(&e, "indicator.match");
    assert!(e.finding(&id)["thing_now"].is_null());
    common::next_second();
    list("[]");
    e.run();
    assert!(e.finding(&id)["thing_now"].is_null());
    let text = e.text(&id);
    assert!(
        !text.contains("    Now ") && !text.contains("no longer there"),
        "{text}"
    );
}

#[test]
fn a_finding_that_rests_on_events_only_says_nothing_of_what_is_there_now() {
    // A verdict raises a finding of the response layer about what it judged: an event, which is
    // over once it happened.
    let (e, _, id) = a_profile_changed("events-only");
    let store = e.finding(&id)["store_id"].clone();
    let verdict = json!({
        "format": 1, "store_id": store, "finding": { "id": id }, "kind": "suspicious",
        "reason_text": "invented", "case_text": "case-1", "severity": "low", "confidence": "low",
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_immunity"))
        .env("HOME", e.home())
        .env("PATH", "/usr/bin:/bin")
        .args(["verdict", "--json", "--store"])
        .arg(e.store())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(verdict.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let recorded: Value = serde_json::from_slice(&out.stdout).unwrap();
    let own = recorded["recorded"]["finding"]["id"].as_str().unwrap();
    assert!(e.finding(&id)["thing_now"].is_object());
    assert!(e.finding(own)["thing_now"].is_null());
    assert!(!e.text(own).contains("    Now "), "{}", e.text(own));
}

#[test]
fn the_list_carries_every_finding_in_every_state_whatever_all_says_and_a_person_sees_the_open_ones()
{
    let e = a_task_run_on_opening("states");
    let id = id_of(&e, "autorun.folder-open");
    assert!(e.immunity(&["finding", &id, "seen"]).status.success());
    for args in [&["findings"][..], &["findings", "--all"][..]] {
        let listed = e.json(args);
        let states: Vec<&Value> = listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| &f["finding"]["state"])
            .collect();
        assert_eq!(states, [&json!("seen")], "{args:?}");
    }
    let text = String::from_utf8(e.immunity(&["findings"]).stdout).unwrap();
    assert!(text.starts_with("✓ No open findings"), "{text}");
    assert!(!text.contains(&id), "{text}");
    let text = String::from_utf8(e.immunity(&["findings", "--all"]).stdout).unwrap();
    assert!(
        text.starts_with("✓ 1 finding, 0 open, none urgent") && text.contains(&id),
        "{text}"
    );
}

#[test]
fn the_binary_and_the_json_forms_are_one_message_for_the_list_and_for_one_finding() {
    let e = a_task_run_on_opening("forms");
    let id = id_of(&e, "autorun.folder-open");
    // The two are asked apart, so the second in which each was answered may differ.
    let mut json = e.json(&["findings"]);
    let binary = e.immunity(&["findings", "--proto"]).stdout;
    let mut decoded = v1::Findings::decode(binary.as_slice()).unwrap();
    decoded.answered_at = 0;
    json["answered_at"] = json!(0);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), json);
    let parsed: v1::Findings = serde_json::from_value(json).unwrap();
    assert_eq!(parsed, decoded);
    assert_eq!(decoded.findings.len(), 1);
    // The latest run is the one every answer about this store names.
    assert!(decoded.latest_run_at.is_some());
    assert_eq!(
        json!(decoded.latest_run_at),
        e.json(&["machine"])["latest_run_at"]
    );

    let mut json = e.json(&["finding", &id]);
    let binary = e.immunity(&["finding", &id, "--proto"]).stdout;
    let mut decoded = v1::Finding::decode(binary.as_slice()).unwrap();
    decoded.answered_at = 0;
    json["answered_at"] = json!(0);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), json);
    let parsed: v1::Finding = serde_json::from_value(json).unwrap();
    assert_eq!(parsed, decoded);
    assert_eq!(decoded.finding.unwrap().id, id);
    // A one-of prints as an object with one key, the case that is set.
    assert!(matches!(
        decoded.evidence.and_then(|e| e.body),
        Some(v1::evidence::Body::PlaceChanged(_))
    ));
}

#[test]
fn a_failure_never_parses_as_an_answer() {
    // A reader checks the exit code first; one that parses all the same reads format 0.
    let e = a_task_run_on_opening("failure");
    let unknown = e.immunity(&["finding", "f0000000000", "--json"]);
    assert_eq!(unknown.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&unknown.stdout).unwrap();
    assert_eq!(v["errors"][0]["code"], "unknown_finding");
    let parsed: v1::Finding = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(parsed.format, 0);
    let text = e.immunity(&["finding", "f0000000000"]);
    assert_eq!(text.status.code(), Some(2));
    assert!(text.stdout.is_empty());

    // A misuse of either command, as the contract fails.
    for args in [
        &["findings", "--open", "--json"][..],
        &["finding", "--json"][..],
        &["findings", "--json", "--proto"][..],
    ] {
        let out = e.immunity(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(v.get("format").is_none(), "{v}");
        assert_eq!(v["errors"][0]["code"], "usage");
        let parsed: v1::Findings = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.format, 0);
    }
    // An answer fails with the same message.
    let out = e.immunity(&["finding", "f0000000000", "seen", "--json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (v.get("format"), &v["errors"][0]["code"]),
        (None, &json!("unknown_finding"))
    );
    let id = id_of(&e, "autorun.folder-open");
    let out = e.immunity(&["finding", &id, "seen", "--via", "agent", "--json"]);
    assert_eq!(out.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (v.get("format"), &v["errors"][0]["code"]),
        (None, &json!("usage"))
    );
    // An answer asked in binary answers with the finding as it left it, in binary.
    let out = e.immunity(&["finding", &id, "seen", "--proto"]);
    assert_eq!(out.status.code(), Some(0));
    let answered = v1::Finding::decode(out.stdout.as_slice()).unwrap();
    assert_eq!(answered.format, 1);
    assert_eq!(
        answered.finding.as_ref().map(|f| f.state),
        Some(v1::FindingState::Seen as i32)
    );
    assert_eq!(e.finding(&id)["finding"]["state"], "seen");
    assert_eq!(
        e.immunity(&["finding", &id, "reopen"]).status.code(),
        Some(0)
    );
    assert_eq!(e.finding(&id)["finding"]["state"], "open");

    // No store: a failure with exit code 3, never an empty list.
    let none = Estate::new("no-store");
    for args in [
        &["findings", "--json"][..],
        &["finding", "f0000000000", "--json"][..],
    ] {
        let out = none.immunity(args);
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["errors"][0]["code"], "store_unreadable");
        assert!(v.get("format").is_none(), "{v}");
    }
    assert!(!none.store().exists());
}

#[test]
fn a_store_without_the_table_of_findings_fails_as_damaged_rather_than_reading_as_none() {
    // False calm: an empty list from a store that lacks the table of findings would read as
    // "nothing found". A store of this format always has it, so one without it is damaged.
    let e = a_task_run_on_opening("damaged");
    rusqlite::Connection::open(e.store())
        .unwrap()
        .execute_batch("DROP TABLE finding_basis; DROP TABLE rule_line; DROP TABLE rule_finding; DROP TABLE rule_evidence; DROP TABLE rule_file_evidence; DROP TABLE finding;")
        .unwrap();
    let out = e.immunity(&["findings", "--json"]);
    assert_eq!(out.status.code(), Some(3));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["errors"][0]["detail_text"]
            .as_str()
            .unwrap()
            .contains("is damaged: it lacks the table"),
        "{v}"
    );
}

/// The `store_id` of every message of the contract this store answers with.
fn store_ids(e: &Estate) -> Vec<Value> {
    let id = id_of(e, "autorun.folder-open");
    let root = e.system();
    let root = root.to_str().unwrap();
    [
        e.json(&["findings"]),
        e.json(&["finding", &id]),
        e.json(&["machine"]),
        e.json(&["project", "~/dev/shop"]),
        e.json(&["matches", "--system-root", root]),
    ]
    .iter()
    .map(|m| m["store_id"].clone())
    .collect()
}

#[test]
fn every_message_of_one_store_carries_its_id_another_store_has_another_and_a_run_keeps_it() {
    // A finding's id is unique only within one store: a verdict kept by finding id alone would
    // attach to another finding once the store is made again.
    let e = a_task_run_on_opening("store-id");
    let ids = store_ids(&e);
    let first = ids[0].as_str().unwrap().to_string();
    assert!(
        first.len() == 32 && first.bytes().all(|b| b.is_ascii_hexdigit()),
        "{first}"
    );
    assert!(ids.iter().all(|i| *i == ids[0]), "{ids:?}");
    // The binary form carries the same.
    let binary = e.immunity(&["findings", "--proto"]).stdout;
    assert_eq!(
        v1::Findings::decode(binary.as_slice()).unwrap().store_id,
        Some(first.clone())
    );
    e.run();
    assert_eq!(store_ids(&e)[0], ids[0]);
    // The same Mac, read the same way, into a store made again: another id.
    let other = a_task_run_on_opening("store-id-other");
    assert_ne!(store_ids(&other)[0], ids[0]);
    // A finding's id, which is not random, can be the same in both.
    assert_eq!(
        id_of(&other, "autorun.folder-open"),
        id_of(&e, "autorun.folder-open")
    );
}

#[test]
fn every_command_of_the_contract_answers_in_binary_with_proto_and_refuses_two_forms() {
    let e = a_task_run_on_opening("proto");
    let root = e.system();
    let root = root.to_str().unwrap();
    for args in [
        vec!["project", "~/dev/shop"],
        vec!["program", "Ledger"],
        vec!["machine"],
        vec!["matches", "--system-root", root],
    ] {
        let mut proto = args.clone();
        proto.push("--proto");
        let named = e.immunity(&proto);
        assert!(named.status.success(), "{args:?}");
        let mut json = e.json(&args);
        // The time it was answered may differ by a second; the rest is the same message.
        let mut decoded = if args[0] == "matches" {
            serde_json::to_value(v1::Matches::decode(named.stdout.as_slice()).unwrap()).unwrap()
        } else {
            serde_json::to_value(v1::Known::decode(named.stdout.as_slice()).unwrap()).unwrap()
        };
        decoded["answered_at"] = Value::Null;
        json["answered_at"] = Value::Null;
        assert_eq!(decoded, json, "{args:?}");
        let mut both = args.clone();
        both.extend(["--json", "--proto"]);
        let out = e.immunity(&both);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(v.get("format").is_none(), "{v}");
    }
}

/// What `needs_a_look` lists, each `LookFinding` read as one object: the finding's reference,
/// the finding as listed and its words side by side, so a test names a field once.
fn looks(status: &serde_json::Value) -> serde_json::Value {
    let items = status["needs_a_look"]["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    items
        .iter()
        .map(|look| {
            let mut flat = serde_json::Map::new();
            for part in [&look["finding"]["finding"], &look["finding"], look] {
                for (k, v) in part.as_object().into_iter().flatten() {
                    if k != "finding" {
                        flat.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
            serde_json::Value::Object(flat)
        })
        .collect()
}
