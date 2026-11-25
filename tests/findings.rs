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
        json!({ "place_changed": { "change": "new", "presence_only": false, "read_as_before_at": null, "runs": [], "started_by": [] } })
    );
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
        json!({ "place_changed": { "change": "changed", "presence_only": false, "read_as_before_at": null, "runs": [], "started_by": [] } })
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
    // Closed findings before it, of its rule about another thing and of another rule about its
    // thing: neither is an earlier occurrence of it.
    let store = rusqlite::Connection::open(e.store()).unwrap();
    let before = |id: &str, rule: &str, about: &str| {
        store
            .execute(
                "INSERT INTO finding (id, rule, about, occurrence, state, first_seen_at,
                                      first_seen_run, last_seen_at, last_seen_run)
                 SELECT ?1, COALESCE(?2, rule), COALESCE(?3, about), 0, 'cleared', 1, 'r', 1, 'r'
                 FROM finding WHERE id = ?4",
                rusqlite::params![
                    id,
                    (!rule.is_empty()).then_some(rule),
                    (!about.is_empty()).then_some(about),
                    first
                ],
            )
            .unwrap();
    };
    store
        .execute(
            "INSERT INTO entity (id, type) VALUES ('file:machine:mac/.bashrc', 'file')",
            [],
        )
        .unwrap();
    before("f00000000b1", "", "file:machine:mac/.bashrc");
    before("f00000000b2", "watched.ssh-access", "");
    let whole = e.finding(&first);
    assert!(whole["earlier"].is_null(), "{whole:#}");
    assert!(!e.text(&first).contains("Earlier"));
    // An occurrence before it that the core closed, which nobody answered, as of a package
    // cleared by an upgrade: named in every form, with no answer.
    before("f00000000aa", "", "");
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
    // On the page the reason given then is the quote of that answer, escaped.
    let page = e.pages();
    let voice = format!("<div class=\"vn\">Your agent before, to {first}</div>");
    let quote = &page[page.find(&voice).expect(&voice)..];
    let quote = &quote[quote.find("<blockquote").unwrap()..quote.find("</blockquote>").unwrap()];
    assert!(
        quote.starts_with("<blockquote class=\"quote\">the installer of a &lt;i&gt;tool&lt;/i&gt;"),
        "{quote}"
    );
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

/// UTC seconds as `date` writes them in this format.
fn date(at: i64, format: &str) -> String {
    let out = Command::new("/bin/date")
        .args(["-u", "-r", &at.to_string(), format])
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .trim_end()
        .to_string()
}

/// UTC seconds as the text for a person writes them in a pipe.
fn utc(at: i64) -> String {
    date(at, "+%Y-%m-%d %H:%M UTC")
}

/// The `<dd>` of the fact a page labels `Read back`.
fn read_back_on_page(page: &str) -> &str {
    let dd = &page[page.find("<dt>Read back</dt><dd>").expect(page)..];
    &dd[..dd.find("</dd>").unwrap()]
}

/// What `immunity finding <id>` says of a reading that read a watched file as it was before.
const READ_AS_BEFORE: &str = "read the content with the checksum it had before the first change of content this finding rests on";

impl Estate {
    /// `PlaceChanged.read_as_before_at` of a finding.
    fn read_as_before(&self, id: &str) -> Value {
        self.finding(id)["evidence"]["place_changed"]["read_as_before_at"].clone()
    }

    /// A watched file unreadable for one run.
    fn run_unreadable(&self, path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        self.run();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}

/// The `recorded_at` of the latest entry a finding rests on with this entry and predicate.
fn latest_entry(whole: &Value, entry: &str, predicate: Option<&str>) -> i64 {
    whole["rests_on"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|r| r["entry"] == entry && predicate.is_none_or(|p| r["predicate"] == p))
        .unwrap_or_else(|| panic!("no {entry} in {whole:#}"))["recorded_at"]
        .as_i64()
        .unwrap()
}

#[test]
fn a_watched_file_read_back_as_before_its_first_change_names_that_reading_and_stays_open() {
    // A shell profile changed, then changed back a second later: the finding names the reading
    // that read the content it had before, in the message, the text and the page, and stays as
    // it was: open, at its levels, among what needs a look, with its title.
    let (e, profile, id) = a_profile_changed("back");
    let before = e.shown("watched.shell-profile");
    common::next_second();
    e.put(&profile, "export A=1\n");
    e.run();
    assert_eq!(id_of(&e, "watched.shell-profile"), id);
    let whole = e.finding(&id);
    let back = latest_entry(&whole, "changed", Some("has_content"));
    assert_eq!(e.read_as_before(&id), json!(back), "{whole:#}");
    let after = e.shown("watched.shell-profile");
    for part in ["state", "severity", "confidence", "urgent", "title"] {
        assert_eq!(after[part], before[part], "{part}");
    }
    assert_eq!(whole["evidence"]["place_changed"]["change"], "changed");
    let line = format!("the reading of {} {READ_AS_BEFORE}", utc(back));
    let text = e.text(&id);
    assert!(
        text.lines()
            .any(|l| l.trim_start().starts_with("Read back") && l.ends_with(&line)),
        "{text}"
    );
    let page = e.pages();
    let dd = read_back_on_page(&page);
    assert!(
        dd.contains(&format!("title=\"{}\"", utc(back))) && dd.contains(READ_AS_BEFORE),
        "{dd}"
    );
    assert!(
        dd.starts_with("<dt>Read back</dt><dd><span class=\"w\">the reading of</span> <time"),
        "{dd}"
    );
}

#[test]
fn a_watched_file_changed_back_and_changed_again_says_nothing_of_the_return() {
    let (e, profile, id) = a_profile_changed("back-again");
    for content in ["export A=1\n", "export A=3\n"] {
        common::next_second();
        e.put(&profile, content);
        e.run();
    }
    assert_eq!(id_of(&e, "watched.shell-profile"), id);
    assert!(e.read_as_before(&id).is_null());
    assert!(!e.text(&id).contains("Read back"));
    assert!(!e.pages().contains("Read back"));
}

#[test]
fn a_reading_that_could_not_read_a_file_changed_back_never_moves_the_reading_named() {
    // Changed back, then not read, then read again unchanged: neither later reading read
    // anything new, so the reading named is still the one that read it back, and nothing says
    // what the file holds now.
    let (e, profile, id) = a_profile_changed("back-unread");
    common::next_second();
    e.put(&profile, "export A=1\n");
    e.run();
    // An hour ago, so that the minutes the text names tell the readings apart.
    common::rewrite_journal(
        &e.store(),
        "UPDATE journal SET at = at - 3600 WHERE predicate = 'has_content'",
    );
    let back = e.read_as_before(&id);
    assert!(back.is_i64(), "{:#}", e.finding(&id));
    common::next_second();
    e.run_unreadable(&profile);
    let whole = e.finding(&id);
    assert_eq!(whole["evidence"]["place_changed"]["change"], "not_read");
    assert!(latest_entry(&whole, "not_read", None) > back.as_i64().unwrap());
    assert_eq!(e.read_as_before(&id), back);
    common::next_second();
    e.run();
    assert_eq!(e.read_as_before(&id), back);
    let text = e.text(&id);
    let line = text.lines().find(|l| l.contains(READ_AS_BEFORE)).unwrap();
    assert!(line.contains(&utc(back.as_i64().unwrap())), "{line}");
    assert!(!line.contains("now"), "{line}");
    // The page names that reading to the second.
    let iso = date(back.as_i64().unwrap(), "+%Y-%m-%dT%H:%M:%SZ");
    let page = e.pages();
    let dd = read_back_on_page(&page);
    assert!(dd.contains(&format!("datetime=\"{iso}\"")), "{dd}");
}

#[test]
fn a_file_never_read_before_its_first_change_says_nothing_of_a_return() {
    // Added, then changed and changed back to what it was added with: there was no content
    // before the finding's first change to read back.
    let e = Estate::new("back-new");
    e.run();
    let profile = e.home().join(".zshrc");
    for content in ["export A=1\n", "export A=2\n", "export A=1\n"] {
        common::next_second();
        e.put(&profile, content);
        e.run();
    }
    let id = id_of(&e, "watched.shell-profile");
    let whole = e.finding(&id);
    let added = whole["rests_on"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["predicate"] == "has_content")
        .unwrap()
        .clone();
    assert_eq!(added["entry"], "added", "{whole:#}");
    assert!(e.read_as_before(&id).is_null(), "{whole:#}");
}

#[test]
fn a_place_not_read_then_read_again_unchanged_is_titled_by_the_time_it_was_not_read() {
    // Reading it again unchanged is no event, so the finding keeps its title; the title names
    // the reading that could not read it, never "the last check", which read it. Not read
    // again, it names the latest such reading.
    let e = Estate::new("unread-title");
    let profile = e.home().join(".zshrc");
    e.put(&profile, "export A=1\n");
    e.run();
    common::next_second();
    e.run_unreadable(&profile);
    // An hour ago, so that the minutes a title names tell two readings apart.
    common::rewrite_journal(
        &e.store(),
        "UPDATE journal SET at = at - 3600 WHERE entry = 'not_read'",
    );
    let id = id_of(&e, "watched.shell-profile");
    let title = |at: i64| {
        format!(
            "At {} Immunity Core could not read a watched shell profile, so it is not known whether it was added, changed or removed.",
            utc(at)
        )
    };
    let first = title(latest_entry(&e.finding(&id), "not_read", None));
    common::next_second();
    e.run();
    let whole = e.finding(&id);
    assert_eq!(whole["title"], first, "{whole:#}");
    assert_eq!(e.shown("watched.shell-profile")["title"], first);
    assert!(e.text(&id).contains(&first));
    assert!(!e.text(&id).contains("the last check"));
    common::next_second();
    e.run_unreadable(&profile);
    assert_eq!(id_of(&e, "watched.shell-profile"), id);
    let latest = title(latest_entry(&e.finding(&id), "not_read", None));
    assert_ne!(latest, first);
    assert_eq!(e.finding(&id)["title"], latest);
}

#[test]
fn a_place_not_read_is_titled_by_its_latest_reading_in_the_journal_s_order_after_a_clock_set_back()
{
    // Two readings that could not read the file, the later one made after the clock was set
    // back two hours: the title names the later reading, at the time the clock gave it.
    let e = Estate::new("unread-clock");
    let profile = e.home().join(".zshrc");
    e.put(&profile, "export A=1\n");
    e.run();
    for _ in 0..2 {
        common::next_second();
        e.run_unreadable(&profile);
        common::next_second();
        e.run();
    }
    common::rewrite_journal(
        &e.store(),
        "UPDATE journal SET at = at - 7200
         WHERE seq = (SELECT MAX(seq) FROM journal WHERE entry = 'not_read')",
    );
    let id = id_of(&e, "watched.shell-profile");
    let whole = e.finding(&id);
    let unread: Vec<i64> = whole["rests_on"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["entry"] == "not_read")
        .map(|r| r["recorded_at"].as_i64().unwrap())
        .collect();
    assert!(unread.len() == 2 && unread[1] < unread[0], "{whole:#}");
    let title = whole["title"].as_str().unwrap();
    assert!(
        title.starts_with(&format!("At {} ", utc(unread[1]))),
        "{title}"
    );
}

#[test]
fn the_page_of_code_changed_outside_an_app_names_each_file_escaped() {
    // The page names the files the text names, from the same message; a name holding markup is
    // shown as text.
    let e = Estate::new("outside-page");
    application(&e);
    let code = e
        .home()
        .join("Library/Application Support/org.example.ledger/app");
    e.put(&code.join("main.js"), "start();\n");
    e.put(&code.join("other.js"), "other();\n");
    e.run();
    common::next_second();
    e.put(&code.join("main.js"), "start();\nsteal();\n");
    let forged = "<img src=x onerror=alert(1)>.js";
    e.put(&code.join(forged), "steal();\n");
    // A folder all of whose files are new is one entry, with its number of files.
    e.put(&code.join("vendor/a.js"), "a();\n");
    e.put(&code.join("vendor/b.js"), "b();\n");
    e.run();
    let id = id_of(&e, "integrity.app-code-outside");
    let files = &e.finding(&id)["evidence"]["changed_in_place"]["files"];
    assert_eq!((&files["added"], &files["changed"]), (&json!(3), &json!(1)));
    let text = e.text(&id);
    assert!(text.contains("app/main.js") && text.contains("\"app/vendor/\" (2 files)"));
    let page = e.pages();
    // Each kind's label once, on its first entry, as the text gives it.
    let mono = |path: &str| format!("<span class=\"mono\">{path}</span>");
    for (label, said) in [
        ("Added", mono("app/&lt;img src=x onerror=alert(1)&gt;.js")),
        (
            "",
            format!("{} <span class=\"w\">(2 files)</span>", mono("app/vendor/")),
        ),
        ("Changed", mono("app/main.js")),
    ] {
        let fact = format!("<dt>{label}</dt><dd>{said}</dd>");
        assert!(page.contains(&fact), "{fact}\n{page}");
    }
    assert!(!page.contains(forged));
    assert!(page.contains("3 added, 0 removed, 1 changed"), "{page}");
    assert!(!page.contains("Digest before"));
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

// ---- Startup items and the programs they run. ----

const AUTOSTART: &str = "watched.autostart";
const TARGET: &str = "watched.startup-target";
/// The signer the store reads of a copy of `/usr/bin/true`.
const TRUE_SIGNER: &str = "apple, identifier com.apple.true";

impl Estate {
    /// A launch agent of the home folder by its name, and where the findings say it is.
    fn agent(&self, name: &str) -> (PathBuf, String) {
        let rel = format!("Library/LaunchAgents/org.example.{name}.plist");
        (self.home().join(&rel), format!("~/{rel}"))
    }

    /// An invented launch item at `path` that starts `program`, written as XML text.
    fn launch_item(&self, path: &Path, program: &str) {
        let program = program
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        self.put(
            path,
            &format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
                 <key>Label</key><string>org.example.item</string><key>ProgramArguments</key>\
                 <array><string>{program}</string></array></dict></plist>\n"
            ),
        );
    }

    /// A copy of a program macOS ships at `path` from the system root.
    fn program(&self, path: &str) {
        let to = self.system().join(path.trim_start_matches('/'));
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy("/usr/bin/true", to).unwrap();
    }

    /// The id of the finding of `rule` whose place is `place`.
    fn id_at(&self, rule: &str, place: &str) -> String {
        let listed = self.json(&["findings"]);
        let f = (listed["findings"].as_array().unwrap().iter())
            .find(|f| f["finding"]["rule"] == rule && f["where_text"] == place)
            .unwrap_or_else(|| panic!("no {rule} at {place} in {listed:#}"));
        f["finding"]["id"].as_str().unwrap().to_string()
    }

    /// The journal's entries of the ties of the program at `path`, oldest first: what each did
    /// and its time.
    fn tie_entries(&self, path: &str) -> Vec<(String, i64)> {
        rusqlite::Connection::open(self.store())
            .unwrap()
            .prepare(
                "SELECT entry, at FROM journal WHERE predicate = 'started_by' AND subject = ?1
                 ORDER BY seq",
            )
            .unwrap()
            .query_map([format!("file:machine:mac/{path}")], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }
}

/// The ties of a finding's evidence, `runs` or `started_by`.
fn ties(whole: &Value, side: &str) -> Value {
    whole["evidence"]["place_changed"][side].clone()
}

#[test]
fn a_launch_agent_added_names_the_program_the_store_ties_to_it_in_force_with_its_signer() {
    let e = Estate::new("tie-added");
    e.run();
    common::next_second();
    e.program("/usr/local/bin/runner");
    let (agent, place) = e.agent("a");
    e.launch_item(&agent, "/usr/local/bin/runner");
    e.run();
    let id = e.id_at(AUTOSTART, &place);
    let whole = e.finding(&id);
    let added = e.tie_entries("/usr/local/bin/runner");
    assert_eq!(added.len(), 1, "{added:?}");
    assert_eq!(
        ties(&whole, "runs"),
        json!([{
            "path_text": "/usr/local/bin/runner",
            "state": "in_force",
            "recorded_at": added[0].1,
            "signed_by_text": TRUE_SIGNER,
        }])
    );
    assert_eq!(ties(&whole, "started_by"), json!([]));
    let text = e.text(&id);
    for line in [
        format!(
            "    Runs         held since the reading of {}: \"/usr/local/bin/runner\"\n",
            utc(added[0].1)
        ),
        format!("    Signer       {TRUE_SIGNER}\n"),
    ] {
        assert!(text.contains(&line), "{line}\n{text}");
    }
    let page = e.pages();
    for fact in [
        "<dt>Runs</dt><dd><span class=\"mono\">/usr/local/bin/runner</span> <span class=\"w\">held since the reading of</span> ".to_string(),
        format!("<dt>Signer</dt><dd><span class=\"mono\">{TRUE_SIGNER}</span></dd>"),
    ] {
        assert!(page.contains(&fact), "{fact}\n{page}");
    }
}

#[test]
fn a_login_hook_removed_names_the_script_the_store_last_tied_to_it_as_retracted_and_never_as_gone()
{
    let e = Estate::new("tie-hook");
    let prefs = e
        .system()
        .join("Library/Preferences/com.apple.loginwindow.plist");
    let login_window = |entries: &str| {
        e.put(
            &prefs,
            &format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>{entries}</dict></plist>\n"
            ),
        )
    };
    login_window("<key>GuestEnabled</key><false/>");
    e.program("/usr/local/bin/hook.sh");
    e.run();
    common::next_second();
    login_window("<key>LoginHook</key><string>/usr/local/bin/hook.sh</string>");
    e.run();
    common::next_second();
    login_window("<key>GuestEnabled</key><false/>");
    e.run();
    let place = "/Library/Preferences/com.apple.loginwindow.plist#/LoginHook";
    let id = e.id_at("watched.login-hook", place);
    let whole = e.finding(&id);
    assert_eq!(whole["evidence"]["place_changed"]["change"], "gone");
    let entries = e.tie_entries("/usr/local/bin/hook.sh");
    let removed = entries
        .iter()
        .find(|(entry, _)| entry == "removed")
        .unwrap()
        .1;
    let runs = ties(&whole, "runs");
    assert_eq!(runs.as_array().unwrap().len(), 1, "{runs:#}");
    assert_eq!(
        (
            &runs[0]["path_text"],
            &runs[0]["state"],
            &runs[0]["recorded_at"]
        ),
        (
            &json!("/usr/local/bin/hook.sh"),
            &json!("retracted"),
            &json!(removed)
        )
    );
    let text = e.text(&id);
    let line = format!(
        "    Runs         held until the reading of {}: \"/usr/local/bin/hook.sh\"\n",
        utc(removed)
    );
    assert!(text.contains(&line), "{line}\n{text}");
    // The script was not looked for: nothing says it is gone or that it is still there.
    for absent in ["gone", "no longer", "still", "now"] {
        let mut lines = text.lines().filter(|l| l.contains("hook.sh"));
        assert!(lines.all(|l| !l.contains(absent)), "{absent}\n{text}");
    }
    // Nor that the hook runs it: no line of the finding, its advice among them, says so.
    assert!(text.lines().all(|l| !l.contains("it runs")), "{text}");
    assert!(e.pages().contains(
        "<dd><span class=\"mono\">/usr/local/bin/hook.sh</span> <span class=\"w\">held until the reading of</span> "
    ));
}

#[test]
fn an_item_whose_reading_failed_or_was_set_aside_is_not_said_to_have_stopped_running_its_program() {
    let e = Estate::new("tie-unread");
    e.run();
    common::next_second();
    e.program("/usr/local/bin/runner");
    let (agent, place) = e.agent("a");
    e.launch_item(&agent, "/usr/local/bin/runner");
    e.run();
    let id = e.id_at(AUTOSTART, &place);
    let added = e.tie_entries("/usr/local/bin/runner")[0].1;
    // The item could not be read: the store keeps the tie as it was, in force since it was added.
    common::next_second();
    e.run_unreadable(&agent);
    let whole = e.finding(&id);
    assert_eq!(whole["evidence"]["place_changed"]["change"], "not_read");
    let runs = ties(&whole, "runs");
    assert_eq!(
        (
            &runs[0]["state"],
            &runs[0]["recorded_at"],
            runs.as_array().unwrap().len()
        ),
        (&json!("in_force"), &json!(added), 1)
    );
    // Its tie closed by a reading that did not read it, as this version closes what it no
    // longer reads: set aside, never held until then.
    common::next_second();
    std::fs::remove_file(&agent).unwrap();
    e.run();
    common::rewrite_journal(
        &e.store(),
        "UPDATE journal SET entry = 'retired', new_value = NULL
         WHERE predicate = 'started_by' AND entry = 'removed'",
    );
    let runs = ties(&e.finding(&id), "runs");
    assert_eq!(runs[0]["state"], "set_aside", "{runs:#}");
    let text = e.text(&id);
    assert!(
        text.contains("    Runs         set aside, not read again, by the reading of "),
        "{text}"
    );
    assert!(!text.contains("held until"), "{text}");
}

#[test]
fn a_startup_program_changed_names_every_item_that_runs_it_and_its_signer_before_and_after_and_nothing_else_moves()
 {
    let e = Estate::new("tie-target");
    e.program("/usr/local/bin/runner");
    let (a, a_place) = e.agent("a");
    let (b, b_place) = e.agent("b");
    e.launch_item(&a, "/usr/local/bin/runner");
    e.launch_item(&b, "/usr/local/bin/runner");
    e.run();
    common::next_second();
    e.run();
    common::next_second();
    e.put(
        &e.system().join("usr/local/bin/runner"),
        "#!/bin/sh\nexit 0\n",
    );
    e.run();
    let id = e.id_at(TARGET, "/usr/local/bin/runner");
    let whole = e.finding(&id);
    let added = e.tie_entries("/usr/local/bin/runner")[0].1;
    let signed = latest_entry(&whole, "changed", Some("signed_by"));
    let tie = |place: &str| json!({ "path_text": place, "state": "in_force", "recorded_at": added, "signed_by_text": null });
    assert_eq!(
        ties(&whole, "started_by"),
        json!([tie(&a_place), tie(&b_place)])
    );
    assert_eq!(ties(&whole, "runs"), json!([]));
    let text = e.text(&id);
    for line in [
        format!(
            "    Run by       held since the reading of {}: \"{a_place}\"\n",
            utc(added)
        ),
        format!(
            "    Run by       held since the reading of {}: \"{b_place}\"\n",
            utc(added)
        ),
        format!(
            "    Signer       until the reading of {}: \"{TRUE_SIGNER}\"\n",
            utc(signed)
        ),
        format!(
            "                 from the reading of {}: \"unsigned\"\n",
            utc(signed)
        ),
    ] {
        assert!(text.contains(&line), "{line}\n{text}");
    }
    let page = e.pages();
    for fact in [
        format!("<dt>Signer before</dt><dd><span class=\"mono\">{TRUE_SIGNER}</span> <span class=\"w\">until the reading of</span> "),
        "<dt>Signer after</dt><dd><span class=\"mono\">unsigned</span> <span class=\"w\">from the reading of</span> ".to_string(),
        format!("<dt>Run by</dt><dd><span class=\"mono\">{b_place}</span> "),
    ] {
        assert!(page.contains(&fact), "{fact}\n{page}");
    }

    // One item no longer runs it: the finding names the other alone, and its state, levels,
    // words and place in the list are as they were.
    let listed = |e: &Estate| {
        let all = e.json(&["findings"]);
        let all = all["findings"].as_array().unwrap().clone();
        let at = (all.iter())
            .position(|f| f["finding"]["id"] == json!(id))
            .unwrap();
        (all[at].clone(), at)
    };
    let before = (listed(&e), whole["finding"].clone(), whole["title"].clone());
    common::next_second();
    std::fs::remove_file(&b).unwrap();
    e.run();
    let again = e.finding(&id);
    assert_eq!(ties(&again, "started_by"), json!([tie(&a_place)]));
    // The removed item's own finding is listed before it, as the newest.
    let after = listed(&e);
    assert_eq!((&after.0, after.1), (&before.0.0, before.0.1 + 1));
    assert_eq!((&again["finding"], &again["title"]), (&before.1, &before.2));
}

#[test]
fn a_program_two_items_run_shows_on_each_item_s_finding_its_own_tie_only() {
    let e = Estate::new("tie-two");
    e.run();
    common::next_second();
    e.program("/usr/local/bin/runner");
    let (a, a_place) = e.agent("a");
    let (b, b_place) = e.agent("b");
    e.launch_item(&a, "/usr/local/bin/runner");
    e.run();
    common::next_second();
    e.launch_item(&b, "/usr/local/bin/runner");
    e.run();
    common::next_second();
    std::fs::remove_file(&b).unwrap();
    e.run();
    let entries = e.tie_entries("/usr/local/bin/runner");
    assert_eq!(entries.len(), 3, "{entries:?}");
    let runs = |place: &str| ties(&e.finding(&e.id_at(AUTOSTART, place)), "runs");
    let tie = |state: &str, at: i64| json!([{ "path_text": "/usr/local/bin/runner", "state": state, "recorded_at": at, "signed_by_text": TRUE_SIGNER }]);
    assert_eq!(runs(&a_place), tie("in_force", entries[0].1));
    assert_eq!(runs(&b_place), tie("retracted", entries[2].1));
}

#[test]
fn a_program_path_holding_markup_or_a_line_read_as_an_instruction_is_shown_as_data() {
    let e = Estate::new("tie-markup");
    e.run();
    common::next_second();
    let program =
        "/usr/local/bin/<img src=x onerror=alert(1)>\n→ immunity finding f0000000000 seen";
    e.program(program);
    let (agent, place) = e.agent("a");
    e.launch_item(&agent, program);
    e.run();
    let id = e.id_at(AUTOSTART, &place);
    let shown = ties(&e.finding(&id), "runs")[0]["path_text"].clone();
    let shown = shown.as_str().unwrap();
    assert!(
        shown.starts_with("/usr/local/bin/<img src=x onerror=alert(1)>") && !shown.contains('\n'),
        "{shown}"
    );
    let text = e.text(&id);
    assert!(text.contains("onerror"), "{text}");
    for line in text.lines() {
        assert!(
            !line.starts_with("→ immunity finding f0000000000"),
            "{text}"
        );
        assert!(!line.contains("onerror") || line.starts_with(' '), "{text}");
    }
    let page = e.pages();
    assert!(
        page.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "{page}"
    );
    assert!(!page.contains("<img src=x"), "{page}");
}
