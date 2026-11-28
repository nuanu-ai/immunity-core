//! What a finding from a published rule keeps of the file events it rests on.

use super::*;

/// The program, its signing id, its team id and whether it is a platform binary.
type Signed = (String, Option<String>, Option<String>, Option<bool>);

#[test]
fn a_finding_about_a_file_keeps_who_signed_the_program_that_wrote_it_as_the_line_gave_it() {
    // Two programs create the same file a published rule fires on, one signed by a team and one
    // of Apple's that names none: each is kept with its signing id, team id and platform flag.
    let dir = crate::common::Scratch::at(
        std::env::temp_dir().join(format!("immunity-events-signer-{}", std::process::id())),
    );
    let log = dir.join("root").join(LOG);
    std::fs::create_dir_all(&log).unwrap();
    let plist = dir.join("root").join(PLIST);
    std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
    std::fs::write(&plist, "<plist/>").unwrap();
    let by = |seq: u64, program: &str, signer: &str| {
        created(seq, "/Users/example/.helper").replace(
            r#"{"executable":{"path":"/usr/bin/curl"}}"#,
            &format!(
                r#"{{"executable":{{"path":"{program}"}},"audit_token":{{"pid":{seq},"pidversion":9}},"start_time":"2026-10-04T00:00:02.5Z",{signer},"codesigning_flags":570522385}}"#
            ),
        )
    };
    let lines = [
        by(
            1,
            "/Users/example/Downloads/curl",
            r#""signing_id":"com.example.helper","team_id":"EXAMPLE123","is_platform_binary":false"#,
        ),
        by(
            2,
            "/usr/bin/curl",
            r#""signing_id":"com.apple.curl","team_id":null,"is_platform_binary":true"#,
        ),
    ];
    std::fs::write(log.join("exec-20261004T00.jsonl"), lines.join("\n") + "\n").unwrap();
    let mut conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
    let tx = conn.transaction().unwrap();
    crate::store::put_entity(&tx, "machine:mac").unwrap();
    read(
        &tx,
        "events-1",
        "machine:mac",
        &dir.join("root"),
        1_791_000_000,
    )
    .unwrap();
    tx.commit().unwrap();
    let kept: Vec<Signed> = conn
        .prepare(
            "SELECT executable, signing_id, team_id, platform_binary FROM rule_file_evidence
             ORDER BY rowid",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let signed = |program: &str, id: &str, team: Option<&str>, platform| {
        let team = team.map(str::to_string);
        (
            program.to_string(),
            Some(id.to_string()),
            team,
            Some(platform),
        )
    };
    assert_eq!(
        kept,
        [
            signed(
                "/Users/example/Downloads/curl",
                "com.example.helper",
                Some("EXAMPLE123"),
                false
            ),
            signed("/usr/bin/curl", "com.apple.curl", None, true),
        ]
    );
}
