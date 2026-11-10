mod support;

use std::collections::{BTreeMap, BTreeSet};

use support::{fixture, fixture_files, fixture_text, hex_encode, parse_json, sha256};

const SOURCE_FILES: &[(&str, &str)] = &[
    (
        "README.md",
        "8b939f4d7885e4248115c761c47ed78cc292e466455977beba3b5ffad13f898b",
    ),
    (
        "routes.json",
        "8d13873daa0f0a681f3b99ff579fb1d8f78310862a26d3a64d4f252ac6860c84",
    ),
    (
        "schemas/common.schema.json",
        "b4e1dde01230629a4dbf78bdddd32cdd95ccb6c0ff5cef565046c70321b1a6d6",
    ),
    (
        "schemas/control-api.schema.json",
        "ba240db28b8c63b7e9206bd058d5845fccf5b9874f11cddccc2f0294ca788464",
    ),
    (
        "schemas/mqtt-v2.schema.json",
        "30aac4d0fd1b9d04ae03246012a47a4e0fc71f002807055511b33e6d1648e8c4",
    ),
    (
        "schemas/problem.schema.json",
        "8ee8bd525dec6466125f60fcf637b309630f887d695e596ecf1dfb9081184000",
    ),
    (
        "schemas/reporter-api.schema.json",
        "116ac61346e0e43d908be956be6acc9f4b11081b56dc19e38aafa97ac11e8c56",
    ),
    (
        "schemas/vector.schema.json",
        "df06128903e3a60e9792031471588966a6646c67d3c324eb824ebeb9a8466cf5",
    ),
    (
        "threat-model.md",
        "da31a0c1b516dc53dd6eb9a3f986405afce1599fa19a35daf8a921c28cf82d1f",
    ),
    (
        "vectors/common.json",
        "7e8262fa26ed3ee7ce7f13558b8ceaf5b42e3182204693206143295ceaca7150",
    ),
    (
        "vectors/control-bootstrap-recovery.json",
        "941eba8898ccbdaf4b51e4f6c23a40d82e3c8c375b9acc7df4d5065281621d38",
    ),
    (
        "vectors/http-signatures.json",
        "75149ef360bfe9e116f93756727f9fca4266a643fe6ee8bb6e7432326b6c4ed6",
    ),
    (
        "vectors/interactive-enrollment.json",
        "1d19b6a1aa3bc7226165682fd7f831a0cc9f7b5b6b5ebae6b993b9aa6422f36d",
    ),
    (
        "vectors/key-rotations.json",
        "40e672058799b924edff5c3316e2be541dc6aef00b17e0bcf5125a5148fcef3a",
    ),
    (
        "vectors/managed-enrollment.json",
        "cecb3a8f55e7a8ac6283d00f1abb5b364cf83cb0a952c67a07b5183c87bb4cd9",
    ),
    (
        "vectors/managed-token-control.json",
        "850fe3e3867b364de98c99fcaeae61375623f434ebbc7a24e33d0f4d1dd5cad9",
    ),
    (
        "vectors/manifest.json",
        "08b06d20d6463c5f805cd2a584d86ebd170a140360d7e32b14121c74eddf6490",
    ),
    (
        "vectors/mqtt-v2-aead.json",
        "452a45eac40fb31d516cc4b2d981d0be952faffa7862bbdf0ff4d4063527203f",
    ),
    (
        "wire-profile.md",
        "6b0aa172a6b7825408c421015ecb6bb18ce0d9242cd7144c0ebed233cc09c41e",
    ),
];

#[test]
fn vendored_protocol_corpus_has_exact_pinned_file_set_and_bytes() {
    let expected: BTreeSet<_> = SOURCE_FILES
        .iter()
        .map(|(path, _)| (*path).to_owned())
        .chain(["PROVENANCE.txt".to_owned()])
        .collect();
    assert_eq!(
        fixture_files().into_iter().collect::<BTreeSet<_>>(),
        expected
    );

    for (path, expected_sha256) in SOURCE_FILES {
        assert_eq!(
            hex_encode(&sha256(&fixture(path))),
            *expected_sha256,
            "vendored bytes changed for {path}"
        );
    }
}

#[test]
fn provenance_pins_the_server_owned_profile_without_local_installation_data() {
    assert_eq!(
        fixture_text("PROVENANCE.txt"),
        concat!(
            "source_repository: superkus/remote_energy_meter\n",
            "source_path: docs/protocol/v1\n",
            "profile_version: 1\n",
            "source_commit: ad4fb43b413d2e27ad842d3a790aa8ecd8dcf103\n",
        )
    );
}

#[test]
fn manifest_metadata_file_checksums_and_case_sets_are_complete() {
    let manifest = parse_json(&fixture("vectors/manifest.json"));
    assert_eq!(manifest.member("schema").string(), "rem-vector-manifest-v1");
    assert_eq!(
        manifest.member("profile_version"),
        &support::Json::Number("1".into())
    );
    assert_eq!(manifest.member("source_of_truth").string(), "server-owned");
    assert_eq!(
        manifest.member("source_repository").string(),
        "superkus/remote_energy_meter"
    );
    assert_eq!(manifest.member("profile_path").string(), "docs/protocol/v1");
    assert_eq!(manifest.member("checksum_algorithm").string(), "sha256");

    let expected_cases: BTreeMap<&str, &[&str]> = BTreeMap::from([
        (
            "common.json",
            &[
                "common.transcript-encoding",
                "common.jwk-thumbprint",
                "common.content-digest",
                "common.server-identity",
                "common.problem-response",
                "common.roster-snapshot-digest",
                "common.operation-digest",
            ] as &[_],
        ),
        (
            "http-signatures.json",
            &[
                "http.route.reporter.enrollment.create",
                "http.route.reporter.enrollment.create.managed",
                "http.route.reporter.enrollment.reveal",
                "http.route.reporter.enrollment.confirm",
                "http.route.reporter.enrollment.status",
                "http.route.reporter.challenge.create",
                "http.route.reporter.session.create",
                "http.reporter-signature",
                "http.route.reporter.key-rotation-challenge.create",
                "http.route.reporter.key-rotation.complete",
                "http.route.control.managed-token.issue",
                "http.route.control.managed-token.status",
                "http.route.control.managed-token.revoke",
                "http.route.control.roster.events",
                "http.route.control.roster.snapshot",
                "http.route.control.roster.snapshot.continuation",
                "http.route.control.reporter.action",
                "http.route.control.reporter-key-rotation.confirm",
                "http.route.control.control-key-rotation-challenge.create",
                "http.route.control.control-spki-rotation",
                "http.route.control.control-spki-rotation.confirm",
                "http.route.control.mqtt-key.provision",
                "http.route.control.mqtt-key.acknowledge",
                "http.control-signature",
            ],
        ),
        (
            "interactive-enrollment.json",
            &["interactive.commitments", "interactive.sas"],
        ),
        ("managed-enrollment.json", &["managed.proof"]),
        (
            "control-bootstrap-recovery.json",
            &[
                "bootstrap.commit-reveal-confirm",
                "recovery.commit-reveal-revoke",
            ],
        ),
        (
            "key-rotations.json",
            &[
                "rotation.reporter",
                "rotation.control-key",
                "rotation.control-spki",
            ],
        ),
        (
            "managed-token-control.json",
            &["managed-token.issue-status-revoke"],
        ),
        (
            "mqtt-v2-aead.json",
            &[
                "mqtt.key-provision",
                "mqtt.key-acknowledge",
                "mqtt.aead-envelope",
                "mqtt.process-offline-will",
            ],
        ),
    ]);

    let entries = manifest.member("files").array();
    assert_eq!(entries.len(), expected_cases.len());
    for entry in entries {
        let file = entry.member("file").string();
        let expected_ids = expected_cases
            .get(file)
            .unwrap_or_else(|| panic!("unexpected manifest vector {file}"));
        let actual_ids: Vec<_> = entry
            .member("case_ids")
            .array()
            .iter()
            .map(support::Json::string)
            .collect();
        assert_eq!(
            &actual_ids, expected_ids,
            "manifest case order changed for {file}"
        );
        assert_eq!(
            hex_encode(&sha256(&fixture(&format!("vectors/{file}")))),
            entry.member("sha256").string(),
            "manifest checksum mismatch for {file}"
        );

        let vector = parse_json(&fixture(&format!("vectors/{file}")));
        let file_ids: Vec<_> = vector
            .member("cases")
            .array()
            .iter()
            .map(|case| case.member("id").string())
            .collect();
        assert_eq!(
            file_ids, actual_ids,
            "manifest does not consume every case in {file}"
        );
    }

    let contracts = manifest.member("contract_files").array();
    assert_eq!(contracts.len(), 8);
    for entry in contracts {
        let path = entry.member("path").string();
        assert_eq!(
            hex_encode(&sha256(&fixture(path))),
            entry.member("sha256").string(),
            "manifest checksum mismatch for {path}"
        );
    }
}

#[test]
fn vector_consumption_accounting_fixes_every_case_and_mutation_count() {
    let expected = [
        ("common.json", 7, 38),
        ("control-bootstrap-recovery.json", 2, 51),
        ("http-signatures.json", 24, 466),
        ("interactive-enrollment.json", 2, 27),
        ("key-rotations.json", 3, 97),
        ("managed-enrollment.json", 1, 22),
        ("managed-token-control.json", 1, 12),
        ("mqtt-v2-aead.json", 4, 66),
    ];
    let mut total_cases = 0;
    let mut total_mutations = 0;
    let mut mutation_ids = BTreeSet::new();

    for (file, expected_case_count, expected_mutation_count) in expected {
        let vector = parse_json(&fixture(&format!("vectors/{file}")));
        let cases = vector.member("cases").array();
        let mutation_count: usize = cases
            .iter()
            .map(|case| case.member("mutations").array().len())
            .sum();
        assert_eq!(
            cases.len(),
            expected_case_count,
            "unaccounted case in {file}"
        );
        assert_eq!(
            mutation_count, expected_mutation_count,
            "unaccounted mutation in {file}"
        );
        for mutation in cases
            .iter()
            .flat_map(|case| case.member("mutations").array())
        {
            assert!(
                mutation_ids.insert(mutation.member("id").string().to_owned()),
                "duplicate mutation id"
            );
        }
        total_cases += cases.len();
        total_mutations += mutation_count;
    }

    assert_eq!(total_cases, 44);
    assert_eq!(total_mutations, 779);
    assert_eq!(mutation_ids.len(), 779);
}
