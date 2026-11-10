mod support;

use std::collections::BTreeSet;

use remote_energy_meter_reporter::protocol_v1::content_digest::CONTENT_DIGEST_HEADER_MAX_BYTES;
use remote_energy_meter_reporter::protocol_v1::routes::{
    HEADER_BYTES_MAX, HEADER_COUNT_MAX, PROBLEM_RESPONSE_MAX_BYTES, REQUEST_TARGET_MAX_BYTES,
    ROUTES, SIGNATURE_HEADER_MAX_BYTES, SIGNATURE_INPUT_HEADER_MAX_BYTES, Surface, TrustState,
};
use support::{Json, fixture, parse_json};

fn number(value: &Json) -> usize {
    match value {
        Json::Number(text) => text.parse().expect("manifest integer"),
        _ => panic!("expected manifest integer"),
    }
}

fn optional_string(value: &Json) -> Option<&str> {
    match value {
        Json::Null => None,
        other => Some(other.string()),
    }
}

#[test]
fn compiled_route_table_matches_every_in_scope_vendored_manifest_field() {
    let manifest = parse_json(&fixture("routes.json"));
    assert_eq!(manifest.member("schema").string(), "rem-route-manifest-v1");
    assert_eq!(number(manifest.member("profile_version")), 1);

    let limits = manifest.member("limits");
    let expected_limits = [
        ("request_target_max_bytes", REQUEST_TARGET_MAX_BYTES),
        ("header_count_max", HEADER_COUNT_MAX),
        ("header_bytes_max", HEADER_BYTES_MAX),
        ("signature_header_max_bytes", SIGNATURE_HEADER_MAX_BYTES),
        (
            "signature_input_header_max_bytes",
            SIGNATURE_INPUT_HEADER_MAX_BYTES,
        ),
        (
            "content_digest_header_max_bytes",
            CONTENT_DIGEST_HEADER_MAX_BYTES,
        ),
        ("problem_response_max_bytes", PROBLEM_RESPONSE_MAX_BYTES),
    ];
    assert_eq!(limits.object().len(), expected_limits.len());
    for (name, value) in expected_limits {
        assert_eq!(number(limits.member(name)), value, "limit {name}");
    }

    let routes = manifest.member("routes").array();
    assert_eq!(routes.len(), ROUTES.len());
    let manifest_fields: BTreeSet<_> = [
        "id",
        "surface",
        "trust_state",
        "method",
        "path_template",
        "query_forms",
        "request_body_max_bytes",
        "success_body_max_bytes",
        "success_item_maximum",
        "success_status",
        "purpose",
        "request_schema",
        "response_schema",
        "signature_profile",
        "replay_rule",
    ]
    .into_iter()
    .collect();
    for (entry, route) in routes.iter().zip(ROUTES) {
        assert_eq!(
            entry
                .object()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            manifest_fields,
            "route manifest fields changed"
        );
        // Schema enforcement and stateful replay are later tasks, but account for their manifest
        // fields explicitly so this parity test cannot silently overlook a new route field.
        assert!(matches!(
            entry.member("request_schema"),
            Json::Null | Json::String(_)
        ));
        assert!(!entry.member("response_schema").string().is_empty());
        assert!(!entry.member("replay_rule").string().is_empty());
        let id = entry.member("id").string();
        assert_eq!(route.id(), id);
        let surface = match entry.member("surface").string() {
            "reporter" => Surface::Reporter,
            "control" => Surface::Control,
            other => panic!("unknown surface {other}"),
        };
        assert_eq!(route.surface(), surface, "{id} surface");
        let trust_state = match entry.member("trust_state").string() {
            "pre-enrollment" => TrustState::PreEnrollment,
            "server-authenticated" => TrustState::ServerAuthenticated,
            "enrolled-reporter" => TrustState::EnrolledReporter,
            "provisional-control" => TrustState::ProvisionalControl,
            "post-pair" => TrustState::PostPair,
            other => panic!("unknown trust state {other}"),
        };
        assert_eq!(route.trust_state(), trust_state, "{id} trust state");
        assert_eq!(route.method(), entry.member("method").string(), "{id}");
        assert_eq!(
            route.path_template(),
            entry.member("path_template").string(),
            "{id}"
        );
        let forms: Vec<_> = entry
            .member("query_forms")
            .array()
            .iter()
            .map(Json::string)
            .collect();
        assert_eq!(route.query_forms(), forms.as_slice(), "{id} query forms");
        assert_eq!(
            route.request_body_max_bytes(),
            number(entry.member("request_body_max_bytes")),
            "{id}"
        );
        assert_eq!(
            route.success_body_max_bytes(),
            number(entry.member("success_body_max_bytes")),
            "{id}"
        );
        let items = match entry.member("success_item_maximum") {
            Json::Null => None,
            value => Some(number(value)),
        };
        assert_eq!(route.success_item_maximum(), items, "{id}");
        assert_eq!(
            usize::from(route.success_status()),
            number(entry.member("success_status")),
            "{id}"
        );
        assert_eq!(route.purpose(), entry.member("purpose").string(), "{id}");
        assert_eq!(
            route.signature_profile().map(|profile| profile.name()),
            optional_string(entry.member("signature_profile")),
            "{id} profile"
        );
    }
}
