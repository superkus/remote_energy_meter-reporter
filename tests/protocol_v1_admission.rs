//! Signer round trips, the dual-label route, and admission checks the vectors do not mutate.
//!
//! Test signing keys are generated ephemerally in memory and are never serialized.

mod support;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use remote_energy_meter_reporter::protocol_v1::{
    ErrorClass,
    b64u::B64u,
    content_digest::ContentDigest,
    http_signature::{
        HeaderField, RawRequest, VerificationContext, VerificationKey, render_signature,
        render_signature_input, signature_material, verify_request,
    },
    jwk::P256PublicJwk,
    routes::{SIGNATURE_HEADER_MAX_BYTES, lookup_route},
};
use support::{Json, fixture, named_value, parse_json, vector_case};

fn output<'a>(case: &'a Json, name: &str) -> &'a str {
    case.member("expected")
        .member("outputs")
        .array()
        .iter()
        .find(|item| item.member("name").string() == name)
        .unwrap_or_else(|| panic!("missing output {name}"))
        .member("value")
        .string()
}

/// The vector request without its signature headers, and its verification context.
fn unsigned_vector(id: &str) -> (RawRequest, VerificationContext, Json) {
    let set = parse_json(&fixture("vectors/http-signatures.json"));
    let case = vector_case(&set, id).clone();
    let inputs: Vec<(String, String)> = case
        .member("inputs")
        .array()
        .iter()
        .map(|item| {
            (
                item.member("name").string().to_owned(),
                item.member("value").string().to_owned(),
            )
        })
        .collect();
    let input = |name: &str| {
        inputs
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.clone())
    };
    let headers = inputs
        .iter()
        .filter_map(|(name, value)| {
            name.strip_prefix("headers.").map(|name| HeaderField {
                name: name.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            })
        })
        .collect();
    let generation =
        input("headers.rem-control-key-generation").map(|value| value.parse().unwrap());
    let created = output(&case, "headers.signature-input")
        .split(";created=")
        .nth(1)
        .and_then(|tail| tail.split(';').next())
        .map(|value| value.parse::<u64>().unwrap());
    let request = RawRequest {
        method: input("request.method").unwrap().into_bytes(),
        authority: input("request.authority").unwrap().into_bytes(),
        target: input("request.target").unwrap().into_bytes(),
        headers,
        body: input("body").unwrap_or_default().into_bytes(),
    };
    let context = VerificationContext {
        expected_route_id: lookup_route(&request.method, &request.target).unwrap().id(),
        expected_authority: request.authority.clone(),
        received_at: created.unwrap_or(0),
        keys: vec![VerificationKey {
            stable_principal_id: B64u::<32>::parse(&input("keyid.rem").unwrap()).unwrap(),
            label: b"rem".to_vec(),
            jwk: P256PublicJwk::parse_exact(input("jwk.rem").unwrap().as_bytes()).unwrap(),
            generation,
        }],
    };
    (request, context, case)
}

fn signed_vector(id: &str) -> (RawRequest, VerificationContext) {
    let (mut request, context, case) = unsigned_vector(id);
    for name in ["signature-input", "signature"] {
        request.headers.push(HeaderField {
            name: name.as_bytes().to_vec(),
            value: output(&case, &format!("headers.{name}"))
                .as_bytes()
                .to_vec(),
        });
    }
    (request, context)
}

fn header(request: &mut RawRequest, name: &str, value: &str) {
    match request
        .headers
        .iter_mut()
        .find(|field| field.name == name.as_bytes())
    {
        Some(field) => field.value = value.as_bytes().to_vec(),
        None => request.headers.push(HeaderField {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        }),
    }
}

fn remove_header(request: &mut RawRequest, name: &str) {
    request
        .headers
        .retain(|field| field.name != name.as_bytes());
}

fn rejects(request: &RawRequest, context: &VerificationContext, expected: ErrorClass) {
    assert_eq!(verify_request(request, context).unwrap_err(), expected);
}

fn test_key() -> SigningKey {
    SigningKey::try_generate().expect("system CSPRNG is available for protocol tests")
}

fn jwk_of(key: &SigningKey) -> P256PublicJwk {
    P256PublicJwk::from_verifying_key(key.verifying_key())
}

fn low_s_p1363(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let signature: Signature = key.sign(message);
    signature.normalize_s().to_bytes().into()
}

/// Sign `request` with `(label, key)` members in order, replacing any signature headers.
fn sign(request: &mut RawRequest, members: &[(&str, &SigningKey)], created: u64) {
    remove_header(request, "signature-input");
    remove_header(request, "signature");
    let created = request
        .headers
        .iter()
        .any(|field| field.name == b"rem-control-key-generation")
        .then_some(created);
    let materials: Vec<_> = members
        .iter()
        .map(|(label, key)| {
            signature_material(request, label, jwk_of(key).thumbprint_b64u(), created).unwrap()
        })
        .collect();
    let signatures: Vec<_> = members
        .iter()
        .zip(&materials)
        .map(|((_, key), material)| low_s_p1363(key, material.signature_base()))
        .collect();
    let input: Vec<_> = members
        .iter()
        .zip(&materials)
        .map(|((label, _), material)| (*label, material))
        .collect();
    let signature: Vec<_> = members
        .iter()
        .zip(&signatures)
        .map(|((label, _), signature)| (*label, signature))
        .collect();
    header(request, "signature-input", &render_signature_input(&input));
    header(request, "signature", &render_signature(&signature));
}

#[test]
fn signer_reproduces_every_vector_signature_input_and_base_byte_for_byte() {
    let set = parse_json(&fixture("vectors/http-signatures.json"));
    for case in set.member("cases").array() {
        let id = case.member("id").string();
        let (request, context, case) = unsigned_vector(id);
        let keyid = B64u::<32>::parse(named_value(&case, "inputs", "keyid.rem")).unwrap();
        let created = output(&case, "headers.signature-input")
            .contains(";created=")
            .then_some(context.received_at);
        let material = signature_material(&request, "rem", &keyid, created).unwrap();
        assert_eq!(
            render_signature_input(&[("rem", &material)]),
            output(&case, "headers.signature-input"),
            "{id}"
        );
        assert_eq!(
            material.signature_base(),
            named_value(&case, "intermediates", "signature-base.rem").as_bytes(),
            "{id}"
        );
        assert_eq!(
            material.signature_params(),
            named_value(&case, "intermediates", "signature-params.rem"),
            "{id}"
        );
    }
}

#[test]
fn signer_requires_time_only_for_control_profile() {
    let (reporter, _, reporter_case) = unsigned_vector("http.reporter-signature");
    let reporter_keyid =
        B64u::<32>::parse(named_value(&reporter_case, "inputs", "keyid.rem")).unwrap();
    assert_eq!(
        signature_material(&reporter, "rem", &reporter_keyid, Some(0)).unwrap_err(),
        ErrorClass::AuthenticationRequired
    );
    assert!(signature_material(&reporter, "rem", &reporter_keyid, None).is_ok());

    let (control, context, control_case) = unsigned_vector("http.control-signature");
    let control_keyid =
        B64u::<32>::parse(named_value(&control_case, "inputs", "keyid.rem")).unwrap();
    assert_eq!(
        signature_material(&control, "rem", &control_keyid, None).unwrap_err(),
        ErrorClass::AuthenticationRequired
    );
    assert!(signature_material(&control, "rem", &control_keyid, Some(context.received_at)).is_ok());
}

fn dual_signature_request() -> (RawRequest, VerificationContext, SigningKey, SigningKey) {
    let current = test_key();
    let proposed = test_key();
    let body = br#"{"schema_version":1}"#.to_vec();
    let created = 1_767_226_600;
    let mut request = RawRequest {
        method: b"POST".to_vec(),
        authority: b"control.example.com:8444".to_vec(),
        target: b"/control/v1/control-keys/rotations".to_vec(),
        headers: Vec::new(),
        body,
    };
    header(&mut request, "rem-purpose", "rem-control-key-rotation-v1");
    header(&mut request, "rem-control-key-generation", "1");
    header(&mut request, "rem-request-nonce", "IyMjIyMjIyMjIyMjIyMjIw");
    header(
        &mut request,
        "rem-request-expires",
        &(created + 60).to_string(),
    );
    header(&mut request, "content-type", "application/json");
    let digest = ContentDigest::for_body(&request.body).render();
    header(&mut request, "content-digest", &digest);
    sign(
        &mut request,
        &[("rem", &current), ("rem-proposed", &proposed)],
        created,
    );
    let context = VerificationContext {
        expected_route_id: "control.control-key-rotation.complete",
        expected_authority: request.authority.clone(),
        received_at: created,
        keys: vec![
            VerificationKey {
                stable_principal_id: jwk_of(&current).thumbprint_b64u().clone(),
                label: b"rem".to_vec(),
                jwk: jwk_of(&current),
                generation: Some(1),
            },
            VerificationKey {
                stable_principal_id: jwk_of(&current).thumbprint_b64u().clone(),
                label: b"rem-proposed".to_vec(),
                jwk: jwk_of(&proposed),
                generation: Some(2),
            },
        ],
    };
    (request, context, current, proposed)
}

#[test]
fn dual_label_route_requires_both_signatures_in_order() {
    let (request, context, current, proposed) = dual_signature_request();
    let verified = verify_request(&request, &context).unwrap();
    assert_eq!(
        verified.identity().route_id(),
        "control.control-key-rotation.complete"
    );
    assert_eq!(
        verified.identity().keyid(),
        jwk_of(&current).thumbprint_b64u().as_str().as_bytes()
    );
    assert_eq!(
        verified.identity().proposed_keyid(),
        Some(jwk_of(&proposed).thumbprint_b64u().as_str().as_bytes())
    );
    let rem = verified.signature_base("rem").unwrap();
    let rem_proposed = verified.signature_base("rem-proposed").unwrap();
    assert_ne!(rem, rem_proposed, "bases differ only by keyid");

    let auth = ErrorClass::AuthenticationRequired;
    let mut only_rem = request.clone();
    sign(&mut only_rem, &[("rem", &current)], context.received_at);
    rejects(&only_rem, &context, auth);

    let mut same_key = request.clone();
    sign(
        &mut same_key,
        &[("rem", &current), ("rem-proposed", &current)],
        context.received_at,
    );
    let mut same_context = context.clone();
    same_context.keys[1].jwk = jwk_of(&current);
    rejects(&same_key, &same_context, auth);

    let mut wrong_proposed = context.clone();
    wrong_proposed.keys[1].jwk = jwk_of(&test_key());
    rejects(&request, &wrong_proposed, auth);

    let mut missing_proposed_key = context.clone();
    missing_proposed_key.keys.pop();
    rejects(&request, &missing_proposed_key, auth);

    let mut duplicate_key = context.clone();
    duplicate_key.keys.push(duplicate_key.keys[0].clone());
    rejects(&request, &duplicate_key, auth);

    let mut cross_principal = context.clone();
    cross_principal.keys[1].stable_principal_id = B64u::<32>::from_bytes([0; 32]);
    rejects(&request, &cross_principal, auth);

    for name in ["signature-input", "signature"] {
        let mut swapped = request.clone();
        let field = swapped
            .headers
            .iter_mut()
            .find(|field| field.name == name.as_bytes())
            .unwrap();
        let text = String::from_utf8(field.value.clone()).unwrap();
        let (first, second) = text.split_once(", ").unwrap();
        field.value = format!("{second}, {first}").into_bytes();
        rejects(&swapped, &context, auth);
    }

    let mut proposed_created = request.clone();
    let field = proposed_created
        .headers
        .iter_mut()
        .find(|field| field.name == b"signature-input")
        .unwrap();
    let text = String::from_utf8(field.value.clone()).unwrap();
    let (first, second) = text.split_once(", ").unwrap();
    field.value = format!(
        "{first}, {}",
        second.replace(";created=1767226600", ";created=1767226601")
    )
    .into_bytes();
    rejects(&proposed_created, &context, auth);
}

#[test]
fn rem_proposed_is_rejected_on_every_other_route() {
    let (mut request, mut context) = signed_vector("http.control-signature");
    let current = test_key();
    let proposed = test_key();
    context.keys = vec![
        VerificationKey {
            stable_principal_id: jwk_of(&current).thumbprint_b64u().clone(),
            label: b"rem".to_vec(),
            jwk: jwk_of(&current),
            generation: Some(1),
        },
        VerificationKey {
            stable_principal_id: jwk_of(&current).thumbprint_b64u().clone(),
            label: b"rem-proposed".to_vec(),
            jwk: jwk_of(&proposed),
            generation: Some(2),
        },
    ];
    sign(&mut request, &[("rem", &current)], context.received_at);
    assert!(verify_request(&request, &context).is_ok());
    let keyid = jwk_of(&proposed);
    assert_eq!(
        signature_material(
            &request,
            "rem-proposed",
            keyid.thumbprint_b64u(),
            Some(context.received_at)
        )
        .unwrap_err(),
        ErrorClass::AuthenticationRequired
    );
    let rem_input = String::from_utf8(
        request
            .headers
            .iter()
            .find(|field| field.name == b"signature-input")
            .unwrap()
            .value
            .clone(),
    )
    .unwrap();
    let proposed_member = rem_input.replacen("rem=", "rem-proposed=", 1);
    header(
        &mut request,
        "signature-input",
        &format!("{rem_input}, {proposed_member}"),
    );
    rejects(&request, &context, ErrorClass::AuthenticationRequired);
}

#[test]
fn control_freshness_uses_server_receipt_time() {
    let (request, mut context) = signed_vector("http.control-signature");
    let created = context.received_at;
    let auth = ErrorClass::AuthenticationRequired;
    for (received_at, accepted) in [
        (created - 30, true),
        (created - 31, false),
        (created + 60, true),
        (created + 61, false),
    ] {
        context.received_at = received_at;
        assert_eq!(
            verify_request(&request, &context).is_ok(),
            accepted,
            "receipt at created{:+}",
            i128::from(received_at) - i128::from(created)
        );
    }
    context.received_at = created;
    context.keys[0].generation = None;
    rejects(&request, &context, auth);

    let (mut near_max, mut near_max_context, current, proposed) = dual_signature_request();
    header(&mut near_max, "rem-request-expires", &u64::MAX.to_string());
    sign(
        &mut near_max,
        &[("rem", &current), ("rem-proposed", &proposed)],
        u64::MAX - 60,
    );
    near_max_context.received_at = u64::MAX;
    assert!(verify_request(&near_max, &near_max_context).is_ok());
}

#[test]
fn dual_label_route_binds_the_proposed_key_to_the_next_generation() {
    let (request, context, _, _) = dual_signature_request();
    assert!(verify_request(&request, &context).is_ok());

    for generation in [None, Some(1), Some(3), Some(u64::MAX)] {
        let mut changed = context.clone();
        changed.keys[1].generation = generation;
        rejects(&request, &changed, ErrorClass::AuthenticationRequired);
    }

    let mut wrapped = context;
    wrapped.keys[0].generation = Some(u64::MAX);
    rejects(&request, &wrapped, ErrorClass::AuthenticationRequired);
}

#[test]
fn authority_rejects_numeric_addresses_and_reserved_ldh_labels_before_authentication() {
    let (request, context) = signed_vector("http.control-signature");
    for authority in [
        "127.0.0.1:8444",
        "2130706433:8444",
        "017700000001:8444",
        "0x7f000001:8444",
        "ab--reserved.example.com:8444",
        "xn--a.example.com:8444",
    ] {
        let mut changed_request = request.clone();
        changed_request.authority = authority.as_bytes().to_vec();
        let mut changed_context = context.clone();
        changed_context.expected_authority = changed_request.authority.clone();
        rejects(
            &changed_request,
            &changed_context,
            ErrorClass::InvalidRequest,
        );
    }
}

#[test]
fn authority_accepts_numeric_looking_non_ip_dns_hosts() {
    let (mut request, mut context) = signed_vector("http.control-signature");
    let key = test_key();
    context.keys[0].jwk = jwk_of(&key);
    sign(&mut request, &[("rem", &key)], context.received_at);
    let original_authority = std::str::from_utf8(&request.authority).unwrap();
    let original_line = format!("\"@authority\": {original_authority}");
    let original_base = String::from_utf8(
        verify_request(&request, &context)
            .unwrap()
            .signature_base("rem")
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(original_base.contains(&original_line));

    for authority in ["1.2.3.999:443", "1.2.3.4.5:443"] {
        let mut changed_request = request.clone();
        changed_request.authority = authority.as_bytes().to_vec();
        let changed_base =
            original_base.replacen(&original_line, &format!("\"@authority\": {authority}"), 1);
        let signature = low_s_p1363(&key, changed_base.as_bytes());
        header(
            &mut changed_request,
            "signature",
            &render_signature(&[("rem", &signature)]),
        );
        let mut changed_context = context.clone();
        changed_context.expected_authority = changed_request.authority.clone();

        let verified = verify_request(&changed_request, &changed_context);
        assert!(
            verified.is_ok(),
            "numeric-looking non-IP DNS authority {authority} was rejected: {:?}",
            verified.as_ref().err()
        );
        let verified = verified.unwrap();
        assert_eq!(verified.identity().authority(), authority.as_bytes());
        assert_eq!(
            verified.signature_base("rem"),
            Some(changed_base.as_bytes()),
            "verified base for {authority}"
        );
    }
}

#[test]
fn signature_singletons_trim_surrounding_sp_and_htab() {
    let (request, context) = signed_vector("http.control-signature");
    let original_base = verify_request(&request, &context)
        .unwrap()
        .signature_base("rem")
        .unwrap()
        .to_vec();

    for name in ["signature-input", "signature"] {
        let mut changed = request.clone();
        let field = changed
            .headers
            .iter_mut()
            .find(|field| field.name == name.as_bytes())
            .unwrap();
        field.value.splice(0..0, *b" \t");
        field.value.extend_from_slice(b"\t ");

        let verified = verify_request(&changed, &context);
        assert!(
            verified.is_ok(),
            "surrounding SP/HTAB on singleton {name} was rejected: {:?}",
            verified.as_ref().err()
        );
        assert_eq!(
            verified.unwrap().signature_base("rem"),
            Some(original_base.as_slice()),
            "surrounding OWS on {name} changed the signature base"
        );
    }
}

#[test]
fn malformed_signature_structured_fields_use_authentication_errors() {
    let (request, context) = signed_vector("http.control-signature");
    for name in ["signature-input", "signature"] {
        for malformed in [b"\xff".as_slice(), b"\r\n"] {
            let mut changed = request.clone();
            changed
                .headers
                .iter_mut()
                .find(|field| field.name == name.as_bytes())
                .unwrap()
                .value = malformed.to_vec();
            rejects(&changed, &context, ErrorClass::AuthenticationRequired);
        }
    }
}

#[test]
fn reporter_signatures_omit_client_clock_and_reporter_keys_carry_no_generation() {
    let (request, mut context) = signed_vector("http.reporter-signature");
    let signature_input = request
        .headers
        .iter()
        .find(|field| field.name == b"signature-input")
        .unwrap()
        .value
        .clone();
    assert!(
        !signature_input
            .windows(b";created=".len())
            .any(|window| window == b";created=")
    );
    context.received_at = 0;
    let first = verify_request(&request, &context).unwrap();
    assert_eq!(first.identity().created(), None);
    context.received_at = u64::MAX;
    assert_eq!(verify_request(&request, &context).unwrap(), first);
    context.keys[0].generation = Some(1);
    rejects(&request, &context, ErrorClass::AuthenticationRequired);

    context.keys[0].generation = None;
    let mut injected = request;
    let current = String::from_utf8(signature_input).unwrap();
    header(
        &mut injected,
        "signature-input",
        &current.replacen(";keyid=", ";created=0;keyid=", 1),
    );
    rejects(&injected, &context, ErrorClass::AuthenticationRequired);
}

#[test]
fn verified_reporter_identity_is_not_rederived_from_the_active_keyid() {
    let (request, mut context) = signed_vector("http.reporter-signature");
    let stable_reporter_id = B64u::<32>::from_bytes([0; 32]);
    context.keys[0].stable_principal_id = stable_reporter_id.clone();

    let verified = verify_request(&request, &context).unwrap();
    assert_eq!(
        verified.identity().stable_principal_id(),
        stable_reporter_id.as_bytes()
    );
    assert_ne!(
        verified.identity().stable_principal_id(),
        verified.identity().keyid()
    );
}

#[test]
fn malformed_purpose_label_is_invalid_before_signature_checks() {
    let (request, context) = signed_vector("http.reporter-signature");
    for purpose in ["-", "rem-report-v1-", "rem--report-v1"] {
        let mut changed = request.clone();
        header(&mut changed, "rem-purpose", purpose);
        rejects(&changed, &context, ErrorClass::InvalidRequest);
    }
}

#[test]
fn enrollment_purpose_is_selected_by_the_signed_body_mode() {
    let (request, context) = signed_vector("http.route.reporter.enrollment.create");
    assert!(verify_request(&request, &context).is_ok());

    let mut managed_label = request.clone();
    header(&mut managed_label, "rem-purpose", "rem-managed-enroll-v1");
    rejects(&managed_label, &context, ErrorClass::AuthenticationRequired);

    let mut unknown_mode = request.clone();
    unknown_mode.body = String::from_utf8(unknown_mode.body)
        .unwrap()
        .replacen(r#""mode":"interactive""#, r#""mode":"other""#, 1)
        .into_bytes();
    let digest = ContentDigest::for_body(&unknown_mode.body).render();
    header(&mut unknown_mode, "content-digest", &digest);
    rejects(&unknown_mode, &context, ErrorClass::InvalidRequest);
}

#[test]
fn admission_caps_framing_and_header_policy_return_their_classes() {
    let (request, context) = signed_vector("http.control-signature");
    assert!(verify_request(&request, &context).is_ok());
    let check = |mutate: &dyn Fn(&mut RawRequest), expected: ErrorClass| {
        let mut changed = request.clone();
        mutate(&mut changed);
        rejects(&changed, &context, expected);
    };

    check(
        &|request| {
            for index in 0..17 {
                header(request, &format!("x-filler-{index}"), "1");
            }
        },
        ErrorClass::HeadersTooLarge,
    );
    check(
        &|request| header(request, "x-large", &"a".repeat(8192)),
        ErrorClass::HeadersTooLarge,
    );
    check(
        &|request| {
            let long = "A".repeat(SIGNATURE_HEADER_MAX_BYTES);
            header(request, "signature", &format!("rem=:{long}:"));
        },
        ErrorClass::HeadersTooLarge,
    );
    check(
        &|request| header(request, "content-digest", &"a".repeat(257)),
        ErrorClass::HeadersTooLarge,
    );
    check(
        &|request| request.body.extend_from_slice(&[b' '; 512]),
        ErrorClass::RequestBodyTooLarge,
    );
    check(
        &|request| header(request, "content-encoding", "gzip"),
        ErrorClass::UnsupportedMediaType,
    );
    check(
        &|request| remove_header(request, "content-type"),
        ErrorClass::UnsupportedMediaType,
    );
    check(
        &|request| header(request, "content-type", "Application/JSON"),
        ErrorClass::UnsupportedMediaType,
    );
    check(
        &|request| header(request, "transfer-encoding", "chunked"),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| header(request, "repr-digest", "sha-256=:AA==:"),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| header(request, "content-length", "1"),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| header(request, "host", "other.example.com:8444"),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| header(request, "rem-session-id", "Dw8PDw8PDw8PDw8PDw8PDw"),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| header(request, "x-bad", "caf\u{e9}"),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| header(request, "rem-request-nonce", "IyMjIyMjIyMjIyMjIyMjIx"),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| header(request, "rem-request-expires", "01767226664"),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| remove_header(request, "rem-purpose"),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| {
            let duplicate = request.headers[0].clone();
            request.headers.push(duplicate);
        },
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| request.authority = b"Control.example.com:8444".to_vec(),
        ErrorClass::InvalidRequest,
    );
    check(
        &|request| remove_header(request, "signature-input"),
        ErrorClass::AuthenticationRequired,
    );
    check(
        &|request| remove_header(request, "signature"),
        ErrorClass::AuthenticationRequired,
    );
    check(
        &|request| {
            let field = request
                .headers
                .iter_mut()
                .find(|field| field.name == b"signature-input")
                .unwrap();
            field.value.extend_from_slice(b" ");
            field.value.insert(0, b' ');
            let text = String::from_utf8(field.value.clone()).unwrap();
            field.value = text.replacen(";created=", "; created=", 1).into_bytes();
        },
        ErrorClass::AuthenticationRequired,
    );

    // Leading/trailing OWS around a covered header value is not significant.
    let mut padded = request.clone();
    let field = padded
        .headers
        .iter_mut()
        .find(|field| field.name == b"rem-purpose")
        .unwrap();
    field.value.splice(0..0, *b" \t");
    field.value.extend_from_slice(b" ");
    assert!(verify_request(&padded, &context).is_ok());

    // Header names are case-insensitive.
    let mut upper = request.clone();
    for field in &mut upper.headers {
        field.name.make_ascii_uppercase();
    }
    assert!(verify_request(&upper, &context).is_ok());
}

#[test]
fn bodyless_routes_reject_entity_headers_and_bodies() {
    let (request, context) = signed_vector("http.route.control.roster.events");
    assert!(verify_request(&request, &context).is_ok());
    let mut with_body = request.clone();
    with_body.body = b"{}".to_vec();
    rejects(&with_body, &context, ErrorClass::RequestBodyTooLarge);
    let mut with_type = request.clone();
    header(&mut with_type, "content-type", "application/json");
    rejects(&with_type, &context, ErrorClass::UnsupportedMediaType);
    let mut zero_length = request.clone();
    header(&mut zero_length, "content-length", "0");
    assert!(verify_request(&zero_length, &context).is_ok());
}

#[test]
fn unsigned_routes_never_produce_a_verified_identity() {
    let (mut request, mut context) = signed_vector("http.control-signature");
    request.target = b"/control/v1/bootstrap/commit".to_vec();
    context.expected_route_id = "control.bootstrap.commit";
    rejects(&request, &context, ErrorClass::AuthenticationRequired);
}

#[test]
fn a_valid_signature_for_another_authority_is_rejected() {
    let (mut request, mut context) = signed_vector("http.control-signature");
    let key = test_key();
    context.keys[0].jwk = jwk_of(&key);
    request.authority = b"other.example.com:8444".to_vec();
    sign(&mut request, &[("rem", &key)], context.received_at);
    rejects(&request, &context, ErrorClass::AuthenticationRequired);
    context.expected_authority = request.authority.clone();
    assert!(verify_request(&request, &context).is_ok());
}

type ParamsTamper<'a> = dyn Fn(&str, String) -> String + 'a;

/// A compromised signer: sign `rem` (and optionally `rem-proposed`) over parameters and header
/// values that are internally inconsistent, so only the verifier's consistency checks can reject.
fn sign_tampered(
    request: &mut RawRequest,
    members: &[(&str, &SigningKey)],
    created: u64,
    tamper_params: &ParamsTamper<'_>,
    tamper_base_lines: &dyn Fn(String) -> String,
) {
    remove_header(request, "signature-input");
    remove_header(request, "signature");
    let mut inputs = Vec::new();
    let mut signatures = Vec::new();
    for (label, key) in members {
        let material =
            signature_material(request, label, jwk_of(key).thumbprint_b64u(), Some(created))
                .unwrap();
        let base = String::from_utf8(material.signature_base().to_vec()).unwrap();
        let params = material.signature_params();
        let lines = tamper_base_lines(base[..base.len() - params.len()].to_owned());
        let params = tamper_params(label, params.to_owned());
        signatures.push(low_s_p1363(key, format!("{lines}{params}").as_bytes()));
        inputs.push(format!("{label}={params}"));
    }
    header(request, "signature-input", &inputs.join(", "));
    let rendered: Vec<_> = members
        .iter()
        .zip(&signatures)
        .map(|((label, _), signature)| (*label, signature))
        .collect();
    header(request, "signature", &render_signature(&rendered));
}

#[test]
fn consistently_signed_but_inconsistent_parameters_are_rejected() {
    let (request, mut context) = signed_vector("http.control-signature");
    let key = test_key();
    context.keys[0].jwk = jwk_of(&key);
    let created = context.received_at;
    let other_keyid = jwk_of(&test_key()).thumbprint_b64u().as_str().to_owned();
    let own_keyid = jwk_of(&key).thumbprint_b64u().as_str().to_owned();
    let same = |base: String| base;

    let mut untampered = request.clone();
    sign_tampered(&mut untampered, &[("rem", &key)], created, &|_, p| p, &same);
    assert!(verify_request(&untampered, &context).is_ok(), "control");

    let params_cases: Vec<(&str, Box<ParamsTamper<'static>>)> = vec![
        (
            "keyid",
            Box::new(move |_, params: String| params.replace(&own_keyid, &other_keyid)),
        ),
        (
            "alg",
            Box::new(|_, params: String| params.replace("ecdsa-p256-sha256", "ecdsa-p384-sha384")),
        ),
        (
            "tag",
            Box::new(|_, params: String| {
                params.replace(
                    "tag=\"rem-control-lease-refresh-v1\"",
                    "tag=\"rem-control-mqtt-key-ack-v1\"",
                )
            }),
        ),
        (
            "expires",
            Box::new(|_, params: String| {
                params.replace(";expires=1767226664", ";expires=1767226663")
            }),
        ),
        (
            "nonce",
            Box::new(|_, params: String| {
                params.replace("LS0tLS0tLS0tLS0tLS0tLQ", "LS0tLS0tLS0tLS0tLS0tLA")
            }),
        ),
    ];
    for (name, tamper) in &params_cases {
        let mut tampered = request.clone();
        sign_tampered(
            &mut tampered,
            &[("rem", &key)],
            created,
            tamper.as_ref(),
            &same,
        );
        rejects(&tampered, &context, ErrorClass::AuthenticationRequired);
        assert_ne!(
            tampered, untampered,
            "{name} tamper must change the request"
        );
    }

    // REM-Purpose naming another route, signed consistently in the base and the tag.
    let mut purpose = request.clone();
    let swap = |text: String| {
        text.replace(
            "rem-control-lease-refresh-v1",
            "rem-control-mqtt-key-ack-v1",
        )
    };
    sign_tampered(
        &mut purpose,
        &[("rem", &key)],
        created,
        &|_, p| swap(p),
        &swap,
    );
    header(&mut purpose, "rem-purpose", "rem-control-mqtt-key-ack-v1");
    rejects(&purpose, &context, ErrorClass::AuthenticationRequired);

    // REM-Purpose naming another route while the signed tag keeps the route purpose.
    let mut header_only = request.clone();
    sign_tampered(
        &mut header_only,
        &[("rem", &key)],
        created,
        &|_, p| p,
        &swap,
    );
    header(
        &mut header_only,
        "rem-purpose",
        "rem-control-mqtt-key-ack-v1",
    );
    rejects(&header_only, &context, ErrorClass::AuthenticationRequired);
}

#[test]
fn dual_label_members_must_share_every_parameter_but_keyid() {
    let (request, context, current, proposed) = dual_signature_request();
    let created = context.received_at;
    let same = |base: String| base;
    for tamper in [
        |label: &str, params: String| {
            if label == "rem-proposed" {
                params.replace(";created=1767226600", ";created=1767226601")
            } else {
                params
            }
        },
        |label: &str, params: String| {
            if label == "rem-proposed" {
                params.replace(";expires=1767226660", ";expires=1767226659")
            } else {
                params
            }
        },
        |label: &str, params: String| {
            if label == "rem-proposed" {
                params.replace("IyMjIyMjIyMjIyMjIyMjIw", "IyMjIyMjIyMjIyMjIyMjIA")
            } else {
                params
            }
        },
    ] {
        let mut tampered = request.clone();
        sign_tampered(
            &mut tampered,
            &[("rem", &current), ("rem-proposed", &proposed)],
            created,
            &tamper,
            &same,
        );
        rejects(&tampered, &context, ErrorClass::AuthenticationRequired);
    }
}

#[test]
fn a_canonical_body_that_differs_from_its_digest_is_invalid() {
    let (mut request, context, _, _) = dual_signature_request();
    request.body = br#"{"schema_version":2}"#.to_vec();
    rejects(&request, &context, ErrorClass::InvalidRequest);
}
