mod support;

use std::collections::{BTreeMap, BTreeSet};

use remote_energy_meter_reporter::protocol_v1::{
    ErrorClass,
    b64u::B64u,
    http_signature::{
        HeaderField, LABEL, RawRequest, VerificationContext, VerificationKey, signature_material,
        verify_request,
    },
    jwk::P256PublicJwk,
    routes::{ROUTES, lookup_route},
};
use support::{
    Json, base64_standard_decode, base64_standard_encode_padded, base64url_decode,
    base64url_encode_unpadded, fixture, hex_decode, named_value, optional_named_value, parse_json,
    sha256,
};

fn assert_debug_omits_bytes(rendered: &str, label: &str, bytes: &[u8]) {
    assert!(!bytes.is_empty(), "{label} test marker must be non-empty");
    assert!(
        !rendered.contains(&format!("{bytes:?}")),
        "Debug output leaked {label} bytes"
    );
    if let Ok(text) = std::str::from_utf8(bytes) {
        assert!(!rendered.contains(text), "Debug output leaked {label} text");
    }
}

fn assert_debug_has_field(rendered: &str, field: &str, value: usize) {
    assert!(
        rendered.contains(&format!("{field}: {value}")),
        "Debug output omitted safe {field} metadata"
    );
}

#[derive(Clone, Debug)]
struct VectorRequest {
    request: RawRequest,
    context: VerificationContext,
}

fn http_cases() -> Vec<Json> {
    ["http-signatures.json", "key-rotations.json"]
        .into_iter()
        .flat_map(|file| {
            parse_json(&fixture(&format!("vectors/{file}")))
                .member("cases")
                .array()
                .iter()
                .filter(|case| {
                    case.member("inputs")
                        .array()
                        .iter()
                        .any(|value| value.member("name").string() == "request.method")
                        && case
                            .member("expected")
                            .member("outputs")
                            .array()
                            .iter()
                            .any(|value| value.member("name").string() == "headers.signature-input")
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect()
}

fn expected_output<'a>(case: &'a Json, name: &str) -> &'a str {
    case.member("expected")
        .member("outputs")
        .array()
        .iter()
        .find(|item| item.member("name").string() == name)
        .unwrap_or_else(|| panic!("missing expected output {name}"))
        .member("value")
        .string()
}

fn request_hash(request: &RawRequest) -> [u8; 32] {
    let mut encoded = Vec::new();
    for value in [
        request.method.as_slice(),
        request.authority.as_slice(),
        request.target.as_slice(),
        request.body.as_slice(),
    ] {
        encoded.extend_from_slice(&u64::try_from(value.len()).unwrap().to_be_bytes());
        encoded.extend_from_slice(value);
    }
    encoded.extend_from_slice(&u32::try_from(request.headers.len()).unwrap().to_be_bytes());
    for header in &request.headers {
        encoded.extend_from_slice(&u32::try_from(header.name.len()).unwrap().to_be_bytes());
        encoded.extend_from_slice(&header.name);
        encoded.extend_from_slice(&u64::try_from(header.value.len()).unwrap().to_be_bytes());
        encoded.extend_from_slice(&header.value);
    }
    sha256(&encoded)
}

fn input_map(case: &Json) -> BTreeMap<&str, &str> {
    case.member("inputs")
        .array()
        .iter()
        .map(|item| (item.member("name").string(), item.member("value").string()))
        .collect()
}

fn build_request(case: &Json) -> VectorRequest {
    let inputs = input_map(case);
    let mut headers: Vec<_> = inputs
        .iter()
        .filter_map(|(name, value)| {
            name.strip_prefix("headers.").map(|name| HeaderField {
                name: name.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            })
        })
        .collect();
    headers.push(HeaderField {
        name: b"signature-input".to_vec(),
        value: expected_output(case, "headers.signature-input")
            .as_bytes()
            .to_vec(),
    });
    headers.push(HeaderField {
        name: b"signature".to_vec(),
        value: expected_output(case, "headers.signature")
            .as_bytes()
            .to_vec(),
    });

    let generation = inputs
        .get("headers.rem-control-key-generation")
        .map(|value| value.parse::<u64>().expect("vector generation is uint64"));
    let stable_principal_id =
        B64u::<32>::parse(inputs["keyid.rem"]).expect("vector stable identity is canonical");
    let keys: Vec<_> = inputs
        .iter()
        .filter_map(|(name, jwk)| name.strip_prefix("jwk.").map(|label| (label, jwk)))
        .map(|(label, jwk)| VerificationKey {
            stable_principal_id: stable_principal_id.clone(),
            label: label.as_bytes().to_vec(),
            jwk: P256PublicJwk::parse_exact(jwk.as_bytes()).expect("vector JWK is valid"),
            generation: generation.map(|current| {
                if label == "rem-proposed" {
                    current
                        .checked_add(1)
                        .expect("fixture generation increments")
                } else {
                    current
                }
            }),
        })
        .collect();
    let signature_input = expected_output(case, "headers.signature-input");
    let received_at = if signature_input.contains(";created=") {
        parameter(signature_input, "created")
            .parse()
            .expect("control created is uint64")
    } else {
        0
    };

    VectorRequest {
        request: RawRequest {
            method: inputs["request.method"].as_bytes().to_vec(),
            authority: inputs["request.authority"].as_bytes().to_vec(),
            target: inputs["request.target"].as_bytes().to_vec(),
            headers,
            body: inputs
                .get("body")
                .map_or_else(Vec::new, |body| body.as_bytes().to_vec()),
        },
        context: VerificationContext {
            expected_route_id: lookup_route(
                inputs["request.method"].as_bytes(),
                inputs["request.target"].as_bytes(),
            )
            .expect("vector route is registered")
            .id(),
            expected_authority: inputs["request.authority"].as_bytes().to_vec(),
            received_at,
            keys,
        },
    }
}

fn parameter<'a>(signature_input: &'a str, name: &str) -> &'a str {
    let marker = format!(";{name}=");
    let tail = signature_input
        .find(&marker)
        .map(|at| &signature_input[at + marker.len()..])
        .expect("parameter exists");
    if let Some(quoted) = tail.strip_prefix('"') {
        &quoted[..quoted.find('"').expect("quoted parameter closes")]
    } else {
        &tail[..tail.find([';', ',']).unwrap_or(tail.len())]
    }
}

fn header_index(request: &RawRequest, name: &str) -> usize {
    request
        .headers
        .iter()
        .position(|header| header.name == name.as_bytes())
        .unwrap_or_else(|| panic!("missing header {name}"))
}

fn replace_header(request: &mut RawRequest, name: &str, value: impl Into<Vec<u8>>) {
    let at = header_index(request, name);
    request.headers[at].value = value.into();
}

fn mutate_b64u(text: &str) -> String {
    let mut bytes = base64url_decode(text);
    *bytes.last_mut().expect("non-empty b64u") ^= 1;
    base64url_encode_unpadded(&bytes)
}

fn increment_decimal(text: &str) -> String {
    text.parse::<u64>()
        .expect("uint64 mutation input")
        .checked_add(1)
        .expect("mutation must not wrap")
        .to_string()
}

fn replacement(case: &Json, field: &str) -> String {
    case.member("substitutes")
        .array()
        .iter()
        .find(|item| item.member("field").string() == field)
        .unwrap_or_else(|| panic!("missing substitute for {field}"))
        .member("replacement")
        .member("value")
        .string()
        .to_owned()
}

fn replacement_bytes(case: &Json, field: &str) -> Vec<u8> {
    let replacement = case
        .member("substitutes")
        .array()
        .iter()
        .find(|item| item.member("field").string() == field)
        .unwrap_or_else(|| panic!("missing substitute for {field}"))
        .member("replacement");
    match replacement.member("encoding").string() {
        "ascii" | "utf8" => replacement.member("value").string().as_bytes().to_vec(),
        "hex" => hex_decode(replacement.member("value").string()),
        "base64url" => base64url_decode(replacement.member("value").string()),
        "base64" => base64_standard_decode(replacement.member("value").string()),
        encoding => panic!("unsupported substitute encoding {encoding}"),
    }
}

fn rewrite_parameter(input: &str, name: &str, replacement: &str) -> String {
    let marker = format!(";{name}=");
    let start = input.find(&marker).expect("parameter exists") + marker.len();
    let (value_start, value_end) = if input.as_bytes()[start] == b'"' {
        let value_start = start + 1;
        (
            value_start,
            value_start + input[value_start..].find('"').expect("quote closes"),
        )
    } else {
        (
            start,
            start
                + input[start..]
                    .find([';', ','])
                    .unwrap_or(input.len() - start),
        )
    };
    format!(
        "{}{}{}",
        &input[..value_start],
        replacement,
        &input[value_end..]
    )
}

fn rewrite_component_list(input: &str, operation: &str) -> String {
    let open = input.find('(').expect("component list opens");
    let close = input[open..]
        .find(')')
        .map(|offset| open + offset)
        .expect("component list closes");
    let mut components: Vec<_> = input[open + 1..close].split(' ').collect();
    match operation {
        "reorder" => components.swap(0, 1),
        "omit" => {
            components.pop();
        }
        _ => panic!("unsupported component-list operation {operation}"),
    }
    format!(
        "{}{}{}",
        &input[..open + 1],
        components.join(" "),
        &input[close..]
    )
}

fn rewrite_labeled_parameter(
    input: &str,
    label: &str,
    parameter_name: &str,
    operation: &str,
    substitute: Option<&str>,
) -> String {
    let mut members: Vec<_> = input.split(", ").map(str::to_owned).collect();
    let prefix = format!("{label}=");
    let member = members
        .iter_mut()
        .find(|member| member.starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing signature input label {label}"));
    *member = match parameter_name {
        "components" => rewrite_component_list(member, "reorder"),
        "component-list" => rewrite_component_list(member, "omit"),
        "nonce" => {
            let value = parameter(member, "nonce");
            rewrite_parameter(member, "nonce", &mutate_b64u(value))
        }
        "keyid" if operation == "alter-byte" => {
            let value = parameter(member, "keyid");
            rewrite_parameter(member, "keyid", &mutate_b64u(value))
        }
        name => {
            let value = if let Some(substitute) = substitute {
                substitute.to_owned()
            } else if matches!(name, "created" | "expires") {
                increment_decimal(parameter(member, name))
            } else {
                format!("{}x", parameter(member, name))
            };
            rewrite_parameter(member, name, &value)
        }
    };
    members.join(", ")
}

fn rewrite_signature_bytes(header: &str, label: &str, replacement: &[u8]) -> String {
    let marker = format!("{label}=:");
    let value_start = header.find(&marker).expect("signature label exists") + marker.len();
    let value_end = value_start
        + header[value_start..]
            .find(':')
            .expect("signature byte sequence closes");
    format!(
        "{}{}{}",
        &header[..value_start],
        base64_standard_encode_padded(replacement),
        &header[value_end..]
    )
}

fn mutate_path_parameter(target: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(target).expect("ASCII target");
    let (path, query) = text
        .split_once('?')
        .map_or((text, None), |(path, query)| (path, Some(query)));
    let mut segments: Vec<_> = path.split('/').map(str::to_owned).collect();
    let segment = segments
        .iter_mut()
        .find(|segment| matches!(segment.len(), 22 | 43))
        .expect("vector path has a typed path parameter");
    *segment = mutate_b64u(segment);
    let mut output = segments.join("/");
    if let Some(query) = query {
        output.push('?');
        output.push_str(query);
    }
    output.into_bytes()
}

fn mutate_query(target: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(target).expect("ASCII target");
    let (path, query) = text.split_once('?').expect("query vector");
    let mut pairs: Vec<_> = query.split('&').map(str::to_owned).collect();
    let (name, value) = pairs[0].split_once('=').expect("named query");
    pairs[0] = if value.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("{name}={}", increment_decimal(value))
    } else {
        format!("{name}={}", mutate_b64u(value))
    };
    format!("{path}?{}", pairs.join("&")).into_bytes()
}

fn apply_mutation(vector: &mut VectorRequest, case: &Json, mutation: &Json) {
    let field = mutation.member("field").string();
    let operation = mutation.member("operation").string();

    if field.starts_with("request.") {
        mutate_request(vector, case, field, operation);
    } else if field == "body" || field.starts_with("body.") {
        mutate_body(&mut vector.request, field);
    } else if field.starts_with("headers.signature.") {
        mutate_signature_header(&mut vector.request, field);
    } else if field.starts_with("headers.") {
        mutate_header(&mut vector.request, case, field, operation);
    } else if field.starts_with("signature-input.") {
        mutate_signature_input(&mut vector.request, field, operation);
    } else if field.starts_with("signature-params.") {
        mutate_signature_params(&mut vector.request, case, field, operation);
    } else if field.starts_with("signature.") {
        mutate_signature(&mut vector.request, case, field);
    } else {
        panic!("unconsumed HTTP mutation {field} {operation}");
    }
}

fn mutate_request(vector: &mut VectorRequest, case: &Json, field: &str, operation: &str) {
    let request = &mut vector.request;
    if field == "request.method" {
        request.method = if request.method == b"GET" {
            b"POST".to_vec()
        } else {
            b"GET".to_vec()
        };
    } else if field == "request.authority" {
        let authority = std::str::from_utf8(&request.authority).unwrap();
        let (host, port) = authority.rsplit_once(':').unwrap();
        request.authority = format!("{host}:{}", increment_decimal(port)).into_bytes();
    } else if field == "request.replay.after-expiry" {
        let signature_input = String::from_utf8(
            request.headers[header_index(request, "signature-input")]
                .value
                .clone(),
        )
        .unwrap();
        vector.context.received_at = parameter(&signature_input, "expires")
            .parse::<u64>()
            .unwrap()
            .checked_add(1)
            .unwrap();
    } else if field.starts_with("request.target.") {
        mutate_request_target(request, case, field, operation);
    } else {
        panic!("unconsumed HTTP mutation {field} {operation}");
    }
}

fn mutate_request_target(request: &mut RawRequest, case: &Json, field: &str, operation: &str) {
    if matches!(
        field,
        "request.target.cross-route" | "request.target.empty-query"
    ) {
        request.target = replacement(case, field).into_bytes();
    } else if field == "request.target.path-parameter" {
        request.target = mutate_path_parameter(&request.target);
    } else if field == "request.target.path" {
        let query = request
            .target
            .iter()
            .position(|byte| *byte == b'?')
            .unwrap_or(request.target.len());
        request.target[query - 1] ^= 1;
    } else if field == "request.target.query" {
        request.target = mutate_query(&request.target);
    } else if field == "request.target.query-member" {
        assert_eq!(operation, "duplicate");
        let text = std::str::from_utf8(&request.target).unwrap();
        let (path, query) = text.split_once('?').unwrap();
        let pairs: Vec<_> = query.split('&').collect();
        assert_eq!(
            pairs.len(),
            1,
            "duplicate-query fixture starts with one member"
        );
        let (name, value) = pairs[0].split_once('=').unwrap();
        let duplicate_value = if value.bytes().all(|byte| byte.is_ascii_digit()) {
            value
        } else {
            "AA"
        };
        request.target = format!("{path}?{query}&{name}={duplicate_value}").into_bytes();
    } else if field == "request.target.query-order" {
        let text = std::str::from_utf8(&request.target).unwrap();
        let (path, query) = text.split_once('?').unwrap();
        let mut pairs: Vec<_> = query.split('&').map(str::to_owned).collect();
        if pairs.len() > 1 {
            pairs.swap(0, 1);
        } else {
            panic!("single-member query reorder is undefined by the fixture operation");
        }
        request.target = format!("{path}?{}", pairs.join("&")).into_bytes();
    } else {
        panic!("unconsumed HTTP mutation {field} {operation}");
    }
}

fn mutate_body(request: &mut RawRequest, field: &str) {
    if field == "body" {
        *request.body.last_mut().expect("body route") ^= 1;
        return;
    }
    let member = field.strip_prefix("body.").expect("body mutation prefix");
    let current = String::from_utf8(request.body.clone()).unwrap();
    let marker = format!("\"{member}\":\"");
    let start = current.find(&marker).expect("body member exists") + marker.len();
    let end = start + current[start..].find('"').expect("body string closes");
    request.body = format!(
        "{}{}{}",
        &current[..start],
        mutate_b64u(&current[start..end]),
        &current[end..]
    )
    .into_bytes();
}

fn mutate_signature_header(request: &mut RawRequest, field: &str) {
    let label = if field.contains("rem-proposed") {
        "rem-proposed"
    } else {
        "rem"
    };
    let at = header_index(request, "signature");
    let current = String::from_utf8(request.headers[at].value.clone()).unwrap();
    let marker = format!("{label}=:");
    let start = current.find(&marker).unwrap() + marker.len();
    let end = start + current[start..].find(':').unwrap();
    let mut bytes = base64_standard_decode(&current[start..end]);
    *bytes.last_mut().unwrap() ^= 1;
    request.headers[at].value = rewrite_signature_bytes(&current, label, &bytes).into_bytes();
}

fn mutate_header(request: &mut RawRequest, case: &Json, field: &str, operation: &str) {
    let raw_name = field
        .strip_prefix("headers.")
        .expect("header mutation prefix");
    let name = raw_name.split('.').next().unwrap();
    if name == "signature" && operation == "duplicate" {
        request
            .headers
            .push(request.headers[header_index(request, name)].clone());
        return;
    }
    if operation == "substitute"
        && !request
            .headers
            .iter()
            .any(|header| header.name == name.as_bytes())
    {
        // Bodyless routes carry no Content-Digest; the declared mutation adds the forbidden
        // header with the substitute value.
        request.headers.push(HeaderField {
            name: name.as_bytes().to_vec(),
            value: replacement(case, field).into_bytes(),
        });
        return;
    }
    let current =
        String::from_utf8(request.headers[header_index(request, name)].value.clone()).unwrap();
    let changed = match operation {
        "substitute" => replacement(case, field),
        "alter-byte" if matches!(name, "rem-request-nonce" | "rem-session-id") => {
            mutate_b64u(&current)
        }
        // README: alter-value on a binary value XORs 0x01 into the first decoded byte.
        "alter-value" if matches!(name, "rem-request-nonce" | "rem-session-id") => {
            let mut bytes = base64url_decode(&current);
            bytes[0] ^= 1;
            base64url_encode_unpadded(&bytes)
        }
        "alter-byte" => {
            let mut bytes = current.into_bytes();
            *bytes.last_mut().unwrap() ^= 1;
            String::from_utf8(bytes).unwrap()
        }
        "alter-value" if name == "content-type" => "application/json; charset=utf-8".to_owned(),
        "alter-value" => increment_decimal(&current),
        _ => panic!("unsupported header mutation {field} {operation}"),
    };
    replace_header(request, name, changed.into_bytes());
}

fn mutate_signature_input(request: &mut RawRequest, field: &str, operation: &str) {
    let at = header_index(request, "signature-input");
    let current = String::from_utf8(request.headers[at].value.clone()).unwrap();
    if field == "signature-input.labels" {
        let (first, second) = current.split_once(", ").unwrap();
        request.headers[at].value = format!("{second}, {first}").into_bytes();
    } else if field == "signature-input.rem-proposed" {
        request.headers[at].value = current
            .split(", ")
            .filter(|member| !member.starts_with("rem-proposed="))
            .collect::<Vec<_>>()
            .join(", ")
            .into_bytes();
    } else if field == "signature-input.rem-proposed.label" {
        request.headers[at].value = current.replacen("rem-proposed=", "rem=", 1).into_bytes();
    } else {
        panic!("unconsumed HTTP mutation {field} {operation}");
    }
}

fn mutate_signature_params(request: &mut RawRequest, case: &Json, field: &str, operation: &str) {
    let remainder = field
        .strip_prefix("signature-params.")
        .expect("signature parameter mutation prefix");
    let (label, parameter_name) = remainder
        .split_once('.')
        .expect("signature parameter names its label");
    let at = header_index(request, "signature-input");
    let current = String::from_utf8(request.headers[at].value.clone()).unwrap();
    let substitute = (operation == "substitute").then(|| replacement(case, field));
    request.headers[at].value = rewrite_labeled_parameter(
        &current,
        label,
        parameter_name,
        operation,
        substitute.as_deref(),
    )
    .into_bytes();
}

fn mutate_signature(request: &mut RawRequest, case: &Json, field: &str) {
    let label = if field.contains("rem-proposed") {
        "rem-proposed"
    } else {
        "rem"
    };
    let at = header_index(request, "signature");
    let current = String::from_utf8(request.headers[at].value.clone()).unwrap();
    let bytes = if field.ends_with("high-s") {
        replacement_bytes(case, field)
    } else {
        let marker = format!("{label}=:");
        let start = current.find(&marker).unwrap() + marker.len();
        let end = start + current[start..].find(':').unwrap();
        let mut bytes = base64_standard_decode(&current[start..end]);
        *bytes.last_mut().unwrap() ^= 1;
        bytes
    };
    request.headers[at].value = rewrite_signature_bytes(&current, label, &bytes).into_bytes();
}

fn error_class(name: &str) -> ErrorClass {
    match name {
        "invalid_request" => ErrorClass::InvalidRequest,
        "authentication_required" => ErrorClass::AuthenticationRequired,
        "method_not_allowed" => ErrorClass::MethodNotAllowed,
        "unsupported_media_type" => ErrorClass::UnsupportedMediaType,
        "not_found" => ErrorClass::NotFound,
        _ => panic!("unexpected HTTP mutation error class {name}"),
    }
}

#[test]
fn header_field_debug_redacts_name_and_value_bytes() {
    let header = HeaderField {
        name: b"debug-secret-header-marker".to_vec(),
        value: b"debug-header-value-marker".to_vec(),
    };

    let rendered = format!("{header:?}");
    assert!(
        rendered.starts_with("HeaderField {"),
        "Debug output omitted the HeaderField type"
    );
    assert_debug_omits_bytes(&rendered, "header name", &header.name);
    assert_debug_omits_bytes(&rendered, "header value", &header.value);
    assert_debug_has_field(&rendered, "name_len", header.name.len());
    assert_debug_has_field(&rendered, "value_len", header.value.len());
}

#[test]
fn raw_request_debug_redacts_request_bytes_and_retains_only_safe_lengths() {
    let request = RawRequest {
        method: b"POST".to_vec(),
        authority: b"debug-authority-marker.example:443".to_vec(),
        target: b"/debug-target-marker?token=debug-query-secret-marker".to_vec(),
        headers: vec![HeaderField {
            name: b"debug-secret-header-marker".to_vec(),
            value: b"debug-header-value-marker".to_vec(),
        }],
        body: br#"{"secret":"debug-body-secret-marker"}"#.to_vec(),
    };

    let rendered = format!("{request:?}");
    assert!(
        rendered.starts_with("RawRequest {"),
        "Debug output omitted the RawRequest type"
    );
    assert_debug_omits_bytes(&rendered, "method", &request.method);
    assert_debug_omits_bytes(&rendered, "authority", &request.authority);
    assert_debug_omits_bytes(&rendered, "target", &request.target);
    assert_debug_omits_bytes(&rendered, "header name", &request.headers[0].name);
    assert_debug_omits_bytes(&rendered, "header value", &request.headers[0].value);
    assert_debug_omits_bytes(&rendered, "body", &request.body);
    assert_debug_has_field(&rendered, "authority_len", request.authority.len());
    assert_debug_has_field(&rendered, "target_len", request.target.len());
    assert_debug_has_field(&rendered, "header_count", request.headers.len());
    assert_debug_has_field(&rendered, "body_len", request.body.len());
}

#[test]
fn verified_identity_debug_redacts_exact_request_key_and_session_data() {
    let case = http_cases()
        .into_iter()
        .find(|case| input_map(case).contains_key("headers.rem-session-id"))
        .expect("report request vector");
    let vector = build_request(&case);
    let verified = verify_request(&vector.request, &vector.context).unwrap();
    let identity = verified.identity();

    let rendered = format!("{identity:?}");
    assert!(
        rendered.starts_with("VerifiedIdentity {"),
        "Debug output omitted the VerifiedIdentity type"
    );
    assert!(
        rendered.contains(&format!("route_id: {:?}", identity.route_id())),
        "Debug output omitted safe route metadata"
    );
    assert_debug_omits_bytes(&rendered, "request body", &vector.request.body);
    assert_debug_omits_bytes(
        &rendered,
        "Signature header",
        &vector.request.headers[header_index(&vector.request, "signature")].value,
    );
    assert_debug_omits_bytes(&rendered, "key ID", identity.keyid());
    assert_debug_omits_bytes(
        &rendered,
        "reporter session ID",
        identity
            .session_id()
            .expect("report identity has session ID"),
    );
}

#[test]
fn verified_request_debug_redacts_signature_bases_nonce_and_nested_request_data() {
    let case = http_cases()
        .into_iter()
        .find(|case| input_map(case).contains_key("headers.rem-request-nonce"))
        .expect("control request vector");
    let vector = build_request(&case);
    let verified = verify_request(&vector.request, &vector.context).unwrap();
    let signature_base = verified.signature_base(LABEL).unwrap();

    let rendered = format!("{verified:?}");
    assert!(
        rendered.starts_with("VerifiedRequest {"),
        "Debug output omitted the VerifiedRequest type"
    );
    assert_debug_omits_bytes(&rendered, "signature base", signature_base);
    assert_debug_omits_bytes(
        &rendered,
        "control nonce",
        verified
            .identity()
            .nonce()
            .expect("control identity has nonce"),
    );
    assert_debug_omits_bytes(
        &rendered,
        "Signature header",
        &vector.request.headers[header_index(&vector.request, "signature")].value,
    );
    assert_debug_omits_bytes(&rendered, "key ID", verified.identity().keyid());
    assert_debug_has_field(&rendered, "signature_base_count", 1);
}

#[test]
fn signature_material_debug_redacts_parameters_bases_and_nonce_markers() {
    let case = http_cases()
        .into_iter()
        .find(|case| input_map(case).contains_key("headers.rem-request-nonce"))
        .expect("control request vector");
    let mut vector = build_request(&case);
    let nonce_marker = [0xa7; 16];
    let encoded_nonce_marker = base64url_encode_unpadded(&nonce_marker);
    replace_header(
        &mut vector.request,
        "rem-request-nonce",
        encoded_nonce_marker.as_bytes().to_vec(),
    );
    let signature_input = expected_output(&case, "headers.signature-input");
    let created = parameter(signature_input, "created").parse().unwrap();
    let keyid = B64u::<32>::parse(input_map(&case)["keyid.rem"]).unwrap();
    let material = signature_material(&vector.request, LABEL, &keyid, Some(created)).unwrap();

    let rendered = format!("{material:?}");
    assert!(
        rendered.starts_with("SignatureMaterial {"),
        "Debug output omitted the SignatureMaterial type"
    );
    assert_debug_omits_bytes(
        &rendered,
        "signature parameters",
        material.signature_params().as_bytes(),
    );
    assert_debug_omits_bytes(&rendered, "signature base", material.signature_base());
    assert_debug_omits_bytes(&rendered, "encoded nonce", encoded_nonce_marker.as_bytes());
    assert_debug_omits_bytes(&rendered, "decoded nonce", &nonce_marker);
    assert_debug_has_field(
        &rendered,
        "signature_params_len",
        material.signature_params().len(),
    );
    assert_debug_has_field(
        &rendered,
        "signature_base_len",
        material.signature_base().len(),
    );
}

#[test]
fn every_reporter_and_control_vector_builds_exact_signature_bases_and_verified_identity() {
    let cases = http_cases();
    assert_eq!(cases.len(), 25);
    let covered_routes: BTreeSet<_> = cases
        .iter()
        .map(|case| {
            let inputs = input_map(case);
            lookup_route(
                inputs["request.method"].as_bytes(),
                inputs["request.target"].as_bytes(),
            )
            .unwrap()
            .id()
        })
        .collect();
    let signed_routes: BTreeSet<_> = ROUTES
        .iter()
        .filter(|route| route.signature_profile().is_some())
        .map(|route| route.id())
        .collect();
    assert_eq!(covered_routes, signed_routes);

    for case in &cases {
        let id = case.member("id").string();
        let vector = build_request(case);
        let verified = verify_request(&vector.request, &vector.context)
            .unwrap_or_else(|error| panic!("positive vector {id} failed: {error:?}"));
        assert_eq!(
            verified.identity().request(),
            &vector.request,
            "request for {id}"
        );
        assert_eq!(
            verified.identity().request_hash(),
            &request_hash(&vector.request),
            "exact request hash for {id}"
        );
        let route_id = lookup_route(&vector.request.method, &vector.request.target)
            .unwrap()
            .id();
        assert_eq!(
            verified.identity().route_id(),
            route_id,
            "route identity for {id}"
        );
        assert_eq!(
            verified.identity().method(),
            vector.request.method,
            "method identity for {id}"
        );
        assert_eq!(
            verified.identity().authority(),
            vector.request.authority,
            "authority identity for {id}"
        );
        assert_eq!(
            verified.identity().target(),
            vector.request.target,
            "target identity for {id}"
        );
        assert_eq!(
            verified.identity().purpose(),
            named_value(case, "inputs", "headers.rem-purpose").as_bytes()
        );

        let expected_rem = named_value(case, "intermediates", "signature-base.rem");
        assert_eq!(
            verified.signature_base("rem"),
            Some(expected_rem.as_bytes()),
            "rem base for {id}"
        );
        if let Some(expected_proposed) =
            optional_named_value(case, "intermediates", "signature-base.rem-proposed")
        {
            assert_eq!(
                verified.signature_base("rem-proposed"),
                Some(expected_proposed.as_bytes()),
                "proposed base for {id}"
            );
        } else {
            assert_eq!(
                verified.signature_base("rem-proposed"),
                None,
                "unexpected proposed base for {id}"
            );
        }

        let keyid = named_value(case, "inputs", "keyid.rem");
        assert_eq!(
            verified.identity().keyid(),
            keyid.as_bytes(),
            "key identity for {id}"
        );
        if let Some(proposed_keyid) = optional_named_value(case, "inputs", "keyid.rem-proposed") {
            assert_eq!(
                verified.identity().proposed_keyid(),
                Some(proposed_keyid.as_bytes()),
                "proposed key identity for {id}"
            );
        } else {
            assert_eq!(verified.identity().proposed_keyid(), None, "{id}");
        }
        if route_id.starts_with("control.") {
            assert_eq!(
                verified.identity().key_generation(),
                Some(1),
                "generation identity for {id}"
            );
            assert_eq!(
                verified.identity().created(),
                Some(
                    parameter(expected_output(case, "headers.signature-input"), "created")
                        .parse()
                        .unwrap()
                ),
                "created identity for {id}"
            );
            assert_eq!(
                verified.identity().nonce(),
                Some(
                    base64url_decode(named_value(case, "inputs", "headers.rem-request-nonce",))
                        .as_slice()
                ),
                "nonce identity for {id}"
            );
            assert_eq!(
                verified.identity().expires(),
                Some(
                    named_value(case, "inputs", "headers.rem-request-expires")
                        .parse()
                        .unwrap()
                ),
                "expiry identity for {id}"
            );
        } else {
            assert_eq!(verified.identity().key_generation(), None);
            assert_eq!(verified.identity().created(), None);
            assert_eq!(verified.identity().nonce(), None);
            assert_eq!(verified.identity().expires(), None);
        }

        let repeated = verify_request(&vector.request, &vector.context).unwrap();
        assert_eq!(
            verified.identity(),
            repeated.identity(),
            "verified identity must be stable for replay logic: {id}"
        );
    }
}

#[test]
fn named_query_values_are_preserved_as_exact_signed_raw_bytes() {
    let set = parse_json(&fixture("vectors/http-signatures.json"));
    for id in [
        "http.route.reporter.enrollment.status",
        "http.route.control.roster.events",
        "http.route.control.roster.snapshot",
        "http.route.control.roster.snapshot.continuation",
    ] {
        let case = support::vector_case(&set, id);
        let vector = build_request(case);
        let verified = verify_request(&vector.request, &vector.context).unwrap();
        let target = std::str::from_utf8(&vector.request.target).unwrap();
        let (_, raw_query) = target.split_once('?').unwrap();
        assert_eq!(
            verified.identity().raw_query(),
            Some(raw_query.as_bytes()),
            "whole query for {id}"
        );
        for pair in raw_query.split('&') {
            let (name, value) = pair.split_once('=').unwrap();
            assert_eq!(
                verified.identity().named_query(name),
                Some(value.as_bytes()),
                "named query {name} for {id}"
            );
        }
    }
}

#[test]
fn both_singleton_snapshot_duplicate_query_members_execute_exactly() {
    let set = parse_json(&fixture("vectors/http-signatures.json"));
    for id in [
        "http.route.control.roster.snapshot",
        "http.route.control.roster.snapshot.continuation",
    ] {
        let case = support::vector_case(&set, id);
        let mutation = case
            .member("mutations")
            .array()
            .iter()
            .find(|mutation| mutation.member("field").string() == "request.target.query-member")
            .expect("snapshot case declares duplicate query-member mutation");
        assert_eq!(mutation.member("operation").string(), "duplicate");
        assert_eq!(mutation.member("expected_code").string(), "invalid_request");

        let mut vector = build_request(case);
        apply_mutation(&mut vector, case, mutation);
        let query = std::str::from_utf8(&vector.request.target)
            .unwrap()
            .split_once('?')
            .unwrap()
            .1;
        let pairs: Vec<_> = query.split('&').collect();
        let names: Vec<_> = pairs
            .iter()
            .map(|pair| pair.split_once('=').unwrap().0)
            .collect();
        assert_eq!(pairs.len(), 2, "{id}");
        assert_eq!(names[0], names[1], "{id}");
        assert!(vector.request.target.len() <= 256, "{id}");
        assert_eq!(
            verify_request(&vector.request, &vector.context).unwrap_err(),
            ErrorClass::InvalidRequest,
            "{id}"
        );
    }
}

#[test]
fn every_in_scope_http_one_field_mutation_returns_its_exact_error_class() {
    let cases = http_cases();
    let mut consumed = 0;
    for case in &cases {
        for mutation in case.member("mutations").array() {
            let mutation_id = mutation.member("id").string();
            if mutation.member("field").string().starts_with("transcript.") {
                continue;
            }
            let mut vector = build_request(case);
            apply_mutation(&mut vector, case, mutation);
            let expected = error_class(mutation.member("expected_code").string());
            assert_eq!(
                verify_request(&vector.request, &vector.context).unwrap_err(),
                expected,
                "mutation {mutation_id} was not rejected at its declared admission class"
            );
            consumed += 1;
        }
    }
    assert_eq!(
        consumed, 506,
        "new in-scope HTTP mutations require an explicit test mutation implementation"
    );
}
