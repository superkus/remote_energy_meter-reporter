# Remote Energy Meter Reporter

Native zero-trust whole-system power reporter for
[`superkus/remote_energy_meter`](https://github.com/superkus/remote_energy_meter).

## Current status

**The code-only Apple-silicon measurement spike passes on AC and battery for the tested laptop. No installable reporter
exists yet.** The executable still exits with `WHOLE_SYSTEM_UNAVAILABLE` because production source-loss, freshness,
transition, signing, and transport behavior has not been implemented. Apple exposes no documented public API for
system watts. The foreground spike qualifies selected laptop telemetry only for software-visible units, internal
consistency, source freshness, workload response, mode transitions, and resource use.

Code-only qualification does not establish physical accuracy. Any accepted value will be identified as
**Apple-reported system power** from an undocumented source. It is not externally calibrated or billing-grade and must
not be used for billing, settlement, or safety-critical decisions. Physical power meters are outside this project's
scope and are not a qualification requirement.

```bash
cargo run --quiet
# stderr: WHOLE_SYSTEM_UNAVAILABLE
# exit status: 2
```

## Measurement spike

The `spike` command reads only selected integer fields from the undocumented
`AppleSmartBattery.PowerTelemetryData` dictionary through public IOKit registry functions. From Apple's public
IOPowerSources API, it uses `Type` and `Is Present` only to select exactly one present `InternalBattery`; no matching
battery or multiple matching batteries makes the read fail closed. These selection-only fields are not emitted to CSV.
The direct public values retained for validation and CSV output are power mode, charging state, optional battery voltage,
and optional signed current. The spike does **not** implement the production `PowerSource`.

Each candidate uses a public/private/public bracket: the spike reads IOPowerSources, reads the private
`PowerTelemetryData` candidate, then reads IOPowerSources again. Both public reads must validate and report the same
classifiable AC or battery mode. Candidate selection and validation use that stable mode. The monotonic boundaries must
satisfy `reference_before_started <= reference_before_finished <= telemetry_finished <= reference_after_finished`, and
the complete bracket must take no more than one second. Exactly one second is accepted.

The CSV includes mode-selected `candidate_w`, separate `system_power_balance_relative_error` and
`mode_crosscheck_relative_error` fields, source accumulator
counts and values, and aggregate `hardware_update` state. Its acquisition-time columns are exactly `elapsed_ms`,
`reference_before_started_elapsed_ms`, `reference_before_finished_elapsed_ms`,
`telemetry_finished_elapsed_ms`, and `reference_after_finished_elapsed_ms`; `elapsed_ms` records the same boundary as
`telemetry_finished_elapsed_ms`. Separate `reference_before_` and `reference_after_` columns record
`platform_power_mode`, `battery_is_charging`, `battery_voltage_mv`, `battery_current_ma`, `battery_signed_w`, and
`battery_discharge_w` for each public read.

On AC, `candidate_w` is `SystemPowerIn`, which includes battery charging. On battery it is `SystemLoad`. Every selected
candidate must be finite, greater than zero, and no more than 100 kW. All consistency comparisons use milliwatts and the
exact rule `abs(a - b) <= max(1 mW, 0.01 * max(abs(a), abs(b)))`. The qualification protocol requires
`SystemPowerIn` to match `SystemLoad + BatteryPower` in every accepted snapshot. The
`system_power_balance_relative_error` field reports that mandatory three-field identity in both modes. The
`mode_crosscheck_relative_error` field reports AC input versus voltage × current on AC and `SystemLoad` versus
`abs(BatteryPower)` on battery. On battery, `BatteryPower` must be negative.

Apple's public IOPowerSources API independently supplies power mode and charging state. The collector also allowlists
its documented battery voltage and signed current when supplied. Missing optional fields remain empty rather than
being inferred. Signed terminal power preserves Apple's current sign; `battery_discharge_w` is emitted as a magnitude
only when the corresponding public read reports battery mode, not charging, and includes both voltage and current.
These optional values are diagnostic only and do not prove physical accuracy.

The command defaults to 10 samples at a 1,000 ms interval. `--samples` accepts the inclusive range 1–36,000, and
`--interval-ms` accepts 100–60,000 ms. Both flags are optional and may appear at most once. The scheduled span from the
first sample to the last, `(samples - 1) × interval_ms`, may not exceed ten hours (36,000,000 ms). This cap preserves the
five-minute qualification runs while preventing accidentally long foreground runs. Run `help` or `--help` with no
other arguments to print this usage and the ten-hour constraint to standard output and exit successfully:

```text
usage: remote-energy-meter-reporter [help | --help | spike [--samples 1..36000] [--interval-ms 100..60000]]
constraint: (samples - 1) * interval-ms <= 36000000 (10 hours)
```

Raw captures and resource measurements are private local data. Before every capture, set `umask 077`; the
`spike-data/` directory must be mode `0700`, and every capture or resource file in it must be mode `0600`. These
commands also repair permissions on existing files before writing a new capture:

```bash
umask 077
mkdir -p spike-data
chmod 0700 spike-data
find spike-data -type f -exec chmod 0600 {} +
cargo run --release --locked -- spike --samples 300 --interval-ms 1000 \
  > spike-data/idle-ac.csv
```

The command fails in controlled ways:

| Condition | Standard error | Exit status |
| --- | --- | ---: |
| Invalid, unknown, repeated, missing, non-numeric, out-of-range, or over-ten-hour sampling arguments | `usage: remote-energy-meter-reporter [help \| --help \| spike [--samples 1..36000] [--interval-ms 100..60000]]` followed by the ten-hour constraint | 64 |
| `spike` requested on a non-macOS platform | `WHOLE_SYSTEM_UNAVAILABLE` | 2 |
| IOKit telemetry cannot be opened or read on macOS | `TELEMETRY_UNAVAILABLE: <reason>` | 3 |
| A sample fails numeric safety checks | `TELEMETRY_UNAVAILABLE: <reason>` | 3 |
| CSV header or row cannot be written to standard output | No additional diagnostic | 74 |

The CSV contains elapsed acquisition timing, candidate power/voltage/current/energy fields, source accumulator
counts/values, hardware-update state, and only the CSV-emitted public battery values listed above. The spike does not
request machine identity fields, so the CSV contains no model, hostname, serial, hardware UUID, username, account, or
MAC address. `/spike-data/` is gitignored. A physical Apple-laptop test is ignored in normal CI and can be run explicitly
on qualifying hardware:

```bash
cargo test --locked --test macos_telemetry_live -- --ignored
```

Qualification uses one five-minute idle, CPU-load, and GPU-load run in each mode. The current bracketed matrix passes
for AC and battery on the tested laptop. Each workload run's median exceeds its mode's idle median. Every selected
candidate is finite, greater than zero, and at or below 100 kW; all direct checks use
`abs(a - b) <= max(1 mW, 0.01 * max(abs(a), abs(b)))`.

Freshness applies separately to `SystemPowerInAccumulatorCount` on AC and to both
`SystemLoadAccumulatorCount` and `BatteryDischargeAccumulatorCount` on battery. For each counter, the first valid
atomic accumulator/count/direct observation starts freshness age, and each positive count delta resets it. A zero delta
is valid only before 90 monotonic seconds have elapsed; it is stale at exactly 90 seconds. A decrease or wrap fails
immediately. One counter's advance cannot refresh another.

A positive count delta closes a source-owned interval. Its accumulator delta divided by count delta must be finite,
have the required sign, remain within the hard ceiling, and follow workload direction. Matching battery load and
discharge intervals must be signed inverses under the direct-check tolerance. Direct process reads are not synchronized
to Apple's private accumulator boundaries, so repeated values are not assigned to hidden intervals or presented as a
pointwise accumulator-accuracy comparison.

Reporter CPU must average below 0.5% of one core, and physical memory must remain below 30 MiB. A failed bracket,
bounds check, direct consistency check, freshness check, accumulator sign/bounds/direction check, workload comparison,
source read, or mode transition leaves that mode unsupported. The future signed reporter must emit
`WHOLE_SYSTEM_UNAVAILABLE` immediately and on its normal cadence, clear prior-mode sample and accumulator baselines,
and admit no new-mode value until a complete bracketed snapshot passes.

The qualification run observed both physical mode transitions. Immediately after each transition, public mode changed
before the private candidate did, so the bracketed collector rejected the stale prior-mode candidate with exit status
3. It accepted the new mode only after the next source-owned update. See
`docs/qualification/apple-silicon-preliminary.md` for the non-identifying aggregate results and exact limits. Physical
power meters remain outside this project's scope; no software-consistency result is an accuracy claim.

## Protocol v1 primitives (draft)

**Draft, not approved for distribution, and pending independent security review.** The `protocol_v1` library module
implements the Rust half of protocol task 3.2 and the Rust SAS half of task 3.3 against the server-owned REM protocol
v1 profile, which is vendored byte-for-byte under `tests/fixtures/protocol/v1/` at the commit recorded in `PROVENANCE.txt`. That profile is itself a
normative draft: task 3.4's independent security review must approve it before any reporter build that speaks it is
distributed. Nothing in this repository listens on or sends the protocol; the reporter executable is unchanged and still
exits with `WHOLE_SYSTEM_UNAVAILABLE`.

The module provides strict, fail-closed primitives. Every failure returns only a closed problem class, never request
input or key material.

- `b64u`: canonical unpadded base64url with exact (`b64u<n>`) or inclusive 1–*n* (`opaque128`/`opaque256`) decoded
  lengths; padding, whitespace, the standard alphabet, and non-zero trailing bits are rejected. `Debug` never prints
  value bytes, and equality compares decoded values in constant time.
- `transcript`: the `REM-TRANSCRIPT` encoding and exact decoder. `encode_transcript` validates the purpose and each
  field-name label as non-empty visible ASCII of at most 65,535 bytes; `TranscriptField::new` only constructs a
  candidate. Encoding also rejects duplicate names and enforces a caller cap (4096 bytes for every bounded transcript)
  before allocation. The exact decoder rejects unexpected field order and unknown or omitted fields.
- `canonical_json`: exact `rem-canonical-json-v1` checks (no BOM or insignificant whitespace outside strings; whitespace
  remains valid as string content; sorted ASCII member names; canonical escapes; non-negative canonical integers within
  `uint64`; at most six non-trailing-zero fraction digits; depth 8; 64 KiB). Accepted bytes are kept, never
  re-serialized. Schema validation is not part of this module.
- `jwk`: the exact four-member canonical P-256 public JWK; duplicate, extra, and private `d` members, other orders,
  whitespace, off-curve points, and coordinates outside the field are rejected. RFC 7638 canonical bytes and the SHA-256
  thumbprint (`keyid`) are exposed.
- `content_digest`: the single-member RFC 9530 `sha-256=:…:` form (at most 256 bytes) with constant-time body
  verification.
- `signature`: 64-byte IEEE P1363 ECDSA P-256/SHA-256 verification that rejects other lengths, zero or out-of-range
  scalars, and high-S signatures. DER is never accepted.
- `sas`: exact six-byte interactive SAS derivation with SHA-256 and HKDF-SHA-256, plus exact alternating
  Even/Odd rendering, strict six-word ASCII parsing, and constant-time authentication-byte verification. The production
  library embeds no word data; callers load separately distributed resources through a length-, hash-, and
  structure-pinned `SasWordLists`.
- `routes`: a compiled route table that a test compares field by field with the vendored `routes.json` for the
  in-scope admission fields, while explicitly accounting for the deferred schema and stateful-replay fields. Lookup
  validates the exact method, the 256-byte target cap, the narrow target grammar (no percent encoding, fragments, dot or
  empty segments, or trailing slash), typed path parameters, exact query forms, and the not-found/method-not-allowed
  order.
- `http_signature`: `reporter-rfc9421-v1` and `control-rfc9421-v1` verification in the profile's admission order:
  route lookup, header caps, body cap and media type, framing headers, the exact REM header set, digest and canonical
  body, then the signature step. HTTP-signature admission validates canonical lowercase IDNA2008 A-label authorities,
  including numeric-address and reserved-LDH rejection. `RawRequest` is already buffered, including its authority and
  body. The library authority and body cap checks are defense in depth: they cannot prevent the caller from allocating
  oversized values first. Any later executable HTTP transport integration must enforce the 259-byte authority cap while
  parsing, before buffering an oversized authority, and count body bytes while streaming so it can abort an oversized
  request before allocating or buffering the full body.
  Schema semantics are separately deferred and are not supplied by transport or library body caps. The verifier requires
  the dispatcher-selected manifest route and rejects a target that resolves to another route before authentication.
  `Signature-Input` and `Signature` accept only the profile's exact serialization; the base is rebuilt from the raw
  method, authority, path, query, named query values, and trimmed header values. Every covered component, parameter,
  purpose (including the body-mode selection for enrollment creation), `alg`, `keyid`, active and proposed control key
  generations, nonce, and expiry is checked. Reporter `Signature-Input` carries no `created` or other client clock;
  control `created`/`expires`/`nonce` freshness uses the caller's server receipt time. The `rem-proposed`
  label is required on `control.control-key-rotation.complete` and rejected elsewhere. A successful verification returns
  a stable, comparable `VerifiedIdentity` containing the complete exact request, its unambiguous length-delimited SHA-256
  request hash, the principal identity supplied by the trusted key binding (not rederived from the rotatable `keyid`),
  route, raw target and query, keyids, optional control generation/`created`/nonce/expiry, reporter session/sequence,
  and digest for replay logic. Reporter identities contain no client-clock value. Stateful
  replay protection itself is out of scope. The signer helper (`signature_material`) applies the same stateless
  pre-signature parsing, caps, media-type, framing, digest, canonical-body, REM-header, and purpose checks before
  producing its signature base. Contextual checks remain verifier responsibilities: dispatcher-selected route binding,
  configured authority, trusted key and generation binding, and server-receipt-time freshness. Stateful replay remains
  the caller's responsibility.

### Demonstration

```bash
cargo run --locked --example protocol_v1_sign_demo
```

The example generates an **ephemeral software P-256 key in memory** from the system CSPRNG, signs one canonical report
request, self-verifies it, and writes one machine-readable canonical JSON object to stdout. The closed object contains
only the public JWK, stable identity, route, exact request method/authority/target/body and ordered headers as lowercase
hex, `Signature-Input`, `Signature`, and the exact signature base. Reporter `Signature-Input` omits `created`. The
private key is never serialized, printed, logged, or stored; the example sends nothing. **Production persistent reporter
keys must be non-exportable System Keychain keys** used by a Developer ID-signed and notarized daemon; software keys
are for demonstrations and tests only.

The following network-free handoff uses a caller-provided local Git checkout or bare mirror of the server repository.
It exports the server package from the verified commit, so working-tree changes cannot affect the check. Set
`SERVER_PYTHON` to a Python 3.12 interpreter that already has that server commit's locked runtime dependencies; the
procedure does not install or download anything.

```bash
REPORTER_SOURCE=/path/to/reporter-source
SERVER_GIT=/path/to/server-git-checkout-or-bare-mirror
SERVER_PYTHON=/path/to/python-with-server-runtime-dependencies
SERVER_COMMIT=13d9b3e67b68a4bc3f3ce473c0ac7dae125849ed
work_dir="$(mktemp -d)"
trap 'rm -r "$work_dir"' EXIT

git -C "$SERVER_GIT" cat-file -e "${SERVER_COMMIT}^{commit}"
test "$(git -C "$SERVER_GIT" rev-parse "${SERVER_COMMIT}^{commit}")" = "$SERVER_COMMIT"
mkdir "$work_dir/server"
git -C "$SERVER_GIT" archive "$SERVER_COMMIT" | tar -x -C "$work_dir/server"
cargo run --quiet --locked --manifest-path "$REPORTER_SOURCE/Cargo.toml" \
  --example protocol_v1_sign_demo >"$work_dir/demo.json"

PYTHONPATH="$work_dir/server/src" "$SERVER_PYTHON" - "$work_dir/demo.json" <<'PY'
import base64
import json
import sys

from remote_energy_meter.protocol_v1 import (
    ProtocolViolation,
    SignedRequest,
    VerificationKey,
    parse_p256_public_jwk,
    route_profile,
    verify_signed_request,
)

with open(sys.argv[1], encoding="utf-8") as stream:
    demo = json.load(stream)
wire = demo["request"]
request = SignedRequest(
    method=bytes.fromhex(wire["method_hex"]),
    authority=bytes.fromhex(wire["authority_hex"]),
    target=bytes.fromhex(wire["target_hex"]),
    headers=tuple(
        (bytes.fromhex(field["name_hex"]), bytes.fromhex(field["value_hex"]))
        for field in wire["headers"]
    ),
    body=bytes.fromhex(wire["body_hex"]),
)
public_jwk = parse_p256_public_jwk(
    json.dumps(demo["public_jwk"], separators=(",", ":")).encode("ascii")
)
key = VerificationKey(identity=demo["stable_identity"], public_jwk=public_jwk)
verify_args = {
    "route": route_profile(demo["route"]),
    "keys": {"rem": key},
    "expected_authority": b"ha.example.com:58443",
    "received_at": 0,
    "active_control_generation": None,
}
verified = verify_signed_request(request, **verify_args)
assert verified.request == request
assert verified.route_id == demo["route"]
assert verified.verified_identity == demo["stable_identity"]
assert dict(verified.signature_bases) == {
    "rem": bytes.fromhex(demo["signature_base_hex"])
}

signature_header = next(value for name, value in request.headers if name == b"signature")
assert signature_header.startswith(b"rem=:") and signature_header.endswith(b":")
signature = bytearray(base64.b64decode(signature_header[5:-1], validate=True))
signature[0] ^= 1
mutated_header = b"rem=:" + base64.b64encode(signature) + b":"
mutated_request = SignedRequest(
    method=request.method,
    authority=request.authority,
    target=request.target,
    headers=tuple(
        (name, mutated_header if name == b"signature" else value)
        for name, value in request.headers
    ),
    body=request.body,
)
try:
    verify_signed_request(mutated_request, **verify_args)
except ProtocolViolation as error:
    assert error.code == "authentication_required"
else:
    raise AssertionError("one-byte signature mutation was accepted")
PY
```

The SAS demonstration reads the two licensed tables from explicit paths rather than embedding them in the production
library. Each path is read through a 2,408-byte hard cap, so an oversized resource is rejected before unbounded
allocation. For the pinned interactive vector it prints the exact six bytes and six-word phrase:

```bash
cargo run --quiet --locked --example protocol_v1_sas_demo -- \
  tests/fixtures/protocol/v1/pgp-word-list/even.txt \
  tests/fixtures/protocol/v1/pgp-word-list/odd.txt
# 4df104cfb9f9
# dreadful vacancy adrift Saturday sentence Waterloo
```

### Testing

```bash
cargo test --locked --all-features --example protocol_v1_sign_demo --example protocol_v1_sas_demo \
  --test protocol_v1_fixture --test protocol_v1_primitives --test protocol_v1_http_signatures \
  --test protocol_v1_admission --test protocol_v1_routes_manifest --test protocol_v1_sas
```

The fixture test pins the vendored corpus's file set, every SHA-256, and the case and mutation counts. The vector tests
re-encode every published bounded transcript, execute all six structural transcript mutations against the exact decoder,
accept every published canonical JSON value, verify every JWK- and SPKI-backed transcript signature and reject its
altered and high-S forms, reproduce all 25 HTTP signature cases and identities, and apply all 506 in-scope HTTP
one-field mutations from `http-signatures.json` and the dual-key case in `key-rotations.json`, each of which must fail
with its exact declared class. The SAS tests independently reproduce the merged interactive vector's transcript,
SHA-256 salt, HKDF output, and phrase; cover all 256 indexes in every one of six positions; enforce exact ASCII,
case, list parity, punctuation, and spacing; exercise nonce/transcript/phrase boundaries; and reject one valid-word
mutation in every position. This includes executable duplicate-query-member mutations for both singleton roster
snapshot forms. Further tests cover the signer round trip against every HTTP signature vector, output privacy and the
closed machine-readable example schema, caller-resource SAS rendering, the dual-label route, server-time freshness
edges, admission caps, and requests that a compromised key holder signs with internally inconsistent parameters. This
coverage does not claim MQTT, managed-token HMAC, schema, or stateful-replay conformance.

### Dependencies and security behavior

Runtime dependencies are exact-pinned and feature-minimized: `hkdf =0.13.0`, `idna =1.1.0` (`default-features = false`,
`alloc` and `compiled_data`), `p256 =0.14.0` (`default-features = false`, `ecdsa` only), `sha2 =0.11.1` and
`subtle =2.6.1` (all use `default-features = false`; `idna` enables only `alloc` and `compiled_data`, and `p256` only
`ecdsa`). `hkdf` is used only for the fixed HKDF-SHA-256 extract/expand operation needed by the six-byte SAS. The IDNA
dependency validates canonical A-label authorities against its compiled Unicode
data without network access. The `getrandom` feature of `p256` is enabled only as a development dependency for the
example and tests, so the production dependency graph contains no random-number source. P-256 signing code from
`p256`'s `ecdsa` feature is compiled into the library because that crate offers no verification-only feature; the
library uses only verification. `cargo audit` and `cargo deny` cover the additions.

### Word-list data license

All Rust code, tests, examples, and ordinary documentation remain MIT licensed. Only
`tests/fixtures/protocol/v1/pgp-word-list/even.txt` and `odd.txt` are GFDL-1.2-only data. Their adjacent
`notice.md` records the source, authorship, extraction, hashes, and redistribution boundary; `gfdl-1.2.txt` is the full
applicable license. The production library does not embed these files. Tests and the SAS demonstration read them as
caller-provided resources. Later packaging must ship any byte-identical data copies as separate files with the complete
adjacent notice and license, and must identify those copies as GFDL-1.2-only without changing the MIT license on Rust
code.

### Remaining protocol work

- The executable example provides the Rust-to-Python handoff used to verify a generated signature with the server package
  from the pinned source commit and reject a one-byte mutation. It remains a local, network-free demonstration rather
  than a persisted fixture or runtime transport.
- Not implemented here: schema semantics or validation; stateful replay stores; executable HTTPS transport integration,
  including streaming body counting and abort before full-body allocation; TLS connection, rate, and concurrency limits;
  problem-response rendering; MQTT AEAD; enrollment state-machine integration around the implemented SAS primitives;
  rotation; and System Keychain signing. Any later executable
  integration remains blocked until its schema, stateful replay, and transport-layer admission work is implemented and
  reviewed.
- Task 3.4's independent security review of the profile and this implementation.

## Security baseline

- No LAN, VPN, loopback, discovery result, or service network is trusted.
- No permanent bearer API key; the installed reporter will use a non-exportable P-256 identity and signed HTTPS
  requests over TLS 1.3.
- Unsigned/ad-hoc code is limited to the foreground measurement spike. A persistent daemon or distributed package
  requires Developer ID signing and notarization.
- No self-updater. Updates use MDM or explicit package replacement.
- No hardware UUID/serial, username/account, or MAC address is transmitted.
- Store every raw measurement capture in the repository-root `./spike-data/` directory. That directory is gitignored
  because captures can reveal local machine context. A capture stored anywhere else is not protected by this rule and
  must not be created, staged, or committed.
- Export and commit only reviewed, UTF-8 text aggregate reports that use neutral labels and contain no raw capture data
  or local setup details. The local-reference scanner rejects unsupported binary artifacts rather than publishing data
  it cannot inspect.

See `.kiro/steering/` for mandatory rules. The protocol is owned by the server repository's
`.kiro/specs/native-computer-reporters/` specification.

## Development prerequisites

Install these prerequisites before enabling the hooks:

- Git and Python 3;
- `curl`, `shasum`, and `tar` for the checksum-verified Gitleaks installation;
- rustup and the Rust `1.99.1` toolchain from `rust-toolchain.toml`;
- GitHub CLI (`gh`) for repository bootstrap and branch-protection verification.

Install the pinned Rust toolchain and policy tools. `--locked` uses each published crate's lockfile, and `--force`
replaces a different installed version.

```bash
rustup toolchain install 1.99.1 --profile minimal --component clippy,rustfmt
cargo +1.99.1 install --locked --force cargo-audit --version 0.22.2
cargo +1.99.1 install --locked --force cargo-deny --version 0.20.2
cargo-audit --version  # cargo-audit 0.22.2
cargo-deny --version   # cargo-deny 0.20.2
```

Install Gitleaks `8.30.1` from its release archive. This selects the macOS archive for the current architecture and
verifies the pinned SHA-256 digest before installing the binary. Ensure `${HOME}/.local/bin` remains on `PATH` for Git
hooks.

```bash
version=8.30.1
case "$(uname -m)" in
  arm64)
    archive="gitleaks_${version}_darwin_arm64.tar.gz"
    sha256="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
    ;;
  x86_64)
    archive="gitleaks_${version}_darwin_x64.tar.gz"
    sha256="dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"
    ;;
  *)
    printf 'unsupported macOS architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --connect-timeout 10 --max-time 120 \
  --output "$work_dir/$archive" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}"
printf '%s  %s\n' "$sha256" "$work_dir/$archive" | shasum -a 256 --check
mkdir -p "${HOME}/.local/bin"
tar -xzf "$work_dir/$archive" -C "$work_dir" gitleaks
install -m 0755 "$work_dir/gitleaks" "${HOME}/.local/bin/gitleaks"
export PATH="${HOME}/.local/bin:${PATH}"
gitleaks version  # 8.30.1
```

CI independently downloads Gitleaks `8.30.1`, manually verifies the pinned Linux archive checksum, and checks the
reported version before executing it. The pre-commit hook requires the exact Gitleaks, cargo-audit, and cargo-deny
versions above. The `commit-msg` and pre-push hooks require the exact Gitleaks version but do not check the two Cargo
policy tools. CI installs the configured cargo-audit and cargo-deny versions and runs self-tests for all three hooks.

## Enable and run local gates

Enable the repository hooks once per checkout, then verify the setting. Never use `--no-verify` or invoke Git with a
configuration that bypasses the hooks.

To scan installation-specific names without publishing them, put one literal term per line in
`.local-refs-denylist` at the repository root. The default file is gitignored. Blank lines and lines whose first
non-whitespace character is `#` are ignored; surrounding whitespace is removed from every other line. Each term uses
case-insensitive literal substring matching. Set `LOCAL_REFS_DENYLIST` to use a different file, and keep that file
untracked as well. If the file does not exist, the scanner still applies its public generic rules.

```bash
git config core.hooksPath .githooks
test "$(git config --get core.hooksPath)" = ".githooks"
```

The pre-commit hook requires the exact versions of all three policy tools, runs this sequence, and stops on the first
failure. The `commit-msg` hook separately requires Gitleaks `8.30.1`, then scans the pending commit message with the
local-reference policy and the pinned Gitleaks rules before Git creates the commit. It does not invoke cargo-audit or
cargo-deny.

```bash
gitleaks version  # must be 8.30.1
cargo-audit --version  # must be cargo-audit 0.22.2
cargo-deny --version   # must be cargo-deny 0.20.2
gitleaks git --staged --pre-commit --config .gitleaks.toml --redact --no-banner .
python3 tools/check_local_refs.py --staged
python3 -m unittest tools/test_check_local_refs.py tools/test_scan_git_objects.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo audit
cargo deny check advisories bans licenses sources
```

The pre-push hook requires Gitleaks `8.30.1`; it does not check cargo-audit or cargo-deny. It first refuses direct
updates to an existing `main` or any `master` branch. Its only `main` exception is the single-ref initial publication
described below. For every pushed target, Gitleaks privately scans bounded local and remote ref-name streams and the
complete payload of every enumerated Git object: blob contents, tree records, and commit/tag headers and messages. The
hook accepts the 40-hex SHA-1 and 64-hex SHA-256 object IDs used by Git repositories and rejects mixed-width or malformed
identifiers. The scan includes annotated and lightweight tags whose final targets are blobs or trees, not only commit
history, and fails closed when an annotated tag has missing, duplicate, malformed, or unsupported target headers.
Commit targets receive one combined Gitleaks history scan. Overlapping ranges and object IDs are deduplicated, and one
persistent Git reader feeds one bounded Gitleaks object stream with explicit newline boundaries between complete
objects. Scanner output for the private streams is suppressed so rejected metadata is not copied into diagnostics. The
local-reference scanner checks the ref names, then checks all selected revisions' commit and tag metadata, every path,
and every text blob in one invocation. Both scans fail closed when an artifact or resource limit prevents complete
inspection.

```bash
gitleaks version  # must be 8.30.1
gitleaks git --config .gitleaks.toml --redact --no-banner --log-opts="<combined-pushed-ranges>" .
gitleaks stdin --config .gitleaks.toml --redact --no-banner  # private bounded pushed-ref stream
python3 tools/scan_git_objects.py "<private-object-index>"  # bounded, batched Git-object stream
python3 tools/check_local_refs.py --ref-file "<private-pushed-ref-file>"
python3 tools/check_local_refs.py --history --revision "<revision>" ...
```

Run the hook self-tests and the remaining local full-history and executable checks before publication. The pre-push
hook performs the publication-range checks shown above.

```bash
sh .githooks/pre-commit.test.sh
sh .githooks/commit-msg.test.sh
sh .githooks/pre-push.test.sh
python3 tools/check_local_refs.py
python3 tools/check_local_refs.py --history
gitleaks git --config .gitleaks.toml --redact --no-banner --log-opts="--all HEAD" .
cargo build --locked
sh tests/fail_closed_executable.test.sh
```

CI repeats the full-history Gitleaks scan, then privately scans bounded streams containing all fetched and triggering
ref names and the complete payload of every fetched Git object. This covers blob contents, tree records, commit/tag
headers and messages, and non-commit targets reachable from tags. It runs the local-reference scanner against both
current tracked files and full history, including Git metadata and path names, then runs all three hook self-tests. Its
Rust jobs use the configured toolchain and install the configured cargo-audit and cargo-deny versions.

## Repository bootstrap and branch protection

Use this one-time pre-publication procedure only when creating the remote repository and its initial `main` ref. Create
an empty GitHub repository without generated files, add the intended destination as `origin` in the reviewed baseline
checkout, and confirm that its configured push URL is the destination Git will receive. The destination must have no
refs. Complete all local gates, then make the one allowed initial `main` push by using the `origin` remote. The hook
requires Git's remote name and URL arguments to match the configured `origin` push URL and requires
`git ls-remote --refs origin` to return no refs. Do not create or push `dev`, tags, or any other ref with that push.
Existing clones and later checkouts must follow the protected-branch workflow below; they must not assume that a remote
is absent or repeat the bootstrap exception.

Immediately after that initial push, before creating `dev` or accepting any other change, apply the following protection
to `main`. It applies to administrators, requires pull requests with resolved review conversations, requires branches
to be up to date, blocks force pushes and deletion, and requires every current CI job.

```bash
REPO="superkus/remote_energy_meter-reporter"
gh api --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "repos/${REPO}/branches/main/protection" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Secret scan (gitleaks)",
      "Local-setup reference scan",
      "Repository policy (hook self-tests)",
      "Rust (fmt + clippy + tests)",
      "Rust dependency policy (audit + deny)",
      "macOS ARM (compile + tests)"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 0,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_conversation_resolution": true,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "lock_branch": false,
  "allow_fork_syncing": false
}
JSON
```

Verify the live policy through the API immediately. The response must show `strict: true`, all six check names above,
`enforce_admins: true`, `pull_requests: true`, `dismiss_stale_reviews: true`, `approvals: 0`,
`conversations: true`, `force_pushes: false`, and `deletions: false`.

```bash
gh api \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "repos/${REPO}/branches/main/protection" \
  --jq '{
    strict: .required_status_checks.strict,
    checks: [.required_status_checks.checks[].context],
    enforce_admins: .enforce_admins.enabled,
    pull_requests: (.required_pull_request_reviews != null),
    dismiss_stale_reviews: .required_pull_request_reviews.dismiss_stale_reviews,
    approvals: .required_pull_request_reviews.required_approving_review_count,
    conversations: .required_conversation_resolution.enabled,
    force_pushes: .allow_force_pushes.enabled,
    deletions: .allow_deletions.enabled
  }'
```

After protection is verified, create `dev` from the protected `main` baseline. All later work lands on `dev` or a feature
branch and reaches `main` only through a pull request whose branch is up to date and whose six required checks pass.
Never push directly to `main`, including as an administrator. If a CI job is added, removed, or renamed, update and
verify the required check contexts through the branch-protection API in the same pull request.

## License

MIT
