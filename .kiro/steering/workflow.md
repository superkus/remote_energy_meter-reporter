# Delivery workflow — MANDATORY

1. Work on `dev` or a feature branch. Protected `main` receives reviewed pull requests only. The sole bootstrap
   exception is the fully reviewed initial `main` publication needed to create the server-side ref. The hook allows it
   only for the configured `origin` push URL when that destination has no refs. Apply and verify branch protection
   immediately after that push, before creating `dev` or accepting any other change.
2. Understand and measure before changing. The Apple power source requires an external-meter spike before admission.
3. Write a regression/contract test first; then the minimal implementation; then refactor with tests green.
4. Every increment ends wired into an executable demo. Do not land orphaned production code.
5. Update README/design/protocol/security documentation and user changelog entries for what ships.
6. Enable hooks with `git config core.hooksPath .githooks`. Never use `--no-verify` or otherwise bypass a hook.
7. Run the full review gate, push through `.githooks/pre-push`, open a PR, wait for every required CI check, and let the
   user merge.
8. Never patch a live installation. Deploy only reviewed artifacts built from merged `main`.

## Required gates

### Local commit hooks

`.githooks/pre-commit` requires Gitleaks `8.30.1`, cargo-audit `0.22.2`, and cargo-deny `0.20.2` exactly, then runs:

- `gitleaks git --staged --pre-commit --config .gitleaks.toml --redact --no-banner .`
- `python3 tools/check_local_refs.py --staged`
- `python3 -m unittest tools/test_check_local_refs.py tools/test_scan_git_objects.py`
- `cargo fmt --all -- --check`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `cargo test --locked --all-targets --all-features`
- `cargo audit`
- `cargo deny check advisories bans licenses sources`

`.githooks/commit-msg` requires Gitleaks `8.30.1` exactly and scans the pending commit message with Gitleaks and the
local-reference policy. The hook rejects policy bypass markers in addition to local setup references.

### Local pre-push hook

`.githooks/pre-push` requires Gitleaks `8.30.1`, enforces the branch-routing policy, and scans every exact pushed
target. It accepts 40-hex SHA-1 and 64-hex SHA-256 object IDs, rejects malformed or mixed-width IDs, and fails closed
when an annotated tag has missing, duplicate, malformed, or unsupported target headers. It privately scans bounded
streams containing the local and remote ref names and each complete enumerated Git object payload: blob contents, tree
records, and commit/tag headers and messages. It unions overlapping pushed ranges and object IDs before scanning, and
one persistent Git reader feeds one Gitleaks process while preserving newline boundaries between objects. This includes
annotated and lightweight tags whose final targets are blobs or trees. Commit targets also receive one combined
Gitleaks commit-range scan. The local-reference scanner checks the private ref-name file and all selected revisions in
one invocation. The hook suppresses Gitleaks output for private streams and fails closed if an artifact or resource
limit prevents complete inspection:

- `gitleaks git --config .gitleaks.toml --redact --no-banner --log-opts="<combined-pushed-ranges>" .`
- `gitleaks stdin --config .gitleaks.toml --redact --no-banner` over the private pushed-ref stream
- `python3 tools/scan_git_objects.py "<private-object-index>"` for one bounded, batched Gitleaks object stream
- `python3 tools/check_local_refs.py --ref-file "<private-pushed-ref-file>"`
- `python3 tools/check_local_refs.py --history --revision "<revision>" ...`

### Full local review and CI

Run the hook self-tests and the local full-history and executable checks:

- `sh .githooks/pre-commit.test.sh`
- `sh .githooks/commit-msg.test.sh`
- `sh .githooks/pre-push.test.sh`
- `python3 tools/check_local_refs.py`
- `python3 tools/check_local_refs.py --history`
- `gitleaks git --config .gitleaks.toml --redact --no-banner --log-opts="--all HEAD" .`
- `cargo build --locked`
- `sh tests/fail_closed_executable.test.sh`

CI manually checksum-verifies the pinned Gitleaks archive and checks its reported version, then runs the following gate
commands. The private Gitleaks streams contain all fetched and triggering ref names and every complete fetched Git
object payload, including blob contents, tree records, commit/tag headers and messages, and non-commit targets reachable
from tags. A persistent Git batch reader validates each object's type, size, framing, count, and aggregate limits before
feeding one newline-separated Gitleaks stream. The dependency-policy job installs the configured cargo-audit and
cargo-deny versions. `1.99.1` is the resolved value of CI's pinned `RUST_TOOLCHAIN` variable.

- `gitleaks git --config .gitleaks.toml --redact --no-banner --log-opts="--all HEAD" .`
- `gitleaks stdin --config .gitleaks.toml --redact --no-banner` over the private fetched/triggering-ref stream
- `python3 tools/scan_git_objects.py "<private-object-index>"` for the bounded, batched object stream
- `python3 tools/check_local_refs.py`
- `python3 tools/check_local_refs.py --history`
- `python3 -m unittest tools/test_check_local_refs.py tools/test_scan_git_objects.py`
- `sh .githooks/pre-commit.test.sh`
- `sh .githooks/commit-msg.test.sh`
- `sh .githooks/pre-push.test.sh`
- `cargo +1.99.1 fmt --all -- --check`
- `cargo +1.99.1 clippy --locked --all-targets --all-features -- -D warnings`
- `cargo +1.99.1 test --locked --all-targets --all-features`
- `cargo +1.99.1 build --locked`
- `sh tests/fail_closed_executable.test.sh`
- `cargo audit`
- `cargo deny check advisories bans licenses sources`

The required CI check names are:

- `Secret scan (gitleaks)`
- `Local-setup reference scan`
- `Repository policy (hook self-tests)`
- `Rust (fmt + clippy + tests)`
- `Rust dependency policy (audit + deny)`

Release artifact signing/notarization checks become mandatory once packaging exists.

## Definition of done

Code/tests/docs committed; full local gates and review pass; PR CI green; demo exercised; deployed result verified where
applicable. If hardware/signing/external review prevents a criterion, mark the task blocked rather than weakening it.
