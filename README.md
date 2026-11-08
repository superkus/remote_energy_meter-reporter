# Remote Energy Meter Reporter

Native zero-trust whole-system power reporter for
[`superkus/remote_energy_meter`](https://github.com/superkus/remote_energy_meter).

## Current status

**Measurement qualification only. No installable reporter exists yet.** The executable deliberately exits with
`WHOLE_SYSTEM_UNAVAILABLE`. Apple exposes no documented public API for whole-system AC watts; Apple-silicon support
will be enabled only if a foreground hardware spike validates candidate laptop telemetry against an external wall meter.
CPU/GPU/package values and estimates are never relabelled as whole-system power.

```bash
cargo run --quiet
# stderr: WHOLE_SYSTEM_UNAVAILABLE
# exit status: 2
```

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
      "Rust dependency policy (audit + deny)"
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

Verify the live policy through the API immediately. The response must show `strict: true`, all five check names above,
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
branch and reaches `main` only through a pull request whose branch is up to date and whose five required checks pass.
Never push directly to `main`, including as an administrator. If a CI job is added, removed, or renamed, update and
verify the required check contexts through the branch-protection API in the same pull request.

## License

MIT
