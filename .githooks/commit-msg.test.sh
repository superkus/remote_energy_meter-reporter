#!/bin/sh
set -u
test_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
hook="$test_dir/commit-msg"
repo_root=$(dirname "$test_dir")
failures=0

expect() {
  description=$1 expected=$2 message=$3 gitleaks_version=${4:-8.30.1}
  temp=$(mktemp -d)
  tools="$temp/bin"
  mkdir -p "$tools"
  message_file="$temp/message"
  printf '%s\n' "$message" > "$message_file"
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version)
    printf '%s\n' "${GITLEAKS_TEST_VERSION:-8.30.1}"
    exit 0
    ;;
esac
if grep -F -- "${GITLEAKS_TEST_NEEDLE:-not-present}" >/dev/null; then
  exit 1
fi
exit 0
EOF
  chmod +x "$tools/gitleaks"
  GITLEAKS_TEST_VERSION="$gitleaks_version" GITLEAKS_TEST_NEEDLE="${GITLEAKS_TEST_NEEDLE:-not-present}" \
    PATH="$tools:$PATH" sh "$hook" "$message_file" >/dev/null 2>&1
  actual=$?
  rm -rf "$temp"
  if [ "$actual" -ne "$expected" ]; then
    echo "FAIL - $description (exit $actual, expected $expected)"
    failures=$((failures + 1))
  else
    echo "ok   - $description"
  fi
}

expect "clean commit metadata is accepted" 0 "documented change"
expect "an unpinned gitleaks version is refused" 1 "documented change" "8.29.0"
private_address="10"".""0"".""0"".""1"
expect "a local reference in a commit message is refused" 1 "diagnose $private_address"
marker="local-refs:"" allow"
expect "the policy bypass marker in a commit message is refused" 1 "$marker"
synthetic_secret="glpat-""AbCdEfGhIjKlMnOpQrSt"
GITLEAKS_TEST_NEEDLE=$synthetic_secret expect "a synthetic secret in a commit message is refused" 1 "$synthetic_secret"

[ "$failures" -eq 0 ] || exit 1
echo "all commit-msg guard checks passed"
