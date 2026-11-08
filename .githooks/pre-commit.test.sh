#!/bin/sh
set -u
test_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
hook="$test_dir/pre-commit"
failures=0

expect_versions() {
  description=$1 expected=$2 gitleaks_version=$3 audit_version=$4 deny_version=$5
  temp=$(mktemp -d)
  cat > "$temp/tool-stub" <<'EOF'
#!/bin/sh
tool=${0##*/}
case "$tool" in
  gitleaks)
    case "${1-}" in
      version|--version) printf '%s\n' "${GITLEAKS_TEST_VERSION:-8.30.1}" ;;
    esac
    ;;
  cargo-audit)
    [ "${1-}" = "--version" ] && printf 'cargo-audit %s\n' "${CARGO_AUDIT_TEST_VERSION:-0.22.2}"
    ;;
  cargo-deny)
    [ "${1-}" = "--version" ] && printf 'cargo-deny %s\n' "${CARGO_DENY_TEST_VERSION:-0.20.2}"
    ;;
  cargo)
    if [ "${1-}" = "audit" ] && [ "${2-}" = "--version" ]; then
      printf 'cargo-audit %s\n' "${CARGO_AUDIT_TEST_VERSION:-0.22.2}"
    elif [ "${1-}" = "deny" ] && [ "${2-}" = "--version" ]; then
      printf 'cargo-deny %s\n' "${CARGO_DENY_TEST_VERSION:-0.20.2}"
    fi
    ;;
esac
exit 0
EOF
  for tool in gitleaks python3 cargo cargo-audit cargo-deny; do
    cp "$temp/tool-stub" "$temp/$tool"
  done
  chmod +x "$temp/gitleaks" "$temp/python3" "$temp/cargo" "$temp/cargo-audit" "$temp/cargo-deny"
  GITLEAKS_TEST_VERSION="$gitleaks_version" \
    CARGO_AUDIT_TEST_VERSION="$audit_version" \
    CARGO_DENY_TEST_VERSION="$deny_version" \
    PATH="$temp:$PATH" sh "$hook" >/dev/null 2>&1
  actual=$?
  rm -rf "$temp"
  if [ "$actual" -ne "$expected" ]; then
    echo "FAIL - $description (exit $actual, expected $expected)"
    failures=$((failures + 1))
  else
    echo "ok   - $description"
  fi
}

expect_versions "pinned tool versions are accepted" 0 "8.30.1" "0.22.2" "0.20.2"
expect_versions "an unpinned gitleaks version is refused" 1 "8.29.0" "0.22.2" "0.20.2"
expect_versions "an unpinned cargo-audit version is refused" 1 "8.30.1" "0.22.1" "0.20.2"
expect_versions "an unpinned cargo-deny version is refused" 1 "8.30.1" "0.22.2" "0.20.1"

[ "$failures" -eq 0 ] || exit 1
echo "all pre-commit tool-version checks passed"
