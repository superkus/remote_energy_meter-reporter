#!/bin/sh
set -u
repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT HUP INT TERM

matches_fail_closed_contract() {
  name=$1
  shift
  stdout="$temp/$name.stdout"
  stderr="$temp/$name.stderr"
  expected="$temp/$name.expected"
  printf 'WHOLE_SYSTEM_UNAVAILABLE\n' > "$expected"

  set +e
  "$@" > "$stdout" 2> "$stderr"
  status=$?
  set -e

  [ "$status" -eq 2 ] && [ ! -s "$stdout" ] && cmp -s "$expected" "$stderr"
}

cat > "$temp/stdout-only" <<'EOF'
#!/bin/sh
printf 'WHOLE_SYSTEM_UNAVAILABLE\n'
exit 2
EOF
cat > "$temp/extra-newline" <<'EOF'
#!/bin/sh
printf 'WHOLE_SYSTEM_UNAVAILABLE\n\n' >&2
exit 2
EOF
chmod +x "$temp/stdout-only" "$temp/extra-newline"

if matches_fail_closed_contract stdout-only "$temp/stdout-only"; then
  echo "FAIL - stdout-only output was accepted"
  exit 1
fi
if matches_fail_closed_contract extra-newline "$temp/extra-newline"; then
  echo "FAIL - extra trailing newline was accepted"
  exit 1
fi
reporter="$repo_root/target/debug/remote-energy-meter-reporter"
if [ ! -x "$reporter" ]; then
  echo "FAIL - build the reporter executable before running this contract test"
  exit 1
fi
if ! matches_fail_closed_contract executable "$reporter"; then
  echo "FAIL - reporter executable violated the fail-closed output contract"
  exit 1
fi

echo "fail-closed executable contract passed"
