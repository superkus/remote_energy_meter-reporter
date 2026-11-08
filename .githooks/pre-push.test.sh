#!/bin/sh
set -u
test_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
hook="$test_dir/pre-push"
repo_root=$(dirname "$test_dir")
sha=$(git -C "$repo_root" rev-parse HEAD)
remote_sha=$sha
zero=0000000000000000000000000000000000000000
failures=0
expect() {
  description=$1 expected=$2 input=$3
  gitleaks_version=${4:-8.30.1}
  # Replace external scan tools so this test isolates branch routing behavior.
  temp=$(mktemp -d)
  cat > "$temp/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version) printf '%s\n' "${GITLEAKS_TEST_VERSION:-8.30.1}" ;;
esac
exit 0
EOF
  printf '#!/bin/sh\nexit 0\n' > "$temp/python3"
  chmod +x "$temp/gitleaks" "$temp/python3"
  printf '%s\n' "$input" | GITLEAKS_TEST_VERSION="$gitleaks_version" PATH="$temp:$PATH" \
    sh "$hook" origin example.invalid:repo >/dev/null 2>&1
  actual=$?
  rm -rf "$temp"
  if [ "$actual" -ne "$expected" ]; then
    echo "FAIL - $description (exit $actual, expected $expected)"
    failures=$((failures + 1))
  else
    echo "ok   - $description"
  fi
}
expect "dev is allowed" 0 "refs/heads/dev $sha refs/heads/dev $zero"
expect "feature branch is allowed" 0 "refs/heads/feature/x $sha refs/heads/feature/x $zero"
expect "tag is allowed" 0 "refs/tags/v1 $sha refs/tags/v1 $zero"
expect "an existing main is refused" 1 "refs/heads/main $sha refs/heads/main $remote_sha"
expect "master is refused" 1 "refs/heads/master $sha refs/heads/master $zero"
expect "dev to new remote main is refused" 1 "refs/heads/dev $sha refs/heads/main $zero"
expect "deleting main is refused" 1 "(delete) $zero refs/heads/main $sha"
expect "main-like feature is allowed" 0 "refs/heads/main-docs $sha refs/heads/main-docs $zero"
expect "initial main plus dev is refused" 1 "refs/heads/main $sha refs/heads/main $zero
refs/heads/dev $sha refs/heads/dev $zero"
expect "initial main plus feature is refused" 1 "refs/heads/feature/x $sha refs/heads/feature/x $zero
refs/heads/main $sha refs/heads/main $zero"
expect "initial main plus tag is refused" 1 "refs/heads/main $sha refs/heads/main $zero
refs/tags/v1 $sha refs/tags/v1 $zero"
expect "an unpinned gitleaks version is refused" 1 \
  "refs/heads/dev $sha refs/heads/dev $zero" "8.29.0"

expect_unreferenced_pushed_commit_is_scanned() {
  temp=$(mktemp -d)
  repo="$temp/repo"
  tools="$temp/bin"
  mkdir -p "$repo/tools" "$tools"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  printf 'host 192.0.2.1\n' > "$repo/data.txt"
  git -C "$repo" add data.txt
  git -C "$repo" commit -q -m clean
  git -C "$repo" checkout -q --detach HEAD
  private_address="10"".""0"".""0"".""1"
  printf 'host %s\n' "$private_address" > "$repo/data.txt"
  git -C "$repo" commit -q -am pushed
  pushed_sha=$(git -C "$repo" rev-parse HEAD)
  git -C "$repo" checkout -q --detach HEAD^
  cp "$repo_root/tools/check_local_refs.py" "$repo/tools/check_local_refs.py"
  cp "$repo_root/tools/scan_git_objects.py" "$repo/tools/scan_git_objects.py"
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version) printf '%s\n' '8.30.1' ;;
  stdin) cat >/dev/null ;;
esac
exit 0
EOF
  chmod +x "$tools/gitleaks"
  printf 'refs/heads/feature/x %s refs/heads/feature/x %s\n' "$pushed_sha" "$zero" | \
    (cd "$repo" && PATH="$tools:$PATH" sh "$hook" origin example.invalid:repo) >/dev/null 2>&1
  actual=$?
  rm -rf "$temp"
  if [ "$actual" -ne 1 ]; then
    echo "FAIL - an unreferenced pushed commit is scanned (exit $actual, expected 1)"
    failures=$((failures + 1))
  else
    echo "ok   - an unreferenced pushed commit is scanned"
  fi
}
expect_unreferenced_pushed_commit_is_scanned

expect_sensitive_pushed_refs_are_refused() {
  temp=$(mktemp -d)
  repo="$temp/repo"
  tools="$temp/bin"
  mkdir -p "$repo/tools" "$tools"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  git -C "$repo" commit -q --allow-empty -m clean
  commit_sha=$(git -C "$repo" rev-parse HEAD)
  cp "$repo_root/tools/check_local_refs.py" "$repo/tools/check_local_refs.py"
  cp "$repo_root/tools/scan_git_objects.py" "$repo/tools/scan_git_objects.py"
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version) printf '%s\n' '8.30.1' ;;
  stdin) cat >/dev/null ;;
esac
exit 0
EOF
  chmod +x "$tools/gitleaks"
  sensitive_ref="refs/heads/diagnostics/device"".""local"
  for side in local remote; do
    if [ "$side" = local ]; then
      input="$sensitive_ref $commit_sha refs/heads/feature/x $zero"
    else
      input="refs/heads/feature/x $commit_sha $sensitive_ref $zero"
    fi
    printf '%s\n' "$input" | \
      (cd "$repo" && PATH="$tools:$PATH" sh "$hook" origin example.invalid:repo) >/dev/null 2>&1
    actual=$?
    if [ "$actual" -ne 1 ]; then
      echo "FAIL - a sensitive $side ref name is refused (exit $actual, expected 1)"
      failures=$((failures + 1))
    else
      echo "ok   - a sensitive $side ref name is refused"
    fi
  done
  rm -rf "$temp"
}
expect_sensitive_pushed_refs_are_refused

expect_secret_ref_names_are_scanned() {
  temp=$(mktemp -d)
  repo="$temp/repo"
  tools="$temp/bin"
  output="$temp/output"
  mkdir -p "$repo/tools" "$tools"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  git -C "$repo" commit -q --allow-empty -m clean
  commit_sha=$(git -C "$repo" rev-parse HEAD)
  cp "$repo_root/tools/check_local_refs.py" "$repo/tools/check_local_refs.py"
  cp "$repo_root/tools/scan_git_objects.py" "$repo/tools/scan_git_objects.py"
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version)
    printf '%s\n' '8.30.1'
    exit 0
    ;;
  git)
    exit 0
    ;;
esac
if grep -F -- "${GITLEAKS_TEST_NEEDLE:?}" >/dev/null; then
  exit 1
fi
exit 0
EOF
  chmod +x "$tools/gitleaks"
  synthetic_secret="glpat-""AbCdEfGhIjKlMnOpQrSt"
  for kind in branch tag; do
    for side in local remote; do
      sensitive_ref="refs/${kind}s/review/$synthetic_secret"
      safe_ref="refs/${kind}s/review/clean"
      if [ "$side" = local ]; then
        input="$sensitive_ref $commit_sha $safe_ref $zero"
      else
        input="$safe_ref $commit_sha $sensitive_ref $zero"
      fi
      printf '%s\n' "$input" | \
        (cd "$repo" && GITLEAKS_TEST_NEEDLE="$synthetic_secret" PATH="$tools:$PATH" \
          sh "$hook" origin example.invalid:repo) >"$output" 2>&1
      actual=$?
      if [ "$actual" -ne 1 ]; then
        echo "FAIL - a synthetic secret in a $side $kind ref name is refused (exit $actual, expected 1)"
        failures=$((failures + 1))
      elif grep -F -- "$synthetic_secret" "$output" >/dev/null; then
        echo "FAIL - rejection diagnostics disclose a synthetic secret from a $side $kind ref name"
        failures=$((failures + 1))
      else
        echo "ok   - a synthetic secret in a $side $kind ref name is refused without disclosure"
      fi
    done
  done
  rm -rf "$temp"
}
expect_secret_ref_names_are_scanned

expect_initial_main_remote_state() {
  description=$1 mode=$2 expected=$3
  temp=$(mktemp -d)
  repo="$temp/repo"
  remote="$temp/origin.git"
  other_remote="$temp/other.git"
  tools="$temp/bin"
  mkdir -p "$repo/tools" "$tools"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  git -C "$repo" commit -q --allow-empty -m clean
  commit_sha=$(git -C "$repo" rev-parse HEAD)
  git init -q --bare "$remote"
  git -C "$repo" remote add origin "$remote"
  remote_name=origin
  remote_url=$remote
  case "$mode" in
    empty) ;;
    unrelated-name) remote_name=upstream ;;
    unrelated-url)
      git init -q --bare "$other_remote"
      remote_url=$other_remote
      ;;
    nonempty-without-main) git -C "$repo" push -q "$remote" HEAD:refs/heads/dev ;;
    bootstrapped) git -C "$repo" push -q "$remote" HEAD:refs/heads/main ;;
  esac
  cp "$repo_root/tools/check_local_refs.py" "$repo/tools/check_local_refs.py"
  cp "$repo_root/tools/scan_git_objects.py" "$repo/tools/scan_git_objects.py"
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version) printf '%s\n' '8.30.1' ;;
  stdin) cat >/dev/null ;;
esac
exit 0
EOF
  printf '#!/bin/sh\nexit 0\n' > "$tools/python3"
  chmod +x "$tools/gitleaks" "$tools/python3"
  printf 'refs/heads/main %s refs/heads/main %s\n' "$commit_sha" "$zero" | \
    (cd "$repo" && PATH="$tools:$PATH" sh "$hook" "$remote_name" "$remote_url") >/dev/null 2>&1
  actual=$?
  rm -rf "$temp"
  if [ "$actual" -ne "$expected" ]; then
    echo "FAIL - $description (exit $actual, expected $expected)"
    failures=$((failures + 1))
  else
    echo "ok   - $description"
  fi
}
expect_initial_main_remote_state "a sole initial main publication to an empty origin is allowed" empty 0
expect_initial_main_remote_state "initial main through an unrelated remote name is refused" unrelated-name 1
expect_initial_main_remote_state "initial main through an unrelated remote URL is refused" unrelated-url 1
expect_initial_main_remote_state "initial main to a nonempty destination without main is refused" nonempty-without-main 1
expect_initial_main_remote_state "the bootstrap exception cannot be reused after main exists" bootstrapped 1

expect_secret_metadata_is_scanned() {
  kind=$1
  temp=$(mktemp -d)
  repo="$temp/repo"
  tools="$temp/bin"
  mkdir -p "$repo/tools" "$tools"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  cp "$repo_root/tools/check_local_refs.py" "$repo/tools/check_local_refs.py"
  cp "$repo_root/tools/scan_git_objects.py" "$repo/tools/scan_git_objects.py"
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version)
    printf '%s\n' '8.30.1'
    exit 0
    ;;
  git)
    exit 0
    ;;
esac
if grep -F -- "${GITLEAKS_TEST_NEEDLE:?}" >/dev/null; then
  exit 1
fi
exit 0
EOF
  chmod +x "$tools/gitleaks"
  synthetic_secret="glpat-""AbCdEfGhIjKlMnOpQrSt"
  if [ "$kind" = commit ]; then
    git -C "$repo" commit -q --allow-empty -m "$synthetic_secret"
    local_sha=$(git -C "$repo" rev-parse HEAD)
    local_ref=refs/heads/feature/metadata
    remote_ref=$local_ref
  else
    git -C "$repo" commit -q --allow-empty -m clean
    git -C "$repo" tag -a review-note -m "$synthetic_secret"
    local_sha=$(git -C "$repo" rev-parse review-note)
    local_ref=refs/tags/review-note
    remote_ref=$local_ref
  fi
  printf '%s %s %s %s\n' "$local_ref" "$local_sha" "$remote_ref" "$zero" | \
    (cd "$repo" && GITLEAKS_TEST_NEEDLE="$synthetic_secret" PATH="$tools:$PATH" \
      sh "$hook" origin example.invalid:repo) >/dev/null 2>&1
  actual=$?
  rm -rf "$temp"
  if [ "$actual" -ne 1 ]; then
    echo "FAIL - a synthetic secret in a $kind message is scanned (exit $actual, expected 1)"
    failures=$((failures + 1))
  else
    echo "ok   - a synthetic secret in a $kind message is scanned"
  fi
}
expect_secret_metadata_is_scanned commit
expect_secret_metadata_is_scanned tag

expect_secret_identity_metadata_is_scanned() {
  identity=$1
  temp=$(mktemp -d)
  repo="$temp/repo"
  tools="$temp/bin"
  mkdir -p "$repo/tools" "$tools"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  cp "$repo_root/tools/check_local_refs.py" "$repo/tools/check_local_refs.py"
  cp "$repo_root/tools/scan_git_objects.py" "$repo/tools/scan_git_objects.py"
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version)
    printf '%s\n' '8.30.1'
    exit 0
    ;;
  git)
    exit 0
    ;;
esac
if grep -F -- "${GITLEAKS_TEST_NEEDLE:?}" >/dev/null; then
  exit 1
fi
exit 0
EOF
  chmod +x "$tools/gitleaks"
  synthetic_secret="glpat-""AbCdEfGhIjKlMnOpQrSt"
  if [ "$identity" = author ]; then
    GIT_AUTHOR_NAME="$synthetic_secret" git -C "$repo" commit -q --allow-empty -m clean
  else
    GIT_COMMITTER_NAME="$synthetic_secret" git -C "$repo" commit -q --allow-empty -m clean
  fi
  commit_sha=$(git -C "$repo" rev-parse HEAD)
  printf 'refs/heads/feature/identity %s refs/heads/feature/identity %s\n' "$commit_sha" "$zero" | \
    (cd "$repo" && GITLEAKS_TEST_NEEDLE="$synthetic_secret" PATH="$tools:$PATH" \
      sh "$hook" origin example.invalid:repo) >/dev/null 2>&1
  actual=$?
  rm -rf "$temp"
  if [ "$actual" -ne 1 ]; then
    echo "FAIL - a synthetic secret in $identity identity metadata is scanned (exit $actual, expected 1)"
    failures=$((failures + 1))
  else
    echo "ok   - a synthetic secret in $identity identity metadata is scanned"
  fi
}
expect_secret_identity_metadata_is_scanned author
expect_secret_identity_metadata_is_scanned committer

expect_malformed_duplicate_tag_headers_are_refused() {
  temp=$(mktemp -d)
  repo="$temp/repo"
  tools="$temp/bin"
  mkdir -p "$repo/tools" "$tools"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  git -C "$repo" commit -q --allow-empty -m clean
  clean_commit=$(git -C "$repo" rev-parse HEAD)
  sensitive_name="device"".""local"
  printf 'public notes\n' > "$repo/$sensitive_name"
  git -C "$repo" add "$sensitive_name"
  sensitive_tree=$(git -C "$repo" write-tree)
  git -C "$repo" update-index --force-remove "$sensitive_name"
  rm -f "$repo/$sensitive_name"
  tag_sha=$(
    {
      printf 'object %s\n' "$sensitive_tree"
      printf 'type tree\n'
      printf 'tag malformed-target\n'
      printf 'tagger Test <test@example.invalid> 1700000000 +0000\n'
      printf 'object %s\n' "$clean_commit"
      printf 'type commit\n\n'
      printf 'reviewed snapshot\n'
    } | git -C "$repo" hash-object -t tag -w --stdin
  )
  git -C "$repo" update-ref refs/tags/malformed-target "$tag_sha"
  peeled=$(git -C "$repo" rev-parse 'malformed-target^{}')
  cp "$repo_root/tools/check_local_refs.py" "$repo/tools/check_local_refs.py"
  cp "$repo_root/tools/scan_git_objects.py" "$repo/tools/scan_git_objects.py"
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version) printf '%s\n' '8.30.1' ;;
  stdin) cat >/dev/null ;;
esac
exit 0
EOF
  chmod +x "$tools/gitleaks"
  printf 'refs/tags/malformed-target %s refs/tags/malformed-target %s\n' "$tag_sha" "$zero" | \
    (cd "$repo" && PATH="$tools:$PATH" sh "$hook" origin example.invalid:repo) >/dev/null 2>&1
  actual=$?
  rm -rf "$temp"
  if [ "$peeled" != "$sensitive_tree" ]; then
    echo "FAIL - Git did not peel the malformed tag through its first target"
    failures=$((failures + 1))
  elif [ "$actual" -ne 1 ]; then
    echo "FAIL - duplicate annotated-tag target headers are refused (exit $actual, expected 1)"
    failures=$((failures + 1))
  else
    echo "ok   - duplicate annotated-tag target headers are refused"
  fi
}
expect_malformed_duplicate_tag_headers_are_refused

expect_sha256_create_and_delete_are_handled() {
  temp=$(mktemp -d)
  repo="$temp/repo"
  tools="$temp/bin"
  mkdir -p "$tools"
  diagnostic=$(git init -q -b main --object-format=sha256 "$repo" 2>&1)
  initialized=$?
  if [ "$initialized" -ne 0 ]; then
    rm -rf "$temp"
    case "$diagnostic" in
      *unknown*sha256*|*unsupported*sha256*|*unknown*object-format*)
        echo "skip - installed Git does not support SHA-256 repositories"
        return
        ;;
      *)
        echo "FAIL - Git failed to initialize the SHA-256 test repository"
        failures=$((failures + 1))
        return
        ;;
    esac
  fi
  mkdir -p "$repo/tools"
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  git -C "$repo" commit -q --allow-empty -m clean
  commit_sha=$(git -C "$repo" rev-parse HEAD)
  zero_sha256=$(printf '%064d' 0)
  cp "$repo_root/tools/check_local_refs.py" "$repo/tools/check_local_refs.py"
  cp "$repo_root/tools/scan_git_objects.py" "$repo/tools/scan_git_objects.py"
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version) printf '%s\n' '8.30.1' ;;
  stdin) cat >/dev/null ;;
esac
exit 0
EOF
  chmod +x "$tools/gitleaks"

  printf 'refs/heads/feature/sha256 %s refs/heads/feature/sha256 %s\n' "$commit_sha" "$zero_sha256" | \
    (cd "$repo" && PATH="$tools:$PATH" sh "$hook" origin example.invalid:repo) >/dev/null 2>&1
  create_actual=$?
  printf '(delete) %s refs/heads/feature/sha256 %s\n' "$zero_sha256" "$commit_sha" | \
    (cd "$repo" && PATH="$tools:$PATH" sh "$hook" origin example.invalid:repo) >/dev/null 2>&1
  delete_actual=$?
  rm -rf "$temp"

  if [ "${#commit_sha}" -ne 64 ]; then
    echo "FAIL - SHA-256 repository produced a non-64-character object ID"
    failures=$((failures + 1))
  elif [ "$create_actual" -ne 0 ]; then
    echo "FAIL - a SHA-256 ref creation is handled (exit $create_actual, expected 0)"
    failures=$((failures + 1))
  else
    echo "ok   - a SHA-256 ref creation is handled"
  fi
  if [ "$delete_actual" -ne 0 ]; then
    echo "FAIL - a SHA-256 ref deletion is handled (exit $delete_actual, expected 0)"
    failures=$((failures + 1))
  else
    echo "ok   - a SHA-256 ref deletion is handled"
  fi
}
expect_sha256_create_and_delete_are_handled

expect_same_target_refs_are_scanned_once() {
  temp=$(mktemp -d)
  repo="$temp/repo"
  tools="$temp/bin"
  gitleaks_log="$temp/gitleaks.log"
  python_log="$temp/python.log"
  input_file="$temp/updates"
  mkdir -p "$repo/tools" "$tools"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  printf 'public notes\n' > "$repo/data.txt"
  git -C "$repo" add data.txt
  git -C "$repo" commit -q -m clean
  commit_sha=$(git -C "$repo" rev-parse HEAD)
  cp "$repo_root/tools/check_local_refs.py" "$repo/tools/check_local_refs.py"
  cp "$repo_root/tools/scan_git_objects.py" "$repo/tools/scan_git_objects.py"
  cp "$repo_root/.gitleaks.toml" "$repo/.gitleaks.toml"
  : > "$input_file"
  for number in 1 2 3 4 5; do
    printf 'refs/heads/feature/%s %s refs/heads/feature/%s %s\n' \
      "$number" "$commit_sha" "$number" "$zero" >> "$input_file"
  done
  cat > "$tools/gitleaks" <<'EOF'
#!/bin/sh
case "${1-}" in
  version|--version) printf '%s\n' '8.30.1' ;;
  git) printf 'git\n' >> "${GITLEAKS_TEST_LOG:?}" ;;
  stdin)
    printf 'stdin\n' >> "${GITLEAKS_TEST_LOG:?}"
    cat >/dev/null
    ;;
esac
exit 0
EOF
  real_python=$(command -v python3)
  cat > "$tools/python3" <<'EOF'
#!/bin/sh
case "$*" in
  *check_local_refs.py*--history*) printf 'history\n' >> "${PYTHON_TEST_LOG:?}" ;;
esac
exec "${REAL_PYTHON:?}" "$@"
EOF
  chmod +x "$tools/gitleaks" "$tools/python3"
  (cd "$repo" && GITLEAKS_TEST_LOG="$gitleaks_log" PYTHON_TEST_LOG="$python_log" \
    REAL_PYTHON="$real_python" PATH="$tools:$PATH" sh "$hook" origin example.invalid:repo \
    < "$input_file") >/dev/null 2>&1
  actual=$?
  git_scans=$(grep -c '^git$' "$gitleaks_log" 2>/dev/null || true)
  stdin_scans=$(grep -c '^stdin$' "$gitleaks_log" 2>/dev/null || true)
  history_scans=$(grep -c '^history$' "$python_log" 2>/dev/null || true)
  rm -rf "$temp"
  if [ "$actual" -ne 0 ] || [ "$git_scans" -ne 1 ] || [ "$stdin_scans" -ne 2 ] || \
    [ "$history_scans" -ne 1 ]; then
    echo "FAIL - overlapping same-target refs are scanned once (exit $actual, git $git_scans, stdin $stdin_scans, history $history_scans)"
    failures=$((failures + 1))
  else
    echo "ok   - overlapping same-target refs are scanned once"
  fi
}
expect_same_target_refs_are_scanned_once

if PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/tests/test_ci_secret_scan.py" >/dev/null 2>&1; then
  echo "ok   - CI secret metadata scan includes full commit identity"
else
  echo "FAIL - CI secret metadata scan omits full commit identity"
  failures=$((failures + 1))
fi

[ "$failures" -eq 0 ] || exit 1
echo "all pre-push guard checks passed"
