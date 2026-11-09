from __future__ import annotations

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import check_local_refs as guard


class RuleTests(unittest.TestCase):
    def rules(self, text: str, denylist: tuple[str, ...] = ()) -> list[str]:
        return [finding.rule for finding in guard.scan_text("sample", text, denylist)]

    def test_rejects_private_network_identity_and_machine_context(self) -> None:
        dot = "."
        at = "@"
        samples = {
            "private-ipv4": dot.join(["192", "168", "1", "9"]),
            "cgnat-or-link-local-ipv4": dot.join(["100", "64", "1", "1"]),
            "mac-address": ":".join(["ec", "a8", "6b", "fb", "ab", "d2"]),
            "home-directory": "/" + "Users/" + "alice/project",
            "mounted-volume": "/" + "Volumes/" + "share/project",
            "lan-hostname": "device" + dot + "local",
            "email-address": "person" + at + "privatecorp" + dot + "corp",
        }
        for expected, sample in samples.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, self.rules(sample))

    def test_accepts_documentation_values(self) -> None:
        samples = (
            "192.0.2.9 198.51.100.9 203.0.113.9",
            "device.example noreply@example.invalid",
            "GitHub <noreply@github.com>",
            "00:00:5e:00:53:01",
            "~/project /Users/<you>/project /Volumes/<share>/project",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(self.rules(sample), [])

    def test_accepts_exact_reserved_email_domains_and_their_subdomains(self) -> None:
        at = "@"
        dot = "."
        domains = (
            "example" + dot + "com",
            "docs" + dot + "example" + dot + "net",
            "example" + dot + "org",
            "service" + dot + "invalid",
            "service" + dot + "test",
            "service" + dot + "localhost",
        )
        for domain in domains:
            with self.subTest(domain=domain):
                self.assertEqual(self.rules("reader" + at + domain), [])

    def test_rejects_email_domains_with_reserved_prefix_collisions(self) -> None:
        at = "@"
        dot = "."
        domains = (
            "example-company" + dot + "corp",
            "example" + dot + "net" + dot + "corp",
            "invalid-service" + dot + "corp",
            "test-service" + dot + "corp",
            "localhost-service" + dot + "corp",
        )
        for domain in domains:
            with self.subTest(domain=domain):
                self.assertIn("email-address", self.rules("reader" + at + domain))

    def test_accepts_exact_github_merge_identity(self) -> None:
        for line in (
            "GitHub <noreply@github.com>",
            "GitHub <noreply@github.com>.",
            "(GitHub <noreply@github.com>)",
            '"GitHub <noreply@github.com>",',
        ):
            with self.subTest(line=line):
                self.assertEqual(self.rules(line), [])

    def test_rejects_github_merge_identity_with_punctuation_attached_suffix(self) -> None:
        at = "@"
        dot = "."
        identity = "GitHub <noreply" + at + "github" + dot + "com>"
        for punctuation in ('"', "'", ".", ",", ";", ":", "!", "?", ")", "]", "}"):
            with self.subTest(punctuation=punctuation):
                self.assertIn("email-address", self.rules(identity + punctuation + "suffix"))

    def test_rejects_github_merge_identity_near_misses(self) -> None:
        at = "@"
        dot = "."
        cases = (
            ("slash email boundary", "person/noreply" + at + "github" + dot + "com"),
            ("at-sign email boundary", "foo" + at + "noreply" + at + "github" + dot + "com"),
            ("punctuation email boundary", "!noreply" + at + "github" + dot + "com"),
            ("invalid identity left boundary", "xGitHub <noreply" + at + "github" + dot + "com>"),
            ("invalid identity right boundary", "GitHub <noreply" + at + "github" + dot + "com>suffix"),
            (
                "non-ASCII email boundary",
                "\N{LATIN SMALL LETTER E WITH ACUTE}" + "noreply" + at + "github" + dot + "com",
            ),
        )

        for boundary, value in cases:
            with self.subTest(boundary=boundary, value=value):
                self.assertIn("email-address", self.rules(value))

    def test_rejects_other_github_address_variants(self) -> None:
        at = "@"
        dot = "."
        values = (
            "person" + at + "github" + dot + "com",
            "noreply" + at + "github" + dot + "co",
            "noreply" + at + "github" + dot + "com" + dot + "evil" + dot + "corp",
        )

        for value in values:
            with self.subTest(value=value):
                self.assertIn("email-address", self.rules(value))

    def test_rejects_lan_hostnames_before_delimiters(self) -> None:
        hostname = "device" + "." + "local"
        for delimiter in ("(", ")", "[", "]", "{", "}", ",", ":", "/", " "):
            with self.subTest(delimiter=delimiter):
                self.assertIn("lan-hostname", self.rules(hostname + delimiter))

    def test_accepts_tokens_that_are_genuinely_longer_than_a_lan_hostname(self) -> None:
        dot = "."
        samples = (
            "device" + dot + "localhost",
            "device" + dot + "local-service",
            "device" + dot + "local" + dot + "example",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertNotIn("lan-hostname", self.rules(sample))

    def test_private_denylist_is_literal_and_case_insensitive(self) -> None:
        self.assertEqual(self.rules("MY-PRIVATE-PROJECT", ("my-private-project",)), ["private-denylist"])

    def test_allow_marker_does_not_suppress_a_private_denylist_term(self) -> None:
        text = guard.ALLOW_MARKER + " PRIVATE-PROJECT"
        self.assertIn("private-denylist", self.rules(text, ("private-project",)))

    def test_findings_do_not_retain_or_echo_rejected_values(self) -> None:
        value = ".".join(["10", "0", "0", "1"])
        finding = next(guard.scan_text("sample", value))
        self.assertFalse(hasattr(finding, "value"))
        self.assertNotIn(value, finding.render())


class TagTargetTests(unittest.TestCase):
    object_id = "a" * 40
    alternate_id = "b" * 40

    def test_rejects_duplicate_object_headers(self) -> None:
        payload = (
            f"object {self.object_id}\n"
            "type tree\n"
            "tag reviewed\n"
            f"object {self.alternate_id}\n\n"
            "reviewed snapshot\n"
        ).encode()

        with self.assertRaises(guard.GitBatchError):
            guard.tag_target(payload)

    def test_rejects_duplicate_type_headers(self) -> None:
        payload = (
            f"object {self.object_id}\n"
            "type tree\n"
            "tag reviewed\n"
            "type commit\n\n"
            "reviewed snapshot\n"
        ).encode()

        with self.assertRaises(guard.GitBatchError):
            guard.tag_target(payload)


class ModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.git_run("init", "-q", "-b", "main")
        self.git_run("config", "user.name", "Test")
        self.git_run("config", "user.email", "test@example.invalid")

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def git_environment() -> dict[str, str]:
        # Hooks may set these for the real commit. They override this throwaway repo's
        # config and would make commit-identity tests depend on the caller.
        environment = os.environ.copy()
        for name in (
            # Identity variables set by the real commit invoking the hook.
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_AUTHOR_DATE",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
            "GIT_COMMITTER_DATE",
            # Repository-local variables from `git rev-parse --local-env-vars`. In
            # particular, a path-limited commit exports GIT_INDEX_FILE to the hook.
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
            "GIT_OBJECT_DIRECTORY",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_IMPLICIT_WORK_TREE",
            "GIT_GRAFT_FILE",
            "GIT_INDEX_FILE",
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_REPLACE_REF_BASE",
            "GIT_PREFIX",
            "GIT_SHALLOW_FILE",
            "GIT_COMMON_DIR",
        ):
            environment.pop(name, None)
        return environment

    def git_run(self, *args: str) -> None:
        subprocess.run(
            ["git", *args], cwd=self.repo, check=True, capture_output=True, env=self.git_environment()
        )

    def git_output(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo,
            check=True,
            capture_output=True,
            text=True,
            env=self.git_environment(),
        ).stdout.strip()

    def git_input(self, payload: bytes, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo,
            check=True,
            capture_output=True,
            input=payload,
            env=self.git_environment(),
        ).stdout.decode("ascii").strip()

    def create_direct_tag(self, target: str, *, annotated: bool, name: str) -> None:
        if annotated:
            self.git_run("tag", "-a", name, target, "-m", "reviewed snapshot")
        else:
            self.git_run("update-ref", f"refs/tags/{name}", target)

    def run_guard(self, *args: str) -> int:
        previous = Path.cwd()
        try:
            # The production guard must see the real commit's alternate index; only
            # these throwaway-repository calls clear caller-local Git variables.
            with mock.patch.dict(os.environ, self.git_environment(), clear=True):
                os.chdir(self.repo)
                return guard.main(list(args))
        finally:
            os.chdir(previous)

    def run_guard_captured(self, *args: str) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = self.run_guard(*args)
        return result, output.getvalue()

    def test_tracked_and_staged_modes_read_the_correct_views(self) -> None:
        path = self.repo / "data.txt"
        path.write_text("host 192.0.2.1\n")
        self.git_run("add", "data.txt")
        previous = Path.cwd()
        try:
            import os

            os.chdir(self.repo)
            self.assertEqual(self.run_guard(), 0)
            path.write_text("host " + ".".join(["10", "0", "0", "1"]) + "\n")
            self.assertEqual(self.run_guard(), 1)
            self.assertEqual(self.run_guard("--staged"), 0)
        finally:
            os.chdir(previous)

    def test_tracked_mode_rejects_a_sensitive_directory_name(self) -> None:
        relative = Path("device" + "." + "local") / "notes.txt"
        path = self.repo / relative
        path.parent.mkdir()
        path.write_text("public notes\n")
        self.git_run("add", relative.as_posix())

        self.assertEqual(self.run_guard(), 1)

    def test_staged_mode_rejects_a_sensitive_file_name(self) -> None:
        relative = Path("diagnostic-" + "device" + "." + "local")
        (self.repo / relative).write_text("public notes\n")
        self.git_run("add", relative.as_posix())

        self.assertEqual(self.run_guard("--staged"), 1)

    def test_tracked_mode_does_not_allow_an_ordinary_line_to_suppress_a_violation(self) -> None:
        private_address = ".".join(["10", "0", "0", "1"])
        (self.repo / "notes.txt").write_text(f"{guard.ALLOW_MARKER} {private_address}\n")
        self.git_run("add", "notes.txt")

        self.assertEqual(self.run_guard(), 1)

    def test_staged_mode_does_not_allow_an_ordinary_line_to_suppress_a_violation(self) -> None:
        private_address = ".".join(["172", "16", "0", "1"])
        (self.repo / "notes.txt").write_text(f"{guard.ALLOW_MARKER} {private_address}\n")
        self.git_run("add", "notes.txt")

        self.assertEqual(self.run_guard("--staged"), 1)

    def test_history_finds_a_removed_reference(self) -> None:
        path = self.repo / "data.txt"
        path.write_text("host " + ".".join(["172", "16", "0", "1"]) + "\n")
        self.git_run("add", "data.txt")
        self.git_run("commit", "-q", "-m", "first")
        path.write_text("host 192.0.2.1\n")
        self.git_run("commit", "-q", "-am", "clean")
        previous = Path.cwd()
        try:
            import os

            os.chdir(self.repo)
            self.assertEqual(self.run_guard(), 0)
            self.assertEqual(self.run_guard("--history"), 1)
        finally:
            os.chdir(previous)

    def test_history_rejects_a_sensitive_tree_entry_name(self) -> None:
        relative = Path("device" + "." + "local") / "notes.txt"
        path = self.repo / relative
        path.parent.mkdir()
        path.write_text("public notes\n")
        self.git_run("add", relative.as_posix())
        self.git_run("commit", "-q", "-m", "add notes")

        self.assertEqual(self.run_guard("--history"), 1)

    def test_history_does_not_allow_an_ordinary_blob_line_to_suppress_a_violation(self) -> None:
        private_address = ".".join(["10", "0", "0", "1"])
        (self.repo / "notes.txt").write_text(f"{guard.ALLOW_MARKER} {private_address}\n")
        self.git_run("add", "notes.txt")
        self.git_run("commit", "-q", "-m", "add notes")

        self.assertEqual(self.run_guard("--history"), 1)

    def test_history_uses_one_persistent_cat_file_process(self) -> None:
        path = self.repo / "data.txt"
        path.write_text("first\n")
        self.git_run("add", "data.txt")
        self.git_run("commit", "-q", "-m", "first")
        path.write_text("second\n")
        self.git_run("commit", "-q", "-am", "second")

        commands: list[list[str]] = []
        real_popen = subprocess.Popen

        def record_popen(command: list[str], *args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            commands.append(command)
            return real_popen(command, *args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(guard.subprocess, "Popen", side_effect=record_popen):
            list(guard.history(self.repo))

        cat_file_commands = [command for command in commands if command[:2] == ["git", "cat-file"]]
        self.assertEqual(cat_file_commands, [["git", "cat-file", "--batch"]])

    def test_history_finds_a_detached_head_commit(self) -> None:
        path = self.repo / "data.txt"
        path.write_text("host 192.0.2.1\n")
        self.git_run("add", "data.txt")
        self.git_run("commit", "-q", "-m", "clean")
        self.git_run("checkout", "-q", "--detach", "HEAD")
        path.write_text("host " + ".".join(["10", "0", "0", "1"]) + "\n")
        self.git_run("commit", "-q", "-am", "detached")

        self.assertEqual(self.run_guard("--history"), 1)

    def test_history_finds_a_remote_tracking_only_commit(self) -> None:
        path = self.repo / "data.txt"
        path.write_text("host 192.0.2.1\n")
        self.git_run("add", "data.txt")
        self.git_run("commit", "-q", "-m", "clean")
        self.git_run("checkout", "-q", "--detach", "HEAD")
        path.write_text("host " + ".".join(["172", "16", "0", "1"]) + "\n")
        self.git_run("commit", "-q", "-am", "remote tracking")
        remote_only = self.git_output("rev-parse", "HEAD")
        self.git_run("update-ref", "refs/remotes/origin/feature", remote_only)
        self.git_run("checkout", "-q", "--detach", "HEAD^")

        self.assertEqual(self.run_guard("--history"), 1)

    def test_tracked_and_staged_modes_fail_closed_for_binary_artifacts(self) -> None:
        artifacts = {
            "payload.bin": b"public\x00private",
            "image.png": b"\x89PNG\r\n\x1a\n",
            "archive.zip": b"PK\x03\x04unsupported",
        }
        for name, payload in artifacts.items():
            with self.subTest(name=name):
                path = self.repo / name
                try:
                    path.write_bytes(payload)
                    self.git_run("add", name)
                    results = (self.run_guard(), self.run_guard("--staged"))
                    self.assertTrue(all(result != 0 for result in results), results)
                finally:
                    self.git_run("update-index", "--force-remove", name)
                    path.unlink(missing_ok=True)

    def test_history_fails_closed_for_an_unsupported_archive(self) -> None:
        path = self.repo / "archive.zip"
        path.write_bytes(b"PK\x03\x04unsupported")
        self.git_run("add", "archive.zip")
        self.git_run("commit", "-q", "-m", "archive")

        self.assertNotEqual(self.run_guard("--history"), 0)

    def test_history_rejects_a_reused_text_blob_under_an_archive_name(self) -> None:
        payload = b"public notes\n"
        text_path = self.repo / "a.txt"
        archive_path = self.repo / "z.zip"
        text_path.write_bytes(payload)
        self.git_run("add", "a.txt")
        self.git_run("commit", "-q", "-m", "text")
        archive_path.write_bytes(payload)
        self.git_run("add", "z.zip")
        self.git_run("commit", "-q", "-m", "reuse")
        self.assertEqual(
            self.git_output("hash-object", "a.txt"),
            self.git_output("hash-object", "z.zip"),
        )

        self.assertNotEqual(self.run_guard("--history"), 0)

    def test_history_scans_annotated_tag_messages(self) -> None:
        self.git_run("commit", "-q", "--allow-empty", "-m", "clean")
        private_address = ".".join(["10", "0", "0", "1"])
        self.git_run("tag", "-a", "review-note", "-m", f"diagnose {private_address}")

        self.assertEqual(self.run_guard("--history"), 1)

    def test_history_does_not_allow_a_tag_message_to_suppress_a_violation(self) -> None:
        self.git_run("commit", "-q", "--allow-empty", "-m", "clean")
        private_address = ".".join(["10", "0", "0", "1"])
        message = f"{guard.ALLOW_MARKER} {private_address}"
        self.git_run("tag", "-a", "review-note", "-m", message)

        self.assertEqual(self.run_guard("--history"), 1)

    def test_history_scans_commit_messages(self) -> None:
        private_address = ".".join(["10", "0", "0", "1"])
        self.git_run("commit", "-q", "--allow-empty", "-m", f"diagnose {private_address}")
        previous = Path.cwd()
        try:
            import os

            os.chdir(self.repo)
            self.assertEqual(self.run_guard("--history"), 1)
        finally:
            os.chdir(previous)

    def test_history_does_not_allow_a_commit_message_to_suppress_a_violation(self) -> None:
        private_address = ".".join(["172", "16", "0", "1"])
        message = f"{guard.ALLOW_MARKER} {private_address}"
        self.git_run("commit", "-q", "--allow-empty", "-m", message)

        self.assertEqual(self.run_guard("--history"), 1)

    def test_history_scans_commit_identity(self) -> None:
        address = "person" + "@" + "privatecorp" + "." + "corp"
        self.git_run("config", "user.email", address)
        self.git_run("commit", "-q", "--allow-empty", "-m", "identity")
        previous = Path.cwd()
        try:
            import os

            os.chdir(self.repo)
            self.assertEqual(self.run_guard("--history"), 1)
        finally:
            os.chdir(previous)

    def assert_direct_blob_tag_is_rejected(self, *, annotated: bool) -> None:
        self.git_run("commit", "-q", "--allow-empty", "-m", "clean baseline")
        payload = self.repo / "detached.txt"
        private_address = ".".join(["10", "0", "0", "1"])
        payload.write_text(f"host {private_address}\n")
        blob_id = self.git_output("hash-object", "-w", "detached.txt")
        payload.unlink()
        self.create_direct_tag(blob_id, annotated=annotated, name="blob-snapshot")

        self.assertEqual(self.run_guard("--history"), 1)
        self.assertEqual(self.run_guard("--history", "--revision", blob_id), 1)

    def assert_direct_tree_tag_is_rejected(self, *, annotated: bool) -> None:
        self.git_run("commit", "-q", "--allow-empty", "-m", "clean baseline")
        archive = self.repo / "archive.zip"
        archive.write_bytes(b"PK\x03\x04unsupported")
        self.git_run("add", "archive.zip")
        tree_id = self.git_output("write-tree")
        self.create_direct_tag(tree_id, annotated=annotated, name="tree-snapshot")
        self.git_run("update-index", "--force-remove", "archive.zip")
        archive.unlink()

        self.assertNotEqual(self.run_guard("--history"), 0)
        self.assertNotEqual(self.run_guard("--history", "--revision", tree_id), 0)

    def test_history_scans_a_lightweight_tag_pointing_directly_to_a_blob(self) -> None:
        self.assert_direct_blob_tag_is_rejected(annotated=False)

    def test_history_scans_an_annotated_tag_pointing_directly_to_a_blob(self) -> None:
        self.assert_direct_blob_tag_is_rejected(annotated=True)

    def test_history_scans_a_lightweight_tag_pointing_directly_to_a_tree(self) -> None:
        self.assert_direct_tree_tag_is_rejected(annotated=False)

    def test_history_scans_an_annotated_tag_pointing_directly_to_a_tree(self) -> None:
        self.assert_direct_tree_tag_is_rejected(annotated=True)

    def test_history_fails_closed_for_duplicate_annotated_tag_target_headers(self) -> None:
        self.git_run("commit", "-q", "--allow-empty", "-m", "clean baseline")
        clean_commit = self.git_output("rev-parse", "HEAD")
        sensitive_path = Path("device" + "." + "local")
        (self.repo / sensitive_path).write_text("public notes\n")
        self.git_run("add", sensitive_path.as_posix())
        sensitive_tree = self.git_output("write-tree")
        self.git_run("update-index", "--force-remove", sensitive_path.as_posix())
        (self.repo / sensitive_path).unlink()
        payload = (
            f"object {sensitive_tree}\n"
            "type tree\n"
            "tag malformed-target\n"
            "tagger Test <test@example.invalid> 1700000000 +0000\n"
            f"object {clean_commit}\n"
            "type commit\n\n"
            "reviewed snapshot\n"
        ).encode()
        tag_id = self.git_input(payload, "hash-object", "-t", "tag", "-w", "--stdin")
        self.git_run("update-ref", "refs/tags/malformed-target", tag_id)

        self.assertEqual(self.git_output("rev-parse", "malformed-target^{}"), sensitive_tree)
        self.assertEqual(self.run_guard("--history"), 2)

    def test_history_scans_a_sha256_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "repo"
            initialized = subprocess.run(
                ["git", "init", "-q", "-b", "main", "--object-format=sha256", str(repo)],
                capture_output=True,
                env=self.git_environment(),
            )
            if initialized.returncode != 0:
                diagnostic = initialized.stderr.lower()
                if b"sha256" in diagnostic and (b"unknown" in diagnostic or b"unsupported" in diagnostic):
                    self.skipTest("installed Git does not support SHA-256 repositories")
                self.fail("Git failed to initialize the SHA-256 test repository")
            subprocess.run(
                ["git", "config", "user.name", "Test"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=self.git_environment(),
            )
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=self.git_environment(),
            )
            subprocess.run(
                ["git", "commit", "-q", "--allow-empty", "-m", "clean"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=self.git_environment(),
            )
            revision = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
                env=self.git_environment(),
            ).stdout.strip()
            self.assertEqual(len(revision), 64)

            result = subprocess.run(
                ["python3", str(Path(guard.__file__).resolve()), "--history", "--revision", revision],
                cwd=repo,
                capture_output=True,
                text=True,
                env=self.git_environment(),
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_tracked_mode_caps_aggregate_bytes_across_artifacts(self) -> None:
        for name in ("first.txt", "second.txt"):
            (self.repo / name).write_text("public-data\n")
            self.git_run("add", name)

        with mock.patch.object(guard, "MAX_SCAN_BYTES", 20, create=True):
            self.assertEqual(self.run_guard(), 2)

    def test_tracked_mode_fails_closed_when_the_aggregate_line_budget_is_exhausted(self) -> None:
        (self.repo / "notes.txt").write_text("first\nsecond\nthird\n")
        self.git_run("add", "notes.txt")

        with mock.patch.object(guard, "MAX_SCAN_LINES", 2, create=True):
            self.assertEqual(self.run_guard(), 2)

    def test_tracked_mode_fails_closed_when_the_scan_work_budget_is_exhausted(self) -> None:
        (self.repo / guard.DENYLIST_FILE).write_text("alpha\nbeta\ngamma\n")
        (self.repo / "notes.txt").write_text("public notes\n")
        self.git_run("add", "notes.txt")

        with mock.patch.object(guard, "MAX_SCAN_WORK", 2, create=True):
            self.assertEqual(self.run_guard(), 2)

    def test_history_fails_closed_when_the_object_budget_is_exhausted(self) -> None:
        (self.repo / "notes.txt").write_text("public notes\n")
        self.git_run("add", "notes.txt")
        self.git_run("commit", "-q", "-m", "notes")

        with mock.patch.object(guard, "MAX_HISTORY_OBJECTS", 1):
            self.assertEqual(self.run_guard("--history"), 2)

    def test_history_fails_closed_when_the_tree_work_budget_is_exhausted(self) -> None:
        for name in ("first.txt", "second.txt"):
            (self.repo / name).write_text("public notes\n")
            self.git_run("add", name)
        self.git_run("commit", "-q", "-m", "notes")

        with mock.patch.object(guard, "MAX_TREE_ASSOCIATIONS", 1):
            self.assertEqual(self.run_guard("--history"), 2)

    def write_repeated_findings(self) -> str:
        private_address = ".".join(["10", "0", "0", "1"])
        (self.repo / "notes.txt").write_text((f"host {private_address}\n") * 8)
        self.git_run("add", "notes.txt")
        return private_address

    def test_finding_count_is_bounded(self) -> None:
        private_address = self.write_repeated_findings()

        with mock.patch.object(guard, "MAX_FINDINGS", 2, create=True):
            result, output = self.run_guard_captured()

        self.assertNotEqual(result, 0)
        self.assertLessEqual(output.count("private-ipv4 --"), 2)
        self.assertNotIn(private_address, output)

    def test_finding_diagnostics_have_an_aggregate_byte_limit(self) -> None:
        private_address = self.write_repeated_findings()

        with mock.patch.object(guard, "MAX_DIAGNOSTIC_BYTES", 256, create=True):
            result, output = self.run_guard_captured()

        self.assertNotEqual(result, 0)
        self.assertLessEqual(len(output.encode("utf-8")), 256)
        self.assertNotIn(private_address, output)


if __name__ == "__main__":
    unittest.main()
