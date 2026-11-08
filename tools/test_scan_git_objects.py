from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import scan_git_objects as scanner


class GitObjectScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.repo = root / "repo"
        self.tools = root / "bin"
        self.object_file = root / "objects"
        self.repo.mkdir()
        self.tools.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        (self.repo / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
        gitleaks = self.tools / "gitleaks"
        gitleaks.write_text(
            "#!/bin/sh\n"
            "[ \"${1-}\" = stdin ] || exit 2\n"
            "cat >/dev/null || exit 2\n"
            "exit \"${GITLEAKS_TEST_EXIT:-0}\"\n"
        )
        gitleaks.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_blob(self, payload: bytes) -> str:
        return subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=self.repo,
            input=payload,
            check=True,
            capture_output=True,
        ).stdout.decode("ascii").strip()

    def write_object_ids(self, *object_ids: str) -> None:
        self.object_file.write_text("".join(f"{object_id}\n" for object_id in object_ids))

    def run_scan(self) -> None:
        environment = os.environ.copy()
        environment["PATH"] = f"{self.tools}{os.pathsep}{environment['PATH']}"
        previous = Path.cwd()
        try:
            with mock.patch.dict(os.environ, environment, clear=True):
                os.chdir(self.repo)
                scanner.scan_objects(self.object_file)
        finally:
            os.chdir(previous)

    def test_many_objects_use_one_git_and_one_gitleaks_process(self) -> None:
        self.write_object_ids(*(self.write_blob(f"payload-{index}\n".encode()) for index in range(20)))
        commands: list[list[str]] = []
        real_popen = subprocess.Popen

        def record_popen(command: list[str], *args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            commands.append(command)
            return real_popen(command, *args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(scanner.subprocess, "Popen", side_effect=record_popen):
            self.run_scan()

        self.assertEqual(commands.count(["git", "cat-file", "--batch"]), 1)
        self.assertEqual(sum(command[:2] == ["gitleaks", "stdin"] for command in commands), 1)

    def test_object_count_limit_fails_closed(self) -> None:
        object_id = self.write_blob(b"x")
        self.write_object_ids(object_id, object_id)

        with mock.patch.object(scanner, "MAX_OBJECTS", 1), self.assertRaises(scanner.ObjectScanError):
            self.run_scan()

    def test_object_size_limit_fails_closed(self) -> None:
        self.write_object_ids(self.write_blob(b"four"))

        with mock.patch.object(scanner, "MAX_OBJECT_BYTES", 3), self.assertRaises(scanner.ObjectScanError):
            self.run_scan()

    def test_aggregate_size_limit_fails_closed(self) -> None:
        self.write_object_ids(self.write_blob(b"four"), self.write_blob(b"five"))

        with mock.patch.object(scanner, "MAX_AGGREGATE_BYTES", 7), self.assertRaises(
            scanner.ObjectScanError
        ):
            self.run_scan()

    def test_malformed_object_index_fails_closed(self) -> None:
        self.object_file.write_text("not-an-object\n")

        with self.assertRaises(scanner.ObjectScanError):
            self.run_scan()

    def test_gitleaks_rejection_fails_closed(self) -> None:
        self.write_object_ids(self.write_blob(b"payload"))

        with mock.patch.dict(os.environ, {"GITLEAKS_TEST_EXIT": "1"}), self.assertRaises(
            scanner.ObjectScanError
        ):
            self.run_scan()


if __name__ == "__main__":
    unittest.main()
