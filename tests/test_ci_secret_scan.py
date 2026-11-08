from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
METADATA_STEP = "Scan commit and annotated-tag messages"


def workflow_run_script(step_name: str) -> str:
    """Extract one literal run block without requiring a YAML dependency."""
    lines = WORKFLOW.read_text().splitlines()
    marker = f"      - name: {step_name}"
    try:
        start = lines.index(marker)
    except ValueError as error:
        raise AssertionError(f"CI step is missing: {step_name}") from error
    if lines[start + 2] != "        run: |":
        raise AssertionError(f"CI step does not have the expected literal run block: {step_name}")
    body: list[str] = []
    for line in lines[start + 3 :]:
        if line.startswith("      - ") or (line and not line.startswith("          ")):
            break
        body.append(line[10:] if line else "")
    if not body:
        raise AssertionError(f"CI step has an empty run block: {step_name}")
    return "\n".join(body)


class CiSecretMetadataTests(unittest.TestCase):
    def run_metadata_step(self, identity: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            tools = root / "bin"
            runner_temp = root / "runner"
            repo.mkdir()
            tools.mkdir()
            runner_temp.mkdir()
            (repo / "tools").mkdir()
            (repo / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
            (repo / "tools" / "scan_git_objects.py").write_bytes(
                (REPO_ROOT / "tools" / "scan_git_objects.py").read_bytes()
            )
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
            synthetic_secret = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"
            environment = os.environ.copy()
            for name in (
                "GIT_AUTHOR_NAME",
                "GIT_AUTHOR_EMAIL",
                "GIT_AUTHOR_DATE",
                "GIT_COMMITTER_NAME",
                "GIT_COMMITTER_EMAIL",
                "GIT_COMMITTER_DATE",
            ):
                environment.pop(name, None)
            environment["GITLEAKS_TEST_NEEDLE"] = synthetic_secret
            environment["RUNNER_TEMP"] = str(runner_temp)
            environment["PATH"] = f"{tools}{os.pathsep}{environment['PATH']}"
            if identity == "author":
                environment["GIT_AUTHOR_NAME"] = synthetic_secret
            elif identity == "committer":
                environment["GIT_COMMITTER_NAME"] = synthetic_secret
            subprocess.run(
                ["git", "commit", "-q", "--allow-empty", "-m", "clean metadata"],
                cwd=repo,
                check=True,
                env=environment,
            )
            if identity == "fetched-ref":
                subprocess.run(
                    ["git", "update-ref", f"refs/heads/review/{synthetic_secret}", "HEAD"],
                    cwd=repo,
                    check=True,
                    env=environment,
                )
            elif identity == "triggering-ref":
                environment["GITHUB_REF"] = f"refs/tags/review/{synthetic_secret}"
            elif identity == "direct-blob":
                blob_id = subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"],
                    cwd=repo,
                    check=True,
                    input=synthetic_secret,
                    capture_output=True,
                    text=True,
                    env=environment,
                ).stdout.strip()
                subprocess.run(
                    ["git", "update-ref", "refs/tags/review-payload", blob_id],
                    cwd=repo,
                    check=True,
                    env=environment,
                )
            (tools / "gitleaks").write_text(
                "#!/bin/sh\n"
                "case \"${1-}\" in\n"
                "  git) exit 0 ;;\n"
                "  stdin)\n"
                "    if grep -F -- \"${GITLEAKS_TEST_NEEDLE:?}\" >/dev/null; then exit 1; fi\n"
                "    exit 0\n"
                "    ;;\n"
                "esac\n"
                "exit 0\n"
            )
            (tools / "gitleaks").chmod(0o700)
            completed = subprocess.run(
                ["bash", "-c", workflow_run_script(METADATA_STEP)],
                cwd=repo,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            return completed.returncode, completed.stdout, completed.stderr

    def test_ci_scans_synthetic_secret_in_author_metadata_without_disclosure(self) -> None:
        return_code, stdout, stderr = self.run_metadata_step("author")
        synthetic_secret = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"

        self.assertNotEqual(return_code, 0)
        self.assertNotIn(synthetic_secret, stdout + stderr)

    def test_ci_scans_synthetic_secret_in_committer_metadata_without_disclosure(self) -> None:
        return_code, stdout, stderr = self.run_metadata_step("committer")
        synthetic_secret = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"

        self.assertNotEqual(return_code, 0)
        self.assertNotIn(synthetic_secret, stdout + stderr)

    def test_ci_scans_fetched_ref_names_without_disclosure(self) -> None:
        return_code, stdout, stderr = self.run_metadata_step("fetched-ref")
        synthetic_secret = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"

        self.assertNotEqual(return_code, 0)
        self.assertNotIn(synthetic_secret, stdout + stderr)

    def test_ci_scans_the_triggering_ref_name_without_disclosure(self) -> None:
        return_code, stdout, stderr = self.run_metadata_step("triggering-ref")
        synthetic_secret = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"

        self.assertNotEqual(return_code, 0)
        self.assertNotIn(synthetic_secret, stdout + stderr)

    def test_ci_scans_a_direct_blob_tag_target_without_disclosure(self) -> None:
        return_code, stdout, stderr = self.run_metadata_step("direct-blob")
        synthetic_secret = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"

        self.assertNotEqual(return_code, 0)
        self.assertNotIn(synthetic_secret, stdout + stderr)


if __name__ == "__main__":
    unittest.main()
