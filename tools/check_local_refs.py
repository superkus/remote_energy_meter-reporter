#!/usr/bin/env python3
"""Fail when a public repository contains references to a contributor's local setup."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TextIO

DENYLIST_FILE = ".local-refs-denylist"
DENYLIST_ENV = "LOCAL_REFS_DENYLIST"
UNSUPPORTED_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".ico", ".zip", ".gz", ".pyc"})
ALLOW_MARKER = "local-refs:" + " allow"
GITHUB_MERGE_IDENTITY = "GitHub <noreply@github.com>"
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_REF_BYTES = 4096
MAX_HISTORY_OBJECTS = 1_000_000
MAX_TREE_ASSOCIATIONS = 2_000_000
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_SCAN_LINES = 2_000_000
MAX_SCAN_WORK = 20_000_000
MAX_FINDINGS = 10_000
MAX_DIAGNOSTIC_BYTES = 256 * 1024
OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
PUSH_REVISION = re.compile(
    r"(?:[0-9A-Fa-f]{40}(?:\.\.[0-9A-Fa-f]{40})?|[0-9A-Fa-f]{64}(?:\.\.[0-9A-Fa-f]{64})?)\Z"
)
OBJECT_ID = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")

# The initial public commit contained this declaration before marker handling was
# tightened. This exact historical source line is the only policy-rule exemption.
APPROVED_ALLOW_MARKER_LINE = ("tools/check_local_refs.py", 18, f'ALLOW_MARKER = "{ALLOW_MARKER}"')


@dataclass(frozen=True)
class Rule:
    """One public local-reference rule."""

    name: str
    pattern: re.Pattern[str]
    hint: str


RULES = (
    Rule(
        "private-ipv4",
        # Token boundaries prevent a private address-like substring from matching inside a longer dotted number.
        re.compile(rf"(?<![\d.])(?:10\.{OCTET}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.{OCTET}\.{OCTET}(?![\d.])"),
        "use an RFC 5737 documentation address",
    ),
    Rule(
        "cgnat-or-link-local-ipv4",
        # The same boundaries keep malformed longer addresses from producing partial matches.
        re.compile(rf"(?<![\d.])(?:100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.{OCTET}\.{OCTET}(?![\d.])"),
        "use an RFC 5737 documentation address",
    ),
    Rule(
        "mac-address",
        # RFC 7042 reserves 00:00:5e:00:53:xx for documentation, so only that prefix is exempt.
        re.compile(r"(?<![0-9A-Fa-f:])(?!00:00:5[eE]:00:53:)(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])"),
        "use an RFC 7042 documentation MAC",
    ),
    Rule(
        "home-directory",
        # Hosted-CI and generic placeholder accounts are public examples rather than contributor identities.
        re.compile(r"(?:/Users|/home)/(?!runner\b|user\b|USER\b|<)[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._-]+"),
        "use ~ or <home>",
    ),
    Rule(
        "mounted-volume",
        # An angle-bracket volume name explicitly marks a documentation placeholder.
        re.compile(r"/Volumes/(?!<)[A-Za-z0-9._-]+|/private/(?:nfs)\b|/net/[A-Za-z0-9._-]+"),
        "describe the mount generically",
    ),
    Rule(
        "lan-hostname",
        # Host-token boundaries prevent a permitted longer name from yielding a forbidden suffix match.
        re.compile(
            r"(?<![A-Za-z0-9.-])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:local|lan|internal|home\.arpa|home)"
            r"(?![A-Za-z0-9.-])"
        ),
        "use a reserved name such as device.example",
    ),
    Rule(
        "email-address",
        # Exempt image names, reserved domains, and GitHub's public user noreply domain.
        re.compile(
            r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?!(?:\d+x)\.)"
            r"(?!(?:[A-Za-z0-9-]+\.)*(?:example(?:\.(?:com|net|org))?|invalid|test|localhost)(?![A-Za-z0-9.-]))"
            r"(?!users\.noreply\.github\.com\b)"
            r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![A-Za-z0-9.-])"
        ),
        "use noreply@example.invalid",
    ),
)


@dataclass(frozen=True)
class Finding:
    """One rejected rule and its location."""

    location: str
    line: int
    rule: str
    hint: str

    def render(self) -> str:
        return f"{self.location}:{self.line}: {self.rule} -- {self.hint}"


@dataclass(frozen=True)
class Scannable:
    """One bounded text value and its optional repository path."""

    location: str
    text: str
    source_path: str | None = None


class UnsupportedArtifactError(Exception):
    """A public artifact cannot be safely inspected as bounded UTF-8 text."""


class ResourceLimitError(Exception):
    """The shared scan budget was exhausted."""


class GitBatchError(Exception):
    """Git did not return a complete object through its batch protocol."""


@dataclass
class ScanBudget:
    """Shared fail-closed limits for one complete scanner invocation."""

    bytes_left: int
    lines_left: int
    work_left: int
    findings_left: int
    history_objects_left: int
    tree_associations_left: int

    @classmethod
    def create(cls) -> ScanBudget:
        return cls(
            MAX_SCAN_BYTES,
            MAX_SCAN_LINES,
            MAX_SCAN_WORK,
            MAX_FINDINGS,
            MAX_HISTORY_OBJECTS,
            MAX_TREE_ASSOCIATIONS,
        )

    @staticmethod
    def _debit(current: int, amount: int) -> int:
        if amount < 0 or amount > current:
            raise ResourceLimitError
        return current - amount

    def debit_bytes(self, amount: int) -> None:
        self.bytes_left = self._debit(self.bytes_left, amount)

    def debit_line(self) -> None:
        self.lines_left = self._debit(self.lines_left, 1)

    def debit_work(self, amount: int = 1) -> None:
        self.work_left = self._debit(self.work_left, amount)

    def record_finding(self) -> None:
        self.findings_left = self._debit(self.findings_left, 1)

    def record_history_object(self) -> None:
        self.history_objects_left = self._debit(self.history_objects_left, 1)

    def record_tree_association(self) -> None:
        self.tree_associations_left = self._debit(self.tree_associations_left, 1)


def text_lines(text: str, budget: ScanBudget | None = None) -> Iterator[tuple[int, str]]:
    """Iterate text lines without constructing an aggregate list."""
    start = 0
    number = 0
    while start < len(text):
        end = text.find("\n", start)
        if end < 0:
            end = len(text)
            next_start = len(text)
        else:
            next_start = end + 1
        line = text[start:end]
        if line.endswith("\r"):
            line = line[:-1]
        number += 1
        if budget is not None:
            budget.debit_line()
        yield number, line
        start = next_start


def byte_lines(payload: bytes, budget: ScanBudget) -> Iterator[bytes]:
    """Iterate already-byte-accounted newline records with a shared line limit."""
    start = 0
    while start < len(payload):
        end = payload.find(b"\n", start)
        if end < 0:
            end = len(payload)
            next_start = len(payload)
        else:
            next_start = end + 1
        line = payload[start:end]
        if line.endswith(b"\r"):
            line = line[:-1]
        budget.debit_line()
        yield line
        start = next_start


def decoded(payload: bytes) -> str | None:
    """Decode bounded UTF-8 source text, rejecting binary or invalid payloads."""
    if len(payload) > MAX_TEXT_BYTES or b"\0" in payload:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def supported_text(path: str, payload: bytes) -> str:
    """Return inspectable text or fail closed for an unsupported artifact."""
    if Path(path).suffix.lower() in UNSUPPORTED_SUFFIXES:
        raise UnsupportedArtifactError(path)
    text = decoded(payload)
    if text is None:
        raise UnsupportedArtifactError(path)
    return text


def read_file(path: Path, budget: ScanBudget, location: str) -> bytes:
    """Read one regular bounded file after reserving its aggregate byte cost."""
    if not path.is_file() or path.is_symlink():
        raise UnsupportedArtifactError(location)
    size = path.stat().st_size
    if size < 0 or size > MAX_TEXT_BYTES:
        raise UnsupportedArtifactError(location)
    budget.debit_bytes(size)
    with path.open("rb") as file:
        payload = file.read(size + 1)
    if len(payload) != size:
        raise UnsupportedArtifactError(location)
    return payload


def load_denylist(repo_root: Path, budget: ScanBudget | None = None) -> tuple[str, ...]:
    """Load literal private terms from the gitignored local denylist."""
    active_budget = budget or ScanBudget.create()
    configured = os.environ.get(DENYLIST_ENV)
    path = Path(configured).expanduser() if configured else repo_root / DENYLIST_FILE
    if not path.is_file():
        return ()
    text = supported_text("", read_file(path, active_budget, str(path)))
    terms: list[str] = []
    for _number, raw in text_lines(text, active_budget):
        active_budget.debit_work()
        line = raw.strip()
        if line and not line.startswith("#"):
            terms.append(line)
    return tuple(terms)


def is_exact_github_merge_identity(line: str, match: re.Match[str]) -> bool:
    """Return whether an email match belongs to GitHub's exact merge identity."""
    email_offset = GITHUB_MERGE_IDENTITY.find(match.group())
    if email_offset < 0:
        return False
    identity_start = match.start() - email_offset
    identity_end = identity_start + len(GITHUB_MERGE_IDENTITY)
    if identity_start < 0 or line[identity_start:identity_end] != GITHUB_MERGE_IDENTITY:
        return False
    left_boundaries = (" ", "\t", '"', "'", "(", "[", "{", ":")
    right_separators = (" ", "\t")
    right_wrappers = ('"', "'", ".", ",", ")")
    left_boundary = identity_start == 0 or line[identity_start - 1] in left_boundaries
    wrapper_end = identity_end
    while wrapper_end < len(line) and line[wrapper_end] in right_wrappers:
        wrapper_end += 1
    right_boundary = wrapper_end == len(line) or line[wrapper_end] in right_separators
    return left_boundary and right_boundary


def scan_text(
    location: str,
    text: str,
    denylist: Sequence[str] = (),
    *,
    source_path: str | None = None,
    budget: ScanBudget | None = None,
) -> Iterator[Finding]:
    """Yield findings without retaining or displaying matched values."""
    lowered_terms = [(term, term.casefold()) for term in denylist]
    for number, line in text_lines(text, budget):
        if budget is not None:
            budget.debit_work()
        if ALLOW_MARKER in line and (source_path, number, line) != APPROVED_ALLOW_MARKER_LINE:
            if budget is not None:
                budget.record_finding()
            yield Finding(location, number, "allow-marker", "remove the forbidden policy bypass marker")
        for rule in RULES:
            if budget is not None:
                budget.debit_work()
            for match in rule.pattern.finditer(line):
                if rule.name == "email-address" and is_exact_github_merge_identity(line, match):
                    continue
                if budget is not None:
                    budget.record_finding()
                yield Finding(location, number, rule.name, rule.hint)
        folded = line.casefold()
        for _term, lowered in lowered_terms:
            if budget is not None:
                budget.debit_work()
            if lowered in folded:
                if budget is not None:
                    budget.record_finding()
                yield Finding(location, number, "private-denylist", f"listed in {DENYLIST_FILE}")


def git(repo_root: Path, *args: str, budget: ScanBudget | None = None) -> bytes:
    """Run one fixed Git operation with bounded captured output and no shell."""
    command = ["git", *args]
    process = subprocess.Popen(
        command,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.terminate()
        process.wait()
        raise GitBatchError
    output = process.stdout.read(MAX_TEXT_BYTES + 1)
    if len(output) > MAX_TEXT_BYTES:
        process.terminate()
        process.wait()
        process.stdout.close()
        raise GitBatchError
    try:
        if budget is not None:
            budget.debit_bytes(len(output))
    except ResourceLimitError:
        process.stdout.close()
        process.wait()
        raise
    process.stdout.close()
    return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(return_code, command)
    return output


def checked_path(path: str) -> str:
    """Validate one public Git path before using or scanning it."""
    try:
        encoded = path.encode("utf-8")
    except UnicodeEncodeError as error:
        raise UnsupportedArtifactError("<path>") from error
    if not encoded or len(encoded) > MAX_PATH_BYTES or "\0" in path:
        raise UnsupportedArtifactError("<path>")
    return path


def tracked(repo_root: Path, budget: ScanBudget | None = None) -> Iterable[Scannable]:
    active_budget = budget or ScanBudget.create()
    try:
        names = git(repo_root, "ls-files", "-z", budget=active_budget).decode("utf-8").split("\0")
    except UnicodeDecodeError as error:
        raise UnsupportedArtifactError("<tracked-path>") from error
    for index, raw_path in enumerate(names, start=1):
        if not raw_path:
            continue
        path = checked_path(raw_path)
        yield Scannable(f"<tracked-path:{index}>", path)
        file = repo_root / path
        if file.is_file():
            payload = read_file(file, active_budget, path)
            yield Scannable(f"<tracked-content:{index}>", supported_text(path, payload), path)


def staged(repo_root: Path, budget: ScanBudget | None = None) -> Iterable[Scannable]:
    active_budget = budget or ScanBudget.create()
    try:
        names = git(
            repo_root,
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
            budget=active_budget,
        ).decode("utf-8").split("\0")
    except UnicodeDecodeError as error:
        raise UnsupportedArtifactError("<staged-path>") from error
    for index, raw_path in enumerate(names, start=1):
        if not raw_path:
            continue
        path = checked_path(raw_path)
        yield Scannable(f"<staged-path:{index}>", path)
        payload = git(repo_root, "show", f":{path}", budget=active_budget)
        yield Scannable(f"<staged-content:{index}>", supported_text(path, payload), path)


class GitObjectBatch:
    """Read many bounded Git objects through one persistent cat-file process."""

    def __init__(self, repo_root: Path, budget: ScanBudget) -> None:
        self._budget = budget
        self._command = ["git", "cat-file", "--batch"]
        self._process = subprocess.Popen(
            self._command,
            cwd=repo_root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if self._process.stdin is None or self._process.stdout is None:
            self._process.terminate()
            self._process.wait()
            raise GitBatchError
        self._input = self._process.stdin
        self._output = self._process.stdout

    def __enter__(self) -> GitObjectBatch:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        try:
            self._input.close()
        except BrokenPipeError:
            pass
        if exc_type is not None and self._process.poll() is None:
            self._process.terminate()
        return_code = self._process.wait()
        self._output.close()
        if exc_type is None and return_code != 0:
            raise GitBatchError

    def read(self, object_id: str) -> tuple[bytes, bytes]:
        """Return one object's type and payload, validating size and framing."""
        try:
            encoded_id = object_id.encode("ascii")
            self._input.write(encoded_id + b"\n")
            self._input.flush()
            header = self._output.readline()
            returned_id, object_type, encoded_size = header.rstrip(b"\n").split(b" ")
            size = int(encoded_size)
            if returned_id != encoded_id or size < 0 or size > MAX_TEXT_BYTES:
                raise ValueError
            self._budget.debit_bytes(size)
            payload = self._output.read(size)
            terminator = self._output.read(1)
        except (BrokenPipeError, UnicodeEncodeError, ValueError) as error:
            raise GitBatchError from error
        if len(payload) != size or terminator != b"\n":
            raise GitBatchError
        return object_type, payload


def revision_object_ids(
    repo_root: Path,
    revision_args: Sequence[str],
    budget: ScanBudget | None = None,
) -> Iterator[str]:
    """Stream bounded object IDs reachable from the selected revisions."""
    active_budget = budget or ScanBudget.create()
    process = subprocess.Popen(
        ["git", "rev-list", "--objects", "--no-object-names", *revision_args, "--"],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.terminate()
        process.wait()
        raise GitBatchError
    completed = False
    try:
        for raw_line in process.stdout:
            active_budget.debit_bytes(len(raw_line))
            active_budget.debit_line()
            if len(raw_line) > 129:
                raise GitBatchError
            object_id = raw_line.rstrip(b"\n").decode("ascii")
            if OBJECT_ID.fullmatch(object_id) is None:
                raise GitBatchError
            yield object_id
        completed = True
    except (UnicodeDecodeError, GitBatchError, ResourceLimitError):
        if process.poll() is None:
            process.terminate()
        raise
    finally:
        process.stdout.close()
        if not completed and process.poll() is None:
            process.terminate()
        return_code = process.wait()
    if return_code != 0:
        raise GitBatchError


def commit_tree(payload: bytes) -> str:
    """Extract and validate a commit's root tree object ID."""
    first_line = payload.partition(b"\n")[0]
    prefix = b"tree "
    if not first_line.startswith(prefix):
        raise GitBatchError
    try:
        tree_id = first_line[len(prefix) :].decode("ascii")
    except UnicodeDecodeError as error:
        raise GitBatchError from error
    if OBJECT_ID.fullmatch(tree_id) is None:
        raise GitBatchError
    return tree_id


def tag_target(payload: bytes) -> tuple[str, bytes]:
    """Extract and validate an annotated tag's direct target."""
    header_block = payload.partition(b"\n\n")[0]
    values: dict[bytes, bytes] = {}
    start = 0
    while start < len(header_block):
        end = header_block.find(b"\n", start)
        if end < 0:
            end = len(header_block)
            next_start = len(header_block)
        else:
            next_start = end + 1
        header = header_block[start:end]
        key, separator, value = header.partition(b" ")
        if separator and key in {b"object", b"type"}:
            if key in values:
                raise GitBatchError
            values[key] = value
        start = next_start
    object_id = values.get(b"object", b"")
    object_type = values.get(b"type", b"")
    if object_type not in {b"blob", b"tree", b"commit", b"tag"}:
        raise GitBatchError
    try:
        decoded_id = object_id.decode("ascii")
    except UnicodeDecodeError as error:
        raise GitBatchError from error
    if OBJECT_ID.fullmatch(decoded_id) is None:
        raise GitBatchError
    return decoded_id, object_type


def tree_entries(payload: bytes, object_id_bytes: int) -> Iterator[tuple[bytes, str, str]]:
    """Parse one raw Git tree without accepting malformed or oversized names."""
    position = 0
    while position < len(payload):
        space = payload.find(b" ", position)
        nul = payload.find(b"\0", space + 1)
        object_end = nul + 1 + object_id_bytes
        if space <= position or nul <= space + 1 or object_end > len(payload):
            raise GitBatchError
        mode = payload[position:space]
        raw_name = payload[space + 1 : nul]
        raw_object_id = payload[nul + 1 : object_end]
        if len(raw_name) > MAX_PATH_BYTES or b"/" in raw_name:
            raise GitBatchError
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError as error:
            raise UnsupportedArtifactError("<history-path>") from error
        if not name or name in {".", ".."}:
            raise GitBatchError
        yield mode, name, raw_object_id.hex()
        position = object_end


def revision_roots(repo_root: Path, revisions: Sequence[str], budget: ScanBudget) -> set[str]:
    """Return bounded direct roots so non-commit refs cannot evade history scanning."""
    roots: set[str] = set()
    if revisions:
        for revision in revisions:
            root = revision.rpartition("..")[2]
            budget.debit_bytes(len(root.encode("ascii")))
            budget.debit_line()
            roots.add(root)
        return roots

    refs = git(repo_root, "for-each-ref", "--format=%(objectname)", budget=budget)
    for raw_id in byte_lines(refs, budget):
        try:
            object_id = raw_id.decode("ascii")
        except UnicodeDecodeError as error:
            raise GitBatchError from error
        if OBJECT_ID.fullmatch(object_id) is None:
            raise GitBatchError
        roots.add(object_id)
    head = git(repo_root, "rev-parse", "--verify", "HEAD", budget=budget).strip()
    if head:
        try:
            head_id = head.decode("ascii")
        except UnicodeDecodeError as error:
            raise GitBatchError from error
        if OBJECT_ID.fullmatch(head_id) is None:
            raise GitBatchError
        budget.debit_line()
        roots.add(head_id)
    return roots


def history(
    repo_root: Path,
    revisions: Sequence[str] = (),
    budget: ScanBudget | None = None,
) -> Iterable[Scannable]:
    """Scan metadata plus every reachable tree-entry path/blob association."""
    active_budget = budget or ScanBudget.create()
    revision_args = list(revisions) if revisions else ["--all", "HEAD"]
    object_format = git(
        repo_root,
        "rev-parse",
        "--show-object-format",
        budget=active_budget,
    ).decode("ascii").strip()
    if object_format not in {"sha1", "sha256"}:
        raise GitBatchError
    object_id_bytes = 20 if object_format == "sha1" else 32
    root_trees: set[str] = set()
    direct_blobs: set[str] = set()
    seen_objects: set[str] = set()
    scanned_metadata: set[str] = set()

    def register(object_id: str) -> bool:
        if object_id in seen_objects:
            return False
        active_budget.record_history_object()
        seen_objects.add(object_id)
        return True

    with GitObjectBatch(repo_root, active_budget) as objects:
        direct_roots = revision_roots(repo_root, revisions, active_budget)
        for object_id in revision_object_ids(repo_root, revision_args, active_budget):
            register(object_id)
            object_type, payload = objects.read(object_id)
            if object_type == b"commit":
                root_trees.add(commit_tree(payload))
                scanned_metadata.add(object_id)
                yield Scannable(f"<commit>@{object_id[:10]}", supported_text("", payload))
            elif object_type == b"tag":
                target_id, target_type = tag_target(payload)
                if target_type == b"tree":
                    root_trees.add(target_id)
                elif target_type == b"blob":
                    direct_blobs.add(target_id)
                scanned_metadata.add(object_id)
                yield Scannable(f"<tag>@{object_id[:10]}", supported_text("", payload))

        pending_roots = list(direct_roots)
        while pending_roots:
            object_id = pending_roots.pop()
            register(object_id)
            object_type, payload = objects.read(object_id)
            if object_type == b"commit":
                root_trees.add(commit_tree(payload))
                if object_id not in scanned_metadata:
                    scanned_metadata.add(object_id)
                    yield Scannable(f"<commit>@{object_id[:10]}", supported_text("", payload))
            elif object_type == b"tag":
                target_id, target_type = tag_target(payload)
                pending_roots.append(target_id)
                if object_id not in scanned_metadata:
                    scanned_metadata.add(object_id)
                    yield Scannable(f"<tag>@{object_id[:10]}", supported_text("", payload))
            elif object_type == b"tree":
                root_trees.add(object_id)
            elif object_type == b"blob":
                direct_blobs.add(object_id)
            else:
                raise GitBatchError

        for blob_id in direct_blobs:
            register(blob_id)
            object_type, payload = objects.read(blob_id)
            if object_type != b"blob":
                raise GitBatchError
            yield Scannable(f"<tag-blob>@{blob_id[:10]}", supported_text("", payload))

        pending = [(tree_id, "") for tree_id in root_trees]
        visited_tree_paths: set[tuple[str, str]] = set()
        while pending:
            tree_id, prefix = pending.pop()
            tree_path = (tree_id, prefix)
            if tree_path in visited_tree_paths:
                continue
            active_budget.debit_work()
            visited_tree_paths.add(tree_path)
            register(tree_id)
            object_type, payload = objects.read(tree_id)
            if object_type != b"tree":
                raise GitBatchError
            for mode, name, child_id in tree_entries(payload, object_id_bytes):
                active_budget.record_tree_association()
                active_budget.debit_work()
                register(child_id)
                path = checked_path(f"{prefix}/{name}" if prefix else name)
                yield Scannable(f"<history-path>@{tree_id[:10]}", path)
                if mode == b"40000" or mode == b"040000":
                    pending.append((child_id, path))
                elif mode == b"160000":
                    continue
                else:
                    child_type, child_payload = objects.read(child_id)
                    if child_type != b"blob":
                        raise GitBatchError
                    yield Scannable(
                        f"<blob>@{child_id[:10]}",
                        supported_text(path, child_payload),
                        path,
                    )


def checked_ref(value: str) -> str:
    """Validate one ref name without retaining it in diagnostics."""
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise UnsupportedArtifactError("<pushed-ref>") from error
    if not encoded or len(encoded) > MAX_REF_BYTES or "\0" in value or "\n" in value or "\r" in value:
        raise UnsupportedArtifactError("<pushed-ref>")
    return value


def references(
    values: Sequence[str],
    budget: ScanBudget | None = None,
    *,
    bytes_accounted: bool = False,
) -> Iterable[Scannable]:
    """Validate and expose pushed ref names for the policy scan."""
    active_budget = budget or ScanBudget.create()
    for index, value in enumerate(values, start=1):
        checked_ref(value)
        if not bytes_accounted:
            active_budget.debit_bytes(len(value.encode("utf-8")))
            active_budget.debit_line()
        yield Scannable(f"<pushed-ref:{index}>", value)


def reference_file(path: Path, budget: ScanBudget) -> Iterable[Scannable]:
    """Read private newline-delimited ref names without putting them on argv."""
    payload = read_file(path, budget, "<pushed-ref-file>")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise UnsupportedArtifactError("<pushed-ref-file>") from error
    values: list[str] = []
    for _number, value in text_lines(text, budget):
        values.append(checked_ref(value))
    return references(values, budget, bytes_accounted=True)


def message_file(path: Path, budget: ScanBudget | None = None) -> Iterable[Scannable]:
    """Read one bounded Git message file without treating it as trusted source."""
    active_budget = budget or ScanBudget.create()
    yield Scannable("<git-message>", supported_text("", read_file(path, active_budget, "<git-message>")))


def emit_bounded(messages: Sequence[tuple[str, TextIO]], *, resource_exhausted: bool = False) -> bool:
    """Emit bounded diagnostics and report whether truncation consumed the budget."""
    limit = max(0, MAX_DIAGNOSTIC_BYTES)
    encoded_size = sum(len(message.encode("utf-8")) for message, _stream in messages)
    if not resource_exhausted and encoded_size <= limit:
        for message, stream in messages:
            stream.write(message)
        return False

    generic = "check_local_refs: scan truncated at a resource limit\n"
    generic_bytes = generic.encode("utf-8")
    regular_limit = max(0, limit - min(limit, len(generic_bytes)))
    used = 0
    for message, stream in messages:
        size = len(message.encode("utf-8"))
        if size > regular_limit - used:
            break
        stream.write(message)
        used += size
    remaining = limit - used
    if remaining:
        sys.stderr.write(generic_bytes[:remaining].decode("ascii"))
    return True


class ScanMode(Enum):
    """One repository view exposed by the command-line interface."""

    TRACKED = "tracked files"
    STAGED = "staged changes"
    HISTORY = "history"
    REFERENCES = "pushed ref names"
    MESSAGE = "Git message"


@dataclass(frozen=True)
class ScanSelection:
    """The selected repository view and arguments needed to read it."""

    mode: ScanMode
    revisions: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()
    path: Path | None = None

    @property
    def scope(self) -> str:
        return self.mode.value


def parse_selection(argv: Sequence[str] | None) -> ScanSelection:
    """Parse and validate arguments into one scanner selection."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--history", action="store_true")
    mode.add_argument("--ref", action="append", default=[], metavar="REF")
    mode.add_argument("--ref-file", type=Path, metavar="PATH")
    mode.add_argument("--message-file", type=Path, metavar="PATH")
    parser.add_argument(
        "--revision",
        action="append",
        default=[],
        metavar="REV",
        help="scan this exact revision or range (requires --history; repeatable)",
    )
    args = parser.parse_args(argv)
    if args.revision and not args.history:
        parser.error("--revision requires --history")
    if any(PUSH_REVISION.fullmatch(revision) is None for revision in args.revision):
        parser.error("--revision must be a full commit ID or commit range")

    if args.staged:
        return ScanSelection(ScanMode.STAGED)
    if args.history:
        return ScanSelection(ScanMode.HISTORY, revisions=tuple(args.revision))
    if args.ref_file is not None:
        return ScanSelection(ScanMode.REFERENCES, path=args.ref_file)
    if args.ref:
        return ScanSelection(ScanMode.REFERENCES, refs=tuple(args.ref))
    if args.message_file is not None:
        return ScanSelection(ScanMode.MESSAGE, path=args.message_file)
    return ScanSelection(ScanMode.TRACKED)


def selected_content(
    selection: ScanSelection,
    repo_root: Path,
    budget: ScanBudget,
) -> Iterable[Scannable]:
    """Open the source represented by one validated scanner selection."""
    if selection.mode is ScanMode.STAGED:
        return staged(repo_root, budget)
    if selection.mode is ScanMode.HISTORY:
        return history(repo_root, selection.revisions, budget)
    if selection.mode is ScanMode.REFERENCES:
        if selection.path is not None:
            return reference_file(selection.path, budget)
        return references(selection.refs, budget)
    if selection.mode is ScanMode.MESSAGE:
        if selection.path is None:
            raise AssertionError("message-file selection requires a path")
        return message_file(selection.path, budget)
    return tracked(repo_root, budget)


def scan_selection(
    selection: ScanSelection,
    budget: ScanBudget,
    findings: list[Finding],
) -> None:
    """Scan one selected source, retaining partial findings on failure."""
    repo_root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel", budget=budget).decode().strip())
    denylist = load_denylist(repo_root, budget)
    for item in selected_content(selection, repo_root, budget):
        findings.extend(
            scan_text(
                item.location,
                item.text,
                denylist,
                source_path=item.source_path,
                budget=budget,
            )
        )


def scan_failure_message(error: Exception, scope: str) -> str:
    """Map a scanner exception to a non-sensitive diagnostic."""
    if isinstance(error, UnsupportedArtifactError):
        return f"check_local_refs: unsupported artifact in {scope}\n"
    if isinstance(error, GitBatchError):
        return "check_local_refs: git object scan failed\n"
    return f"check_local_refs: scan failed: {type(error).__name__}\n"


def render_result(
    findings: Sequence[Finding],
    scope: str,
    *,
    failure_message: str | None = None,
    resource_exhausted: bool = False,
) -> int:
    """Render one bounded scanner result and return its exit status."""
    messages: list[tuple[str, TextIO]] = [(f"{finding.render()}\n", sys.stdout) for finding in findings]
    if failure_message is not None:
        messages.append((failure_message, sys.stderr))
        emit_bounded(messages)
        return 2
    if resource_exhausted:
        emit_bounded(messages, resource_exhausted=True)
        return 2
    if findings:
        messages.append((f"found {len(findings)} local-setup reference(s) in {scope}\n", sys.stderr))
        if emit_bounded(messages):
            return 2
        return 1
    messages.append((f"no local-setup references in {scope}\n", sys.stdout))
    if emit_bounded(messages):
        return 2
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Scan the selected repository view and return 0 only when clean."""
    selection = parse_selection(argv)
    budget = ScanBudget.create()
    findings: list[Finding] = []
    try:
        scan_selection(selection, budget, findings)
    except ResourceLimitError:
        return render_result(findings, selection.scope, resource_exhausted=True)
    except (
        UnsupportedArtifactError,
        GitBatchError,
        OSError,
        subprocess.CalledProcessError,
        UnicodeDecodeError,
    ) as error:
        return render_result(
            findings,
            selection.scope,
            failure_message=scan_failure_message(error, selection.scope),
        )
    return render_result(findings, selection.scope)


if __name__ == "__main__":
    raise SystemExit(main())
