#!/usr/bin/env python3
"""Privately scan bounded Git object payloads through persistent subprocesses."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO

MAX_OBJECTS = 1_000_000
MAX_OBJECT_BYTES = 8 * 1024 * 1024
MAX_AGGREGATE_BYTES = 64 * 1024 * 1024
MAX_OBJECT_ID_LINE_BYTES = 129
OBJECT_ID = re.compile(rb"(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})")
OBJECT_TYPES = frozenset({b"blob", b"commit", b"tag", b"tree"})


class ObjectScanError(Exception):
    """The complete bounded object stream could not be inspected."""


def read_header(stream: BinaryIO) -> tuple[bytes, bytes, int]:
    """Read and validate one bounded ``git cat-file --batch`` header."""
    header = stream.readline(256)
    if not header.endswith(b"\n") or len(header) == 256:
        raise ObjectScanError
    fields = header[:-1].split(b" ")
    if len(fields) != 3:
        raise ObjectScanError
    returned_id, object_type, raw_size = fields
    if OBJECT_ID.fullmatch(returned_id) is None or object_type not in OBJECT_TYPES:
        raise ObjectScanError
    try:
        size = int(raw_size)
    except ValueError as error:
        raise ObjectScanError from error
    if size < 0 or size > MAX_OBJECT_BYTES:
        raise ObjectScanError
    return returned_id, object_type, size


def close_pipe(stream: BinaryIO) -> None:
    """Close a child pipe without exposing a rejected scanner's broken pipe."""
    try:
        stream.close()
    except BrokenPipeError:
        pass


def terminate(process: subprocess.Popen[bytes]) -> None:
    """Stop a child process without allowing cleanup failures to mask rejection."""
    if process.poll() is None:
        process.terminate()
    process.wait()


def scan_objects(object_file: Path) -> None:
    """Validate and scan each listed object with one Git and one Gitleaks process."""
    if not object_file.is_file() or object_file.is_symlink():
        raise ObjectScanError

    try:
        git_process = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise ObjectScanError from error
    try:
        gitleaks_process = subprocess.Popen(
            [
                "gitleaks",
                "stdin",
                "--config",
                ".gitleaks.toml",
                "--redact",
                "--no-banner",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        terminate(git_process)
        raise ObjectScanError from error
    if git_process.stdin is None or git_process.stdout is None or gitleaks_process.stdin is None:
        terminate(git_process)
        terminate(gitleaks_process)
        raise ObjectScanError

    git_input = git_process.stdin
    git_output = git_process.stdout
    scanner_input = gitleaks_process.stdin
    object_count = 0
    aggregate_size = 0
    completed = False
    try:
        with object_file.open("rb") as object_ids:
            while raw_line := object_ids.readline(MAX_OBJECT_ID_LINE_BYTES + 1):
                if len(raw_line) > MAX_OBJECT_ID_LINE_BYTES or not raw_line.endswith(b"\n"):
                    raise ObjectScanError
                object_id = raw_line[:-1]
                if OBJECT_ID.fullmatch(object_id) is None:
                    raise ObjectScanError
                object_count += 1
                if object_count > MAX_OBJECTS:
                    raise ObjectScanError

                git_input.write(object_id + b"\n")
                git_input.flush()
                returned_id, _object_type, object_size = read_header(git_output)
                if returned_id.lower() != object_id.lower():
                    raise ObjectScanError
                aggregate_size += object_size
                if aggregate_size > MAX_AGGREGATE_BYTES:
                    raise ObjectScanError

                remaining = object_size
                while remaining:
                    chunk = git_output.read(min(64 * 1024, remaining))
                    if not chunk:
                        raise ObjectScanError
                    scanner_input.write(chunk)
                    remaining -= len(chunk)
                if git_output.read(1) != b"\n":
                    raise ObjectScanError
                # Gitleaks scans stdin line by line. A newline makes EOF-equivalent
                # object boundaries explicit without changing bytes inside an object.
                scanner_input.write(b"\n")
        close_pipe(git_input)
        close_pipe(scanner_input)
        if git_process.wait() != 0 or gitleaks_process.wait() != 0:
            raise ObjectScanError
        completed = True
    except (BrokenPipeError, OSError) as error:
        raise ObjectScanError from error
    finally:
        if not git_input.closed:
            close_pipe(git_input)
        if not scanner_input.closed:
            close_pipe(scanner_input)
        git_output.close()
        if not completed:
            terminate(git_process)
            terminate(gitleaks_process)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("object_file", type=Path, help="private newline-delimited Git object IDs")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        scan_objects(args.object_file)
    except ObjectScanError:
        print("secret scan rejected a private Git object stream", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
