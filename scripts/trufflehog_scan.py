#!/usr/bin/env python3
"""Run a full-history TruffleHog scan and allow only reviewed exact findings."""

from __future__ import annotations

import hashlib
import json
import re
import argparse
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
IMAGE = (
    "ghcr.io/trufflesecurity/trufflehog@sha256:"
    "674b2f187620a19df77f44cf9a7d77efcc581a5662accef2f2739cbb46ba4a3a"
)
ALLOWLIST = ROOT / ".trufflehog-allowlist.json"


def git_metadata(finding: dict[str, Any]) -> dict[str, Any]:
    metadata = finding.get("SourceMetadata", {})
    data = metadata.get("Data", {}) if isinstance(metadata, dict) else {}
    git = data.get("Git", {}) if isinstance(data, dict) else {}
    return git if isinstance(git, dict) else {}


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Hash detector, source location, and candidate without storing the candidate."""
    git = git_metadata(finding)
    detector = finding.get("DetectorName")
    raw = finding.get("RawV2") or finding.get("Raw")
    if not isinstance(detector, str) or not isinstance(raw, str) or not raw:
        raise ValueError("finding is missing detector or candidate metadata")
    if not all(isinstance(git.get(key), str) and git.get(key) for key in ("commit", "file")):
        raise ValueError("finding is missing Git commit or file metadata")
    line = git.get("line")
    if line is None:
        raise ValueError("finding is missing Git line metadata")
    identity = "\0".join((detector, git["commit"], git["file"], str(line), raw))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def load_allowlist(path: Path = ALLOWLIST) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("findings"), list):
        raise ValueError("allowlist must contain version 1 and a findings list")

    allowed: dict[str, dict[str, Any]] = {}
    for item in data["findings"]:
        required = ("fingerprint", "detector", "commit", "file", "line", "reason")
        if not isinstance(item, dict) or any(not item.get(key) for key in required):
            raise ValueError("each allowlist entry needs a fingerprint, location, detector, and reason")
        fingerprint = item["fingerprint"]
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("allowlist fingerprint must be a lowercase SHA-256 hash")
        if fingerprint in allowed:
            raise ValueError("allowlist contains a duplicate fingerprint")
        allowed[fingerprint] = item
    return allowed


def evaluate_findings(
    lines: Iterable[str], allowed: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], set[str]]:
    rejected: list[dict[str, Any]] = []
    matched: set[str] = set()

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
            if not isinstance(finding, dict):
                raise ValueError
            fingerprint = finding_fingerprint(finding)
        except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
            rejected.append({"reason": "invalid finding record", "record": number})
            continue

        if finding.get("Verified") is True:
            rejected.append({"reason": "verified finding", "finding": _finding_summary(finding)})
            continue

        entry = allowed.get(fingerprint)
        git = git_metadata(finding)
        if (
            entry is not None
            and finding.get("Verified") is False
            and entry["detector"] == finding.get("DetectorName")
            and entry["commit"] == git.get("commit")
            and entry["file"] == git.get("file")
            and str(entry["line"]) == str(git.get("line"))
        ):
            matched.add(fingerprint)
        else:
            rejected.append({"reason": "unreviewed finding", "finding": _finding_summary(finding)})

    return rejected, matched


def _finding_summary(finding: dict[str, Any]) -> dict[str, Any]:
    """Keep only identifying metadata; never retain the candidate in reports."""
    git = git_metadata(finding)
    return {
        "DetectorName": finding.get("DetectorName"),
        "SourceMetadata": {"Data": {"Git": {key: git.get(key) for key in ("commit", "file", "line")}}},
    }


def workflow_error(message: str) -> None:
    escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error::{escaped}")


def report_rejection(rejection: dict[str, Any]) -> None:
    if rejection.get("reason") == "invalid finding record":
        workflow_error(f"TruffleHog emitted an invalid JSON finding record at line {rejection['record']}")
        return

    finding = rejection["finding"]
    git = git_metadata(finding)
    detector = str(finding.get("DetectorName", "unknown detector"))
    commit = str(git.get("commit", "unknown commit"))
    source_file = str(git.get("file", "unknown file")).replace("\r", "?").replace("\n", "?")
    line = str(git.get("line", "?"))
    workflow_error(f"{rejection['reason']}: {detector} at {source_file}:{line} ({commit})")


def run_scan(jsonl_stdin: bool = False) -> int:
    container_name = f"ipgaze-trufflehog-{uuid.uuid4().hex[:8]}"
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "-v",
        f"{ROOT}:/repo:ro",
        "-w",
        "/repo",
        IMAGE,
        "git",
        "file:///repo",
        "--json",
        "--results=verified,unknown",
        "--no-update",
        "--fail-on-scan-errors",
    ]

    try:
        allowed = load_allowlist()
    except (OSError, json.JSONDecodeError, ValueError) as error:
        workflow_error(f"Unable to load TruffleHog finding allowlist: {error}")
        return 2

    if jsonl_stdin:
        rejected, matched = evaluate_findings(sys.stdin, allowed)
    else:
        with tempfile.TemporaryDirectory(prefix="ipgaze-trufflehog-") as temp_dir:
            output_path = Path(temp_dir) / "findings.jsonl"
            try:
                with output_path.open("w", encoding="utf-8") as output:
                    result = subprocess.run(command, cwd=ROOT, stdout=output, check=False)
            except OSError as error:
                workflow_error(f"Unable to run TruffleHog: {error}")
                return 2

            if result.returncode != 0:
                workflow_error(f"TruffleHog scan failed with exit code {result.returncode}")
                return result.returncode

            try:
                with output_path.open(encoding="utf-8") as output:
                    rejected, matched = evaluate_findings(output, allowed)
            except OSError as error:
                workflow_error(f"Unable to read TruffleHog results: {error}")
                return 2

    for fingerprint, entry in allowed.items():
        if fingerprint not in matched:
            workflow_error(
                f"Stale TruffleHog allowlist entry: {entry['detector']} at "
                f"{entry['file']}:{entry['line']} ({entry['commit']})"
            )
        else:
            print(
                f"Reviewed TruffleHog finding: {entry['detector']} at "
                f"{entry['file']}:{entry['line']} ({entry['commit']}) — {entry['reason']}"
            )

    for rejection in rejected:
        report_rejection(rejection)

    if rejected or len(matched) != len(allowed):
        return 1

    print(f"TruffleHog full-history scan passed; reviewed findings: {len(matched)}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jsonl-stdin", action="store_true", help="evaluate TruffleHog JSONL from stdin")
    sys.exit(run_scan(jsonl_stdin=parser.parse_args().jsonl_stdin))
