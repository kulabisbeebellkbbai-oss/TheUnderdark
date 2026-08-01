#!/usr/bin/env python3
"""Narrow advisory preflight and evidence guard for TheUnderdark MCP work."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path


DOMAIN = re.compile(
    r"\b(theunderdark|underdark_[a-z_]+|storage execution adapter|"
    r"(?:donuthole|roadex).{0,80}\bstorage\b)\b",
    re.IGNORECASE | re.DOTALL,
)
EXECUTION = re.compile(
    r"\b(execut(?:e|ed|ion)|mutat(?:e|ion)|write|copy|move|delete|create|"
    r"operation|adapter)\b",
    re.IGNORECASE,
)
TOOL_EVIDENCE = re.compile(
    r"\bunderdark_(?:health_get|project_get|root_get|path_stat|directory_list|"
    r"operation_get|directory_create|file_write|path_copy|path_move|path_delete)\b",
    re.IGNORECASE,
)
RESULT_EVIDENCE = re.compile(
    r"\b(operation[_ ]id|terminal (?:state|status)|redacted evidence)\b",
    re.IGNORECASE,
)


def payload() -> dict:
    try:
        return json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return {}


def prompt_text(data: dict) -> str:
    for key in ("prompt", "user_prompt", "message"):
        if isinstance(data.get(key), str):
            return data[key]
    return json.dumps(data, sort_keys=True)


def last_messages(path: str | None) -> tuple[str, str]:
    if not path:
        return "", ""
    user: list[str] = []
    assistant: list[str] = []
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            item = json.loads(line)
            body = item.get("payload", {})
            if item.get("type") != "response_item" or body.get("type") != "message":
                continue
            text = " ".join(
                part.get("text", "") for part in body.get("content", []) if isinstance(part, dict)
            )
            if body.get("role") == "user":
                user.append(text)
            elif body.get("role") == "assistant":
                assistant.append(text)
    except (OSError, json.JSONDecodeError):
        return "", ""
    return "\n".join(user[-1:]), "\n".join(assistant[-1:])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--stop-check", action="store_true")
    args = parser.parse_args()
    data = payload()
    if args.preflight:
        if DOMAIN.search(prompt_text(data)):
            if shutil.which("theunderdark-mcp") is None:
                print(
                    "TheUnderdark MCP is required but its configured stdio executable "
                    "`theunderdark-mcp` is unavailable. Do not execute storage work. Verify the "
                    "reviewed plugin installation and run `codex mcp get theunderdark`.",
                    file=sys.stderr,
                )
                return 2
            print(json.dumps({
                "continue": True,
                "suppressOutput": True,
                "systemMessage": (
                    "Use the TheUnderdark MCP for registered storage work. Mutations require an exact "
                    "Overseer authorization; include terminal redacted MCP evidence in the result."
                ),
            }))
        return 0

    user, assistant = last_messages(data.get("transcript_path"))
    if (
        DOMAIN.search(user)
        and EXECUTION.search(user)
        and not (TOOL_EVIDENCE.search(assistant) and RESULT_EVIDENCE.search(assistant))
    ):
        print(
            "TheUnderdark execution answer lacks MCP evidence. Use the registered TheUnderdark MCP "
            "and report the tool, operation ID, terminal state, and redacted evidence; do not infer success.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
