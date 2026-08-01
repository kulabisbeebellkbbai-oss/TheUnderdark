from __future__ import annotations

import importlib.util
import json
from pathlib import Path


GUARD = (
    Path(__file__).parents[1]
    / "plugins"
    / "theunderdark-mcp"
    / "hooks"
    / "theunderdark_mcp_guard.py"
)


def load_guard():
    spec = importlib.util.spec_from_file_location("theunderdark_mcp_guard", GUARD)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_guard_domain_is_narrow() -> None:
    guard = load_guard()
    assert guard.DOMAIN.search("Use TheUnderdark for this storage operation")
    assert guard.DOMAIN.search("Call underdark_path_stat")
    assert not guard.DOMAIN.search("Explain ordinary local file permissions")


def test_guard_reads_latest_user_and_assistant_evidence(tmp_path: Path) -> None:
    transcript = tmp_path / "rollout.jsonl"
    rows = [
        {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "Execute a TheUnderdark write"}],
            },
        },
        {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": (
                            "underdark_file_write returned operation_id op-1 "
                            "with terminal state succeeded and redacted evidence."
                        ),
                    }
                ],
            },
        },
    ]
    transcript.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    user, assistant = load_guard().last_messages(str(transcript))
    assert "TheUnderdark write" in user
    assert "underdark_file_write" in assistant
