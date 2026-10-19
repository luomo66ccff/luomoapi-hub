"""Model "lines": each family gets one signage colour key, letter and number.

Templates, the public catalog JSON and the live departure board all read this one mapping.
"""
from __future__ import annotations

import re

_FAMILIES = (
    ("luna", "luna", "L"),
    ("terra", "terra", "T"),
    ("astra", "astra", "A"),
    ("sol", "sol", "S"),
    ("codex", "codex", "C"),
    ("image", "image", "I"),
)


def line_for(model_id: str | None) -> dict:
    model = (model_id or "").lower()
    family, letter = "other", "G" if model.startswith("gpt") else (model[:1] or "?").upper()
    for keyword, name, code in _FAMILIES:
        if keyword in model:
            family, letter = name, code
            break
    version = re.search(r"(\d+)(?:\.(\d+))?", model)
    number = (version.group(1) + (version.group(2) or "0"))[:2] if version else "00"
    return {"family": family, "letter": letter, "number": number}


def board_state(model_id: str, text_candidate: bool) -> dict:
    """Departure-board lamp for a model: boardable, not opened, or not priced."""
    if text_candidate:
        return {"tone": "ok", "label": "可乘车"}
    if model_id.startswith("gpt-image-"):
        return {"tone": "off", "label": "暂未开放"}
    return {"tone": "warn", "label": "未计价"}
