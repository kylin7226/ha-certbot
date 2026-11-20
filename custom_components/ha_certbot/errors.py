from __future__ import annotations

from collections.abc import Iterable
import json
import re
from urllib.parse import quote, quote_plus


def redact(message: str, secrets: Iterable[str] = ()) -> str:
    variants = set()
    for value in secrets:
        if value:
            value = str(value)
            variants.update((value, quote(value, safe=""), quote_plus(value), json.dumps(value)[1:-1]))
    for value in sorted(variants, key=len, reverse=True):
        message = message.replace(value, "[redacted]")
    message = re.sub(r"https?://[^\s<>\"']+", "[URL redacted]", message)
    message = re.sub(
        r"(?i)((?:token|secret|password|signature|authorization|api[_-]?key)\s*[:=]\s*)[^\s,;}]+",
        r"\1[redacted]", message,
    )
    return message
