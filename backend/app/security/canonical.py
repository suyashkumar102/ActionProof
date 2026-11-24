from __future__ import annotations

import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Stable JSON representation used for all hashes and signatures."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

