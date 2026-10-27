"""One canonical JSON implementation for portal, catalog and future delivery admission."""

import hashlib
import json
from typing import Any

import rfc8785


def canonical(value: Any) -> bytes:
    return rfc8785.dumps(value)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def strict_json(data: str | bytes) -> Any:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def bad_constant(_value):
        raise ValueError("Non-finite JSON number")

    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=bad_constant)
