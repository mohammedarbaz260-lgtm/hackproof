"""HackProof threat-intelligence enrichment foundation.

Provider-neutral and offline-safe. External providers can be added later
without changing the existing security analyzers.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


_HASH_LENGTHS = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256",
    96: "SHA-384",
    128: "SHA-512",
}


def identify_indicator(value: str) -> dict:
    """Classify a supported IOC without making external network requests."""
    value = (value or "").strip()

    if not value:
        return {
            "input": "",
            "type": "unknown",
            "normalized": "",
        }

    try:
        ipaddress.ip_address(value)
        return {
            "input": value,
            "type": "ip",
            "normalized": value,
        }
    except ValueError:
        pass

    if value.lower().startswith(("http://", "https://")):
        parsed = urlparse(value)
        return {
            "input": value,
            "type": "url",
            "normalized": parsed.geturl(),
            "host": parsed.hostname or "",
        }

    if re.fullmatch(r"[A-Fa-f0-9]+", value):
        hash_type = _HASH_LENGTHS.get(len(value))
        if hash_type:
            return {
                "input": value,
                "type": "hash",
                "normalized": value.lower(),
                "hash_type": hash_type,
            }

    domain_pattern = r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
    if re.fullmatch(domain_pattern, value):
        return {
            "input": value,
            "type": "domain",
            "normalized": value.lower(),
        }

    return {
        "input": value,
        "type": "unknown",
        "normalized": value,
    }


def enrich_indicator(value: str) -> dict:
    """Return the normalized IOC plus an offline enrichment status."""
    indicator = identify_indicator(value)

    return {
        **indicator,
        "enrichment": {
            "status": "not_configured",
            "providers": [],
            "results": [],
        },
    }


if __name__ == "__main__":
    import sys

    value = " ".join(sys.argv[1:]).strip()
    print(enrich_indicator(value))
