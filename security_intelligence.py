import hashlib
import ipaddress
import re
from urllib.parse import urlparse


def analyze_indicator(value: str) -> dict:
    value = (value or "").strip()

    if not value:
        return {
            "input": "",
            "type": "unknown",
            "risk": "UNKNOWN",
            "score": 0,
            "indicators": [],
            "recommendation": "Provide an indicator to analyze.",
        }

    # IP address detection
    try:
        ip = ipaddress.ip_address(value)

        if ip.is_private:
            ip_type = "private IP"
        elif ip.is_loopback:
            ip_type = "loopback IP"
        elif ip.is_reserved:
            ip_type = "reserved IP"
        else:
            ip_type = "public IP"

        return {
            "input": value,
            "type": "ip",
            "risk": "INFO",
            "score": 10,
            "indicators": [f"Valid {ip_type}: {ip}"],
            "recommendation": (
                "Validate ownership and investigate network activity "
                "before taking action."
            ),
        }
    except ValueError:
        pass

    # URL detection
    if value.lower().startswith(("http://", "https://")):
        parsed = urlparse(value)

        if parsed.hostname:
            return {
                "input": value,
                "type": "url",
                "risk": "INFO",
                "score": 10,
                "indicators": [f"URL hostname: {parsed.hostname}"],
                "recommendation": (
                    "Use the phishing detector for deeper URL risk analysis."
                ),
            }

    # Hash detection
    hash_patterns = {
        32: "MD5",
        40: "SHA-1",
        64: "SHA-256",
        96: "SHA-384",
        128: "SHA-512",
    }

    if re.fullmatch(r"[A-Fa-f0-9]+", value):
        hash_type = hash_patterns.get(len(value))

        if hash_type:
            return {
                "input": value,
                "type": "hash",
                "risk": "INFO",
                "score": 10,
                "indicators": [f"Valid {hash_type} hash format"],
                "recommendation": (
                    "Compare the hash with an authorized threat-intelligence "
                    "source before determining whether it is malicious."
                ),
            }

    # Domain detection
    domain_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}$"
    )

    if re.fullmatch(domain_pattern, value):
        return {
            "input": value,
            "type": "domain",
            "risk": "INFO",
            "score": 10,
            "indicators": [f"Domain format detected: {value}"],
            "recommendation": (
                "Use DNS and authorized reputation checks before trusting "
                "the domain."
            ),
        }

    return {
        "input": value,
        "type": "unknown",
        "risk": "UNKNOWN",
        "score": 0,
        "indicators": ["Input did not match a supported indicator format."],
        "recommendation": (
            "Provide an IP, domain, URL, or recognized hexadecimal hash."
        ),
    }


def format_indicator_result(result: dict) -> str:
    lines = [
        "HACKPROOF SECURITY INTELLIGENCE",
        f"Input: {result.get('input', '')}",
        f"Type: {result.get('type', 'UNKNOWN')}",
        f"Risk: {result.get('risk', 'UNKNOWN')}",
        f"Risk Score: {result.get('score', 0)}/100",
    ]

    indicators = result.get("indicators", [])

    if indicators:
        lines.append("Indicators:")
        for indicator in indicators:
            lines.append(f"- {indicator}")
    else:
        lines.append("Indicators: None detected")

    lines.append(
        f"Recommendation: {result.get('recommendation', '')}"
    )

    return "\n".join(lines)


if __name__ == "__main__":
    print("HackProof Security Intelligence")

    user_input = input("Enter IP, domain, URL, or hash: ").strip()

    result = analyze_indicator(user_input)

    print()
    print(format_indicator_result(result))
