from urllib.parse import urlparse
import re


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "bank",
    "wallet",
    "payment",
    "signin",
    "confirm",
}


def analyze_url(url: str) -> dict:
    """Perform a local, non-networked phishing-risk analysis of a URL."""
    url = url.strip()

    result = {
        "url": url,
        "risk": "LOW",
        "score": 0,
        "indicators": [],
        "recommendation": "No strong phishing indicators detected.",
    }

    if not url:
        result["risk"] = "UNKNOWN"
        result["recommendation"] = "Provide a URL to analyze."
        return result

    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        result["risk"] = "UNKNOWN"
        result["recommendation"] = "The URL could not be parsed."
        return result

    if parsed.scheme != "https":
        result["score"] += 15
        result["indicators"].append("URL does not use HTTPS")

    if "@" in url:
        result["score"] += 25
        result["indicators"].append("URL contains an @ symbol")

    if len(url) > 100:
        result["score"] += 10
        result["indicators"].append("Unusually long URL")

    if hostname.replace(".", "").isdigit():
        result["score"] += 25
        result["indicators"].append("Hostname is an IP address")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        result["score"] += 20
        result["indicators"].append("Internationalized/punycode hostname")

    subdomains = hostname.split(".")
    if len(subdomains) >= 4:
        result["score"] += 15
        result["indicators"].append("Many hostname subdomains")

    matched_keywords = [
        keyword for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url.lower()
    ]

    if matched_keywords:
        result["score"] += min(30, len(matched_keywords) * 10)
        result["indicators"].append(
            "Security/account-related keywords: "
            + ", ".join(matched_keywords)
        )

    if re.search(r"\d{5,}", hostname):
        result["score"] += 10
        result["indicators"].append("Hostname contains a long numeric sequence")

    result["score"] = min(result["score"], 100)

    if result["score"] >= 60:
        result["risk"] = "HIGH"
        result["recommendation"] = (
            "Treat this URL as potentially malicious. "
            "Do not enter credentials or payment information."
        )
    elif result["score"] >= 30:
        result["risk"] = "MEDIUM"
        result["recommendation"] = (
            "Use caution. Verify the domain independently before continuing."
        )

    return result


def format_result(result: dict) -> str:
    """Convert an analysis result into a readable security report."""
    lines = [
        "PHISHING URL ANALYSIS",
        f"URL: {result['url']}",
        f"Risk: {result['risk']}",
        f"Risk Score: {result['score']}/100",
    ]

    if result["indicators"]:
        lines.append("Indicators:")
        for indicator in result["indicators"]:
            lines.append(f"- {indicator}")
    else:
        lines.append("Indicators: None detected")

    lines.append(f"Recommendation: {result['recommendation']}")
    return "\n".join(lines)


if __name__ == "__main__":
    test_url = input("Enter URL to analyze: ").strip()
    print()
    print(format_result(analyze_url(test_url)))
