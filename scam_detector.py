import re


SCAM_KEYWORDS = {
    "urgent": 10,
    "immediately": 10,
    "verify": 8,
    "verification": 8,
    "otp": 15,
    "one time password": 15,
    "password": 12,
    "pin": 12,
    "bank": 10,
    "account": 8,
    "payment": 10,
    "refund": 10,
    "prize": 15,
    "winner": 15,
    "lottery": 15,
    "gift card": 15,
    "investment": 12,
    "guaranteed profit": 20,
    "crypto": 10,
    "bitcoin": 10,
    "send money": 15,
    "wire transfer": 15,
    "click here": 10,
    "act now": 10,
}


def analyze_scam(text: str) -> dict:
    """Perform a local, non-networked scam-risk analysis of text."""

    text = (text or "").strip()

    result = {
        "text": text,
        "risk": "LOW",
        "score": 0,
        "indicators": [],
        "recommendation": "No strong scam indicators detected.",
    }

    if not text:
        result["risk"] = "UNKNOWN"
        result["recommendation"] = "Provide a message or text to analyze."
        return result

    lowered = text.lower()

    matched_keywords = []

    for keyword, points in SCAM_KEYWORDS.items():
        if keyword in lowered:
            matched_keywords.append(keyword)
            result["score"] += points

    if matched_keywords:
        result["indicators"].append(
            "Scam-related keywords: " + ", ".join(matched_keywords)
        )

    # Detect requests for sensitive information.
    sensitive_patterns = [
        r"\b(send|share|give|provide)\b.{0,40}\b(otp|password|pin|cvv)\b",
        r"\b(otp|password|pin|cvv)\b.{0,40}\b(send|share|give|provide)\b",
    ]

    if any(re.search(pattern, lowered) for pattern in sensitive_patterns):
        result["score"] += 25
        result["indicators"].append(
            "Request for sensitive authentication or payment information"
        )

    # Detect suspicious links.
    if re.search(r"https?://\S+", lowered):
        result["score"] += 10
        result["indicators"].append("Message contains a clickable URL")

    # Detect pressure tactics.
    urgency_patterns = [
        r"\bact now\b",
        r"\bwithin \d+ (minutes?|hours?)\b",
        r"\blast warning\b",
        r"\baccount.{0,20}\b(suspended|blocked|closed)\b",
    ]

    if any(re.search(pattern, lowered) for pattern in urgency_patterns):
        result["score"] += 15
        result["indicators"].append("Urgency or pressure tactic detected")

    # Detect excessive monetary promises.
    if re.search(
        r"\b(guaranteed|guarantee|risk[- ]free)\b.{0,50}"
        r"\b(profit|income|return|money)\b",
        lowered,
    ):
        result["score"] += 20
        result["indicators"].append(
            "Potentially unrealistic financial promise"
        )

    result["score"] = min(result["score"], 100)

    if result["score"] >= 60:
        result["risk"] = "HIGH"
        result["recommendation"] = (
            "Treat this message as potentially fraudulent. "
            "Do not send money, passwords, OTPs, or payment information."
        )
    elif result["score"] >= 30:
        result["risk"] = "MEDIUM"
        result["recommendation"] = (
            "Use caution. Verify the sender independently before "
            "clicking links or sharing information."
        )

    return result


def format_scam_result(result: dict) -> str:
    """Convert a scam analysis result into a readable security report."""

    lines = [
        "SCAM MESSAGE ANALYSIS",
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
    test_message = input("Enter message to analyze: ").strip()
    result = analyze_scam(test_message)
    print()
    print(format_scam_result(result))
