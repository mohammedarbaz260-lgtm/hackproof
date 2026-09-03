from typing import Any, Dict

from phishing_detector import analyze_url
from scam_detector import analyze_scam


def analyze_input(text: str, input_type: str = "auto") -> Dict[str, Any]:
    """
    Unified local threat analyzer.

    Supported input types:
        auto
        url
        message
    """

    text = (text or "").strip()
    input_type = (input_type or "auto").lower().strip()

    if not text:
        return {
            "input": "",
            "type": "unknown",
            "risk": "UNKNOWN",
            "score": 0,
            "indicators": [],
            "recommendation": "Provide something to analyze.",
            "sources": [],
        }

    # Automatic URL detection
    if input_type == "auto":
        lowered = text.lower()

        if (
            lowered.startswith("http://")
            or lowered.startswith("https://")
            or lowered.startswith("www.")
        ):
            input_type = "url"
        else:
            input_type = "message"

    if input_type == "url":
        result = analyze_url(text)

        return {
            "input": text,
            "type": "url",
            "risk": result.get("risk", "UNKNOWN"),
            "score": result.get("score", 0),
            "indicators": result.get("indicators", []),
            "recommendation": result.get(
                "recommendation",
                "Review the URL carefully."
            ),
            "sources": ["phishing_detector"],
        }

    if input_type == "message":
        result = analyze_scam(text)

        return {
            "input": text,
            "type": "message",
            "risk": result.get("risk", "UNKNOWN"),
            "score": result.get("score", 0),
            "indicators": result.get("indicators", []),
            "recommendation": result.get(
                "recommendation",
                "Review the message carefully."
            ),
            "sources": ["scam_detector"],
        }

    return {
        "input": text,
        "type": "unknown",
        "risk": "UNKNOWN",
        "score": 0,
        "indicators": [f"Unsupported input type: {input_type}"],
        "recommendation": "Use auto, url, or message.",
        "sources": [],
    }


def format_unified_result(result: Dict[str, Any]) -> str:
    """Convert a unified analysis result into a readable security report."""

    lines = [
        "HACKPROOF UNIFIED THREAT ANALYSIS",
        f"Input Type: {result.get('type', 'UNKNOWN')}",
        f"Input: {result.get('input', '')}",
        f"Risk: {result.get('risk', 'UNKNOWN')}",
        f"Threat Score: {result.get('score', 0)}/100",
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

    sources = result.get("sources", [])
    if sources:
        lines.append(
            "Detection Engines: " + ", ".join(sources)
        )

    return "\n".join(lines)


if __name__ == "__main__":
    print("HackProof Unified Threat Analyzer")
    print("---------------------------------")

    user_input = input("Enter URL or message: ").strip()

    result = analyze_input(user_input)

    print()
    print(format_unified_result(result))
