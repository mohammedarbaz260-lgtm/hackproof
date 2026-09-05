from typing import Any, Dict, List

from phishing_detector import analyze_url
from scam_detector import analyze_scam
from security_intelligence import analyze_indicator


def _score(value: Any) -> int:
    try:
        return max(0, min(int(value), 100))
    except (TypeError, ValueError):
        return 0


def _severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _collect_indicators(result: Dict[str, Any]) -> List[str]:
    indicators = result.get("indicators", [])

    if not isinstance(indicators, list):
        return []

    return [str(item) for item in indicators if str(item).strip()]


def correlate_threat(text: str, input_type: str = "auto") -> Dict[str, Any]:
    """
    Correlate results from HackProof's existing security analyzers.

    Supported input types:
        auto
        url
        message
        indicator
    """

    text = (text or "").strip()
    input_type = (input_type or "auto").strip().lower()

    if not text:
        return {
            "input": "",
            "type": "unknown",
            "risk": "UNKNOWN",
            "score": 0,
            "signals": [],
            "indicators": [],
            "recommendation": "Provide something to analyze.",
        }

    signals = []
    indicators = []

    # Automatic URL detection
    lowered = text.lower()

    if input_type == "auto":
        if lowered.startswith(("http://", "https://", "www.")):
            input_type = "url"
        else:
            input_type = "message"

    # URL correlation
    if input_type == "url":
        phishing = analyze_url(text)
        intelligence = analyze_indicator(text)

        phishing_score = _score(phishing.get("score", 0))
        intelligence_score = _score(intelligence.get("score", 0))

        signals.append({
            "engine": "phishing_detector",
            "score": phishing_score,
            "risk": phishing.get("risk", "UNKNOWN"),
        })

        signals.append({
            "engine": "security_intelligence",
            "score": intelligence_score,
            "risk": intelligence.get("risk", "UNKNOWN"),
        })

        indicators.extend(_collect_indicators(phishing))
        indicators.extend(_collect_indicators(intelligence))

        # Use the strongest signal rather than blindly adding scores.
        final_score = max(phishing_score, intelligence_score)

        if phishing_score >= 60 and intelligence_score >= 30:
            final_score = min(100, max(phishing_score, intelligence_score) + 10)

        return {
            "input": text,
            "type": "url",
            "risk": _severity(final_score),
            "score": final_score,
            "signals": signals,
            "indicators": list(dict.fromkeys(indicators)),
            "recommendation": (
                "Treat this URL as potentially dangerous and verify the "
                "destination independently before interacting with it."
                if final_score >= 60
                else
                "Review the URL and use authorized reputation checks "
                "before trusting it."
            ),
        }

    # Message/scam correlation
    if input_type == "message":
        scam = analyze_scam(text)

        scam_score = _score(scam.get("score", 0))

        signals.append({
            "engine": "scam_detector",
            "score": scam_score,
            "risk": scam.get("risk", "UNKNOWN"),
        })

        indicators.extend(_collect_indicators(scam))

        return {
            "input": text,
            "type": "message",
            "risk": _severity(scam_score),
            "score": scam_score,
            "signals": signals,
            "indicators": list(dict.fromkeys(indicators)),
            "recommendation": (
                scam.get(
                    "recommendation",
                    "Review the message carefully."
                )
            ),
        }

    # IP/domain/hash intelligence
    if input_type == "indicator":
        intelligence = analyze_indicator(text)

        intelligence_score = _score(intelligence.get("score", 0))

        signals.append({
            "engine": "security_intelligence",
            "score": intelligence_score,
            "risk": intelligence.get("risk", "UNKNOWN"),
        })

        indicators.extend(_collect_indicators(intelligence))

        return {
            "input": text,
            "type": intelligence.get("type", "unknown"),
            "risk": _severity(intelligence_score),
            "score": intelligence_score,
            "signals": signals,
            "indicators": list(dict.fromkeys(indicators)),
            "recommendation": intelligence.get(
                "recommendation",
                "Review the indicator carefully."
            ),
        }

    return {
        "input": text,
        "type": "unknown",
        "risk": "UNKNOWN",
        "score": 0,
        "signals": [],
        "indicators": [],
        "recommendation": (
            "Supported types are auto, url, message, and indicator."
        ),
    }


if __name__ == "__main__":
    print("HackProof Threat Correlation Engine")
    print("-----------------------------------")

    test_input = input("Enter URL, message, or indicator: ").strip()

    result = correlate_threat(test_input)

    print()
    print("THREAT CORRELATION RESULT")
    print(f"Input: {result['input']}")
    print(f"Type: {result['type']}")
    print(f"Risk: {result['risk']}")
    print(f"Score: {result['score']}/100")

    print("Signals:")
    for signal in result["signals"]:
        print(
            f"  - {signal['engine']}: "
            f"{signal['risk']} ({signal['score']}/100)"
        )

    print("Indicators:")
    if result["indicators"]:
        for indicator in result["indicators"]:
            print(f"  - {indicator}")
    else:
        print("  - None")

    print(f"Recommendation: {result['recommendation']}")
