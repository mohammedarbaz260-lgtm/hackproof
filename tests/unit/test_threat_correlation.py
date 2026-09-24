from threat_correlation import (
    _score,
    _severity,
    _collect_indicators,
    correlate_threat,
)


def test_score_handles_invalid_value():
    assert _score("invalid") == 0


def test_score_clamps_value():
    assert _score(-10) == 0
    assert _score(150) == 100
    assert _score(50) == 50


def test_severity_boundaries():
    assert _severity(80) == "CRITICAL"
    assert _severity(60) == "HIGH"
    assert _severity(30) == "MEDIUM"
    assert _severity(29) == "LOW"


def test_collect_indicators_requires_list():
    assert _collect_indicators({"indicators": "not-a-list"}) == []


def test_empty_input_returns_safe_result():
    result = correlate_threat("")
    assert result["type"] == "unknown"
    assert result["risk"] == "UNKNOWN"
    assert result["score"] == 0
    assert result["signals"] == []
    assert result["indicators"] == []


def test_auto_detects_url():
    result = correlate_threat("https://example.com")
    assert result["type"] == "url"
    assert "signals" in result
    assert "indicators" in result
    assert "score" in result


def test_explicit_indicator_analysis():
    result = correlate_threat("8.8.8.8", input_type="indicator")
    assert result["type"] == "ip"
    assert result["score"] >= 0
    assert "signals" in result
    assert "indicators" in result
    assert "recommendation" in result


def test_explicit_message_analysis():
    result = correlate_threat(
        "Urgent! Your account will be suspended. Verify your account immediately.",
        input_type="message",
    )
    assert result["type"] == "message"
    assert result["score"] >= 0
    assert "scam_detector" in [s["engine"] for s in result["signals"]]


def test_explicit_url_analysis():
    result = correlate_threat(
        "https://example.com",
        input_type="url",
    )
    assert result["type"] == "url"
    assert len(result["signals"]) == 2


def test_unsupported_input_type_returns_safe_result():
    result = correlate_threat(
        "something",
        input_type="unsupported",
    )
    assert result["type"] == "unknown"
    assert result["risk"] == "UNKNOWN"
    assert result["score"] == 0
    assert result["signals"] == []
    assert result["indicators"] == []
    assert "Supported types" in result["recommendation"]


def test_auto_detection_treats_normal_text_as_message():
    result = correlate_threat("Hello, how are you?")
    assert result["type"] == "message"
    assert "scam_detector" in [s["engine"] for s in result["signals"]]

def test_url_correlation_combines_strong_signals():
    result = correlate_threat(
        "https://secure-login-verify-account.example.com",
        input_type="url",
    )

    assert result["type"] == "url"
    assert result["score"] == 30
    assert len(result["signals"]) >= 2
    assert "phishing_detector" in [s["engine"] for s in result["signals"]]
    assert "security_intelligence" in [s["engine"] for s in result["signals"]]
    assert result["recommendation"]
