from scam_detector import analyze_scam


def test_normal_message_is_low_risk():
    result = analyze_scam("Hello, how are you today?")

    assert isinstance(result, dict)
    assert "risk" in result
    assert "score" in result
    assert "indicators" in result
    assert "recommendation" in result


def test_scam_message_returns_analysis():
    result = analyze_scam(
        "Urgent! Your account will be suspended. Verify your account immediately."
    )

    assert isinstance(result, dict)
    assert "risk" in result
    assert "score" in result
    assert "indicators" in result
    assert "recommendation" in result
