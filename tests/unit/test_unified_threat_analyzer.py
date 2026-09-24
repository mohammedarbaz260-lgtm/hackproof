from unified_threat_analyzer import analyze_input


def test_url_input_returns_unified_analysis():
    result = analyze_input(
        "https://example.com",
        input_type="url",
    )

    assert isinstance(result, dict)
    assert result["type"] == "url"
    assert "risk" in result
    assert "score" in result
    assert "indicators" in result
    assert "recommendation" in result
    assert "sources" in result


def test_message_input_returns_unified_analysis():
    result = analyze_input(
        "Urgent! Your account will be suspended. Verify your account immediately.",
        input_type="message",
    )

    assert isinstance(result, dict)
    assert result["type"] == "message"
    assert "risk" in result
    assert "score" in result
    assert "indicators" in result
    assert "recommendation" in result
    assert "sources" in result
