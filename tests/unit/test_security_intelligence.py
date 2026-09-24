from security_intelligence import analyze_indicator


def test_public_ip_returns_analysis():
    result = analyze_indicator("8.8.8.8")

    assert isinstance(result, dict)
    assert result["type"] == "ip"
    assert "risk" in result
    assert "score" in result
    assert "indicators" in result
    assert "recommendation" in result


def test_invalid_input_returns_safe_result():
    result = analyze_indicator("not-a-valid-indicator")

    assert isinstance(result, dict)
    assert "risk" in result
    assert "score" in result
    assert "indicators" in result
    assert "recommendation" in result
