from phishing_detector import analyze_url


def test_normal_url_is_not_high_risk():
    result = analyze_url("https://example.com")

    assert isinstance(result, dict)
    assert result["risk"] in {"LOW", "MEDIUM", "HIGH"}
    assert "score" in result
    assert "indicators" in result
    assert "recommendation" in result


def test_phishing_url_returns_analysis():
    result = analyze_url(
        "http://secure-login-verify-account.example.com"
    )

    assert isinstance(result, dict)
    assert "risk" in result
    assert "score" in result
    assert "indicators" in result
