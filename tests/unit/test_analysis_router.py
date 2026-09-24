import analysis_router


def test_analyze_ip(monkeypatch):
    monkeypatch.setattr(
        analysis_router,
        "analyze_ip",
        lambda value: {"type": "ip", "input": value},
    )

    result = analysis_router.handle_analysis_request("analyze ip 8.8.8.8")

    assert result == {"type": "ip", "input": "8.8.8.8"}


def test_analyze_domain(monkeypatch):
    monkeypatch.setattr(
        analysis_router,
        "analyze_domain",
        lambda value: {"type": "domain", "input": value},
    )

    result = analysis_router.handle_analysis_request("analyze domain example.com")

    assert result == {"type": "domain", "input": "example.com"}


def test_analyze_subdomain(monkeypatch):
    monkeypatch.setattr(
        analysis_router,
        "analyze_subdomain",
        lambda value: {"type": "subdomain", "input": value},
    )

    result = analysis_router.handle_analysis_request(
        "analyze subdomain mail.example.com"
    )

    assert result == {
        "type": "subdomain",
        "input": "mail.example.com",
    }


def test_analyze_url(monkeypatch):
    monkeypatch.setattr(
        analysis_router,
        "analyze_url",
        lambda value: {"type": "url", "input": value},
    )

    result = analysis_router.handle_analysis_request(
        "analyze url https://example.com"
    )

    assert result == {
        "type": "url",
        "input": "https://example.com",
    }


def test_analyze_port(monkeypatch):
    monkeypatch.setattr(
        analysis_router,
        "analyze_port",
        lambda value: {"type": "port", "input": value},
    )

    result = analysis_router.handle_analysis_request("analyze port 443")

    assert result == {"type": "port", "input": "443"}


def test_analyze_threat(monkeypatch):
    monkeypatch.setattr(
        analysis_router,
        "analyze_threat",
        lambda value: {"type": "threat", "input": value},
    )

    result = analysis_router.handle_analysis_request(
        "analyze threat phishing attack"
    )

    assert result == {
        "type": "threat",
        "input": "phishing attack",
    }


def test_analyze_log(monkeypatch):
    monkeypatch.setattr(
        analysis_router,
        "analyze_log",
        lambda value: {"type": "log", "input": value},
    )

    result = analysis_router.handle_analysis_request(
        "analyze log failed login detected"
    )

    assert result == {
        "type": "log",
        "input": "failed login detected",
    }


def test_unsupported_request_returns_none():
    result = analysis_router.handle_analysis_request("hello hackproof")

    assert result is None


def test_request_is_trimmed():
    result = analysis_router.handle_analysis_request(
        "   hello hackproof   "
    )

    assert result is None
