from threat_intelligence import identify_indicator, enrich_indicator


def test_identifies_ip():
    result = identify_indicator("8.8.8.8")
    assert result["type"] == "ip"
    assert result["normalized"] == "8.8.8.8"


def test_identifies_url():
    result = identify_indicator("https://example.com/login")
    assert result["type"] == "url"
    assert result["host"] == "example.com"


def test_identifies_sha256():
    value = "a" * 64
    result = identify_indicator(value)
    assert result["type"] == "hash"
    assert result["hash_type"] == "SHA-256"


def test_identifies_domain():
    result = identify_indicator("example.com")
    assert result["type"] == "domain"
    assert result["normalized"] == "example.com"


def test_unknown_indicator():
    result = identify_indicator("not-an-indicator")
    assert result["type"] == "unknown"


def test_enrichment_is_offline_safe():
    result = enrich_indicator("8.8.8.8")
    assert result["type"] == "ip"
    assert result["enrichment"]["status"] == "not_configured"
    assert result["enrichment"]["providers"] == []
    assert result["enrichment"]["results"] == []
