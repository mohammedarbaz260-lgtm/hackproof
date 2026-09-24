from security_analysis import (
    analyze_ip,
    analyze_text,
    analyze_domain,
    analyze_subdomain,
    analyze_url,
    analyze_port,
    analyze_log,
    analyze_threat,
)


def test_analyze_ip_invalid():
    result = analyze_ip("not-an-ip")
    assert result == "Invalid IP address."


def test_analyze_ip_private():
    result = analyze_ip("192.168.1.10")
    assert "Private IP address" in result


def test_analyze_ip_loopback():
    result = analyze_ip("127.0.0.1")
    assert "Loopback IP address" in result


def test_analyze_ip_public():
    result = analyze_ip("8.8.8.8")
    assert "Public IP address" in result


def test_analyze_text_without_direct_ip_analysis():
    result = analyze_text("Check 8.8.8.8")
    assert result == "No IP address detected."


def test_analyze_text_without_ip():
    result = analyze_text("hello world")
    assert result == "No IP address detected."


def test_analyze_domain_valid():
    result = analyze_domain("example.com")
    assert "Domain Analysis: example.com" in result


def test_analyze_domain_invalid():
    result = analyze_domain("example")
    assert result == "Invalid domain format."


def test_analyze_domain_rejects_path():
    result = analyze_domain("example.com/path")
    assert result == "Invalid domain format."


def test_analyze_subdomain_valid():
    result = analyze_subdomain("login.example.com")
    assert "Subdomain Analysis: login.example.com" in result


def test_analyze_subdomain_invalid():
    result = analyze_subdomain("example")
    assert result == "Invalid subdomain format."


def test_analyze_url_valid():
    result = analyze_url("https://example.com")
    assert "URL Analysis: https://example.com" in result


def test_analyze_url_invalid():
    result = analyze_url("example.com")
    assert result == "Invalid URL. URL should start with http:// or https://."


def test_analyze_port_known():
    result = analyze_port("443")
    assert "Port Analysis: 443" in result
    assert "HTTPS" in result


def test_analyze_port_invalid():
    result = analyze_port("abc")
    assert result == "Invalid port number."


def test_analyze_port_out_of_range():
    result = analyze_port("70000")
    assert result == "Port must be between 1 and 65535."


def test_analyze_port_custom():
    result = analyze_port("9999")
    assert "Unknown / Custom Service" in result


def test_analyze_log_clean():
    result = analyze_log("User logged in successfully")
    assert "No obvious suspicious indicator detected" in result


def test_analyze_log_suspicious():
    result = analyze_log("authentication failure and permission denied")
    assert "SUSPICIOUS" in result
    assert "authentication failure" in result
    assert "permission denied" in result


def test_analyze_threat_clean():
    result = analyze_threat("normal system activity")
    assert "No obvious threat indicator detected" in result


def test_analyze_threat_malware():
    result = analyze_threat("possible malware detected")
    assert "SUSPICIOUS" in result
    assert "malware" in result


def test_analyze_threat_multiple_indicators():
    result = analyze_threat(
        "malware ransomware phishing credential theft powershell"
    )
    assert "SUSPICIOUS" in result
    assert "malware" in result
    assert "ransomware" in result
    assert "phishing" in result
