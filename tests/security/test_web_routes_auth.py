from web_app import app


PROTECTED_ROUTES = [
    ("/dashboard", "GET"),
    ("/analysis", "GET"),
    ("/tools", "GET"),
    ("/reports", "GET"),
    ("/knowledge", "GET"),
    ("/phishing", "GET"),
    ("/scam", "GET"),
    ("/api/phishing", "POST"),
    ("/api/unified-threat", "POST"),
    ("/api/security-intelligence", "POST"),
    ("/api/threat-correlation", "POST"),
]


def test_protected_routes_require_login():
    client = app.test_client()

    for path, method in PROTECTED_ROUTES:
        if method == "GET":
            response = client.get(path)
        else:
            response = client.post(path, json={})

        assert response.status_code in (302, 401), (
            f"{method} {path} returned {response.status_code}; "
            "expected authentication protection"
        )


def test_login_page_is_public():
    client = app.test_client()

    response = client.get("/login")

    assert response.status_code == 200
