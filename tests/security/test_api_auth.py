from web_app import app


PROTECTED_ENDPOINTS = [
    ("/api/phishing", {"url": "https://example.com"}),
    ("/api/security-intelligence", {"input": "8.8.8.8"}),
    ("/api/threat-correlation", {"input": "Hello, how are you?"}),
    ("/api/unified-threat", {"input": "https://example.com"}),
]


def test_all_protected_endpoints_require_login():
    client = app.test_client()

    for path, payload in PROTECTED_ENDPOINTS:
        response = client.post(path, json=payload)

        assert response.status_code == 302, (
            f"{path} returned {response.status_code}, expected 302"
        )

        assert "/login" in response.headers.get("Location", "")


def test_login_page_is_reachable():
    client = app.test_client()

    response = client.get("/login")

    assert response.status_code == 200


def test_user_password_hashing():
    from auth import User

    user = User(username="coverage_user")
    user.set_password("TestPassword123!")

    assert user.password_hash
    assert user.check_password("TestPassword123!")
    assert not user.check_password("WrongPassword!")
