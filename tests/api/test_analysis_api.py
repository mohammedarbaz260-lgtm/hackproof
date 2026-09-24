from web_app import app, db, User


def test_protected_api_requires_login():
    client = app.test_client()

    with app.app_context():
        response = client.post(
            "/api/unified-threat",
            json={"input": "https://example.com"},
        )

    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


def test_phishing_api_works_for_authenticated_user():
    client = app.test_client()

    with app.app_context():
        user = User.query.first()

        assert user is not None

        with client.session_transaction() as session:
            session["_user_id"] = str(user.id)
            session["_fresh"] = True

        response = client.post(
            "/api/phishing",
            json={"url": "https://example.com"},
        )

    assert response.status_code == 200

    data = response.get_json()
    assert isinstance(data, dict)
    assert data["url"] == "https://example.com"
    assert "risk" in data
    assert "score" in data
