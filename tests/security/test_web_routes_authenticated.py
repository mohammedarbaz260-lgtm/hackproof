from web_app import app
from auth import User, db


TEST_USERNAME = "test_auth_user"
TEST_PASSWORD = "TestPassword123!"


def create_test_user():
    with app.app_context():
        user = User.query.filter_by(username=TEST_USERNAME).first()

        if user is None:
            user = User(username=TEST_USERNAME)
            user.set_password(TEST_PASSWORD)
            db.session.add(user)
            db.session.commit()


def login_test_user(client):
    response = client.post(
        "/login",
        data={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert b"Login successful" in response.data


def test_authenticated_user_can_reach_dashboard():
    create_test_user()

    client = app.test_client()
    login_test_user(client)

    response = client.get("/dashboard")

    assert response.status_code == 200


def test_authenticated_user_can_reach_analysis_page():
    create_test_user()

    client = app.test_client()
    login_test_user(client)

    response = client.get("/analysis")

    assert response.status_code == 200
