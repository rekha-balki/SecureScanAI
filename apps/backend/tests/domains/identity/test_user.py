from app.domains.identity.domain.aggregates.user import User


def test_create_user():
    user = User(
        id="1",
        username="admin",
        email="admin@example.com",
        password_hash="hash",
    )

    assert user.username == "admin"
    assert user.is_active is True
    assert user.created_at is not None