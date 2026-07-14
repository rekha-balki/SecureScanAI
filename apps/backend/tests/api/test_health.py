"""
Health endpoint tests.
"""


def test_health_endpoint(client):
    # Arrange

    # Act
    response = client.get("/api/v1/health")

    # Assert
    assert response.status_code == 200

    body = response.json()

    assert "success" in body
    assert "message" in body
    assert "data" in body
    assert "timestamp" in body

    assert body["success"] is True