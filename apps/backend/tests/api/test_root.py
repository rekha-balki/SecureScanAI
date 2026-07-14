"""
Root endpoint tests.
"""


def test_root_endpoint(client):
    response = client.get("/api/v1/")

    assert response.status_code == 200  