"""
Observability middleware tests.
"""


def test_request_headers(client):
    response = client.get("/api/v1/health")

    assert "X-Request-ID" in response.headers
    assert "X-Correlation-ID" in response.headers