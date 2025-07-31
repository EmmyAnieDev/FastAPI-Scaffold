def test_read_root(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "--- Application API is running"

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_docs_route_available(client):
    response = client.get("/docs")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

def test_redoc_route_available(client):
    response = client.get("/redoc")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
