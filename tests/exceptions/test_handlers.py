import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from httpx import ASGITransport
from app.api.exceptions.handlers import create_exception_handler

@pytest.mark.asyncio
async def test_create_exception_handler_returns_expected_response():

    app = FastAPI()

    @app.get("/raise-error")
    async def raise_error():
        raise ValueError("Something went wrong")

    app.add_exception_handler(ValueError, create_exception_handler(400, "Custom error occurred"))

    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/raise-error")

    assert response.status_code == 400
    assert response.json() == {
        "status_code": 400,
        "success": False,
        "message": "Custom error occurred",
        "data": None
    }
