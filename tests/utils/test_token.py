import pytest
from datetime import timedelta
import jwt

from app.api.utils.token import (
    generate_password_hash,
    verify_password,
    create_access_token,
    decode_token,
)
from config import settings

""" Dummy user payload for token generation """
user_data = {"id": 1, "email": "user@example.com"}

def test_generate_and_verify_password():
    plain_password = "securePassword123"
    hashed = generate_password_hash(plain_password)

    assert hashed != plain_password
    assert verify_password(plain_password, hashed) is True
    assert verify_password("wrongPassword", hashed) is False

@pytest.mark.asyncio
async def test_create_access_token_and_decode():
    token = await create_access_token(user_data)

    decoded = decode_token(token)

    assert isinstance(decoded, dict)
    assert "user" in decoded
    assert decoded["user"] == user_data
    assert "exp" in decoded
    assert decoded["refresh"] is False
    assert "jti" in decoded

@pytest.mark.asyncio
async def test_create_refresh_token():
    token = await create_access_token(user_data, refresh=True)
    decoded = decode_token(token)
    assert decoded["refresh"] is True

@pytest.mark.asyncio
async def test_token_expiry_custom_timedelta():
    token = await create_access_token(user_data, expiry=timedelta(seconds=5))
    decoded = decode_token(token)
    assert decoded["user"] == user_data

def test_decode_token_invalid():
    invalid_token = "this.is.not.valid.jwt"
    decoded = decode_token(invalid_token)
    assert decoded == {}
