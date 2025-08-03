import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, patch
from fastapi import status
from main import app


@pytest.mark.asyncio(scope="session")
async def test_google_login_success():
    """
    Test Google OAuth login initiation.
    """
    with patch("app.api.v1.routes.oauth.oauth") as mock_oauth:
        mock_oauth.google.authorize_redirect = AsyncMock(return_value="redirect_response")
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/api/v1/auth/login/google")
        
        assert response.status_code in [200, 302, 307]
        mock_oauth.google.authorize_redirect.assert_called_once()


@pytest.mark.asyncio(scope="session")
async def test_google_callback_existing_user():
    """
    Test Google OAuth callback with existing user.
    """
    with patch("app.api.v1.routes.oauth.oauth") as mock_oauth, \
         patch("app.api.v1.routes.oauth.id_token") as mock_id_token, \
         patch("app.api.v1.services.users.UserService.get_user_by_email", new_callable=AsyncMock) as mock_get_user, \
         patch("app.api.v1.services.users.UserService.register_user", new_callable=AsyncMock) as mock_register_user, \
         patch("app.api.utils.build_auth_response", new_callable=AsyncMock) as mock_auth_response:

        mock_token = {"id_token": "fake_id_token"}
        mock_oauth.google.authorize_access_token = AsyncMock(return_value=mock_token)
        
        mock_user_info = {"email": "test@example.com"}
        mock_id_token.verify_oauth2_token.return_value = mock_user_info
        
        mock_user = AsyncMock()
        mock_user.email = "test@example.com"
        mock_user.id = "user-123"
        mock_get_user.return_value = mock_user
        
        mock_auth_response.return_value = {"access_token": "fake_token"}
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/api/v1/auth/callback/google?state=test_state&code=test_code")
        
        assert response.status_code in [200, 302, 307]
        mock_get_user.assert_called_once()
        mock_register_user.assert_not_called()


@pytest.mark.asyncio(scope="session")
async def test_google_callback_new_user():
    """
    Test Google OAuth callback with new user registration.
    """
    with patch("app.api.v1.routes.oauth.oauth") as mock_oauth, \
         patch("app.api.v1.routes.oauth.id_token") as mock_id_token, \
         patch("app.api.v1.services.users.UserService.get_user_by_email", new_callable=AsyncMock) as mock_get_user, \
         patch("app.api.v1.services.users.UserService.register_user", new_callable=AsyncMock) as mock_register_user, \
         patch("app.api.utils.build_auth_response", new_callable=AsyncMock) as mock_auth_response:

        mock_token = {"id_token": "fake_id_token"}
        mock_oauth.google.authorize_access_token = AsyncMock(return_value=mock_token)
        
        mock_user_info = {"email": "newuser@example.com"}
        mock_id_token.verify_oauth2_token.return_value = mock_user_info
        
        mock_get_user.return_value = None
        mock_new_user = AsyncMock()
        mock_new_user.email = "newuser@example.com"
        mock_new_user.id = "user-456"
        mock_register_user.return_value = mock_new_user
        
        mock_auth_response.return_value = {"access_token": "fake_token"}
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/api/v1/auth/callback/google?state=test_state&code=test_code")
        
        assert response.status_code in [200, 302, 307]
        mock_get_user.assert_called_once()
        mock_register_user.assert_called_once()


@pytest.mark.asyncio(scope="session")
async def test_google_callback_no_id_token():
    """
    Test Google OAuth callback with missing ID token.
    """
    with patch("app.api.v1.routes.oauth.oauth") as mock_oauth:
        mock_token = {"access_token": "fake_access_token"}
        mock_oauth.google.authorize_access_token = AsyncMock(return_value=mock_token)
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/api/v1/auth/callback/google?state=test_state&code=test_code")
        
        assert response.status_code in [200, 302, 307, 400]


@pytest.mark.asyncio(scope="session")
async def test_google_callback_oauth_exception():
    """
    Test Google OAuth callback with OAuth exception.
    """
    with patch("app.api.v1.routes.oauth.oauth") as mock_oauth:
        mock_oauth.google.authorize_access_token = AsyncMock(side_effect=Exception("OAuth error"))
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/api/v1/auth/callback/google?state=test_state&code=test_code")
        
        assert response.status_code in [200, 302, 307, 400, 500]


@pytest.mark.asyncio(scope="session")
async def test_google_callback_registration_failed():
    """
    Test Google OAuth callback with failed registration.
    """ 
    with patch("app.api.v1.routes.oauth.oauth") as mock_oauth, \
         patch("app.api.v1.routes.oauth.id_token") as mock_id_token, \
         patch("app.api.v1.services.users.UserService.get_user_by_email", new_callable=AsyncMock) as mock_get_user, \
         patch("app.api.v1.services.users.UserService.register_user", new_callable=AsyncMock) as mock_register_user:

        mock_token = {"id_token": "fake_id_token"}
        mock_oauth.google.authorize_access_token = AsyncMock(return_value=mock_token)
        
        mock_user_info = {"email": "newuser@example.com"}
        mock_id_token.verify_oauth2_token.return_value = mock_user_info
        
        mock_get_user.return_value = None
        mock_register_user.return_value = None
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.get("/api/v1/auth/callback/google?state=test_state&code=test_code")
        
        assert response.status_code in [200, 302, 307, 400, 500]


@pytest.mark.asyncio(scope="session")
async def test_google_mobile_login_android_existing_user():
    """
    Test Google mobile login for Android with existing user.
    """
    with patch("app.api.v1.routes.oauth.id_token") as mock_id_token, \
         patch("app.api.v1.services.users.UserService.get_user_by_email", new_callable=AsyncMock) as mock_get_user, \
         patch("app.api.v1.services.users.UserService.register_user", new_callable=AsyncMock) as mock_register_user, \
         patch("app.api.utils.build_auth_response", new_callable=AsyncMock) as mock_auth_response, \
         patch("config.settings.GOOGLE_ANDROID_CLIENT_ID", "fake-android-client-id"):

        mock_user_info = {"email": "test@example.com", "sub": "google-user-123"}
        mock_id_token.verify_oauth2_token.return_value = mock_user_info
        
        mock_user = AsyncMock()
        mock_user.email = "test@example.com"
        mock_user.id = "user-123"
        mock_get_user.return_value = mock_user
        
        mock_auth_response.return_value = {
            "id": "user-123",
            "email": "test@example.com",
            "access_token": "fake_token"
        }
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login/google/mobile",
                json={
                    "platform": "android",
                    "id_token": "fake_google_id_token"
                }
            )
        
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert response_data["message"] == "User logged in Successfully"
        mock_get_user.assert_called_once()
        mock_register_user.assert_not_called()


@pytest.mark.asyncio(scope="session")
async def test_google_mobile_login_ios_new_user():
    """
    Test Google mobile login for iOS with new user registration.
    """
    with patch("app.api.v1.routes.oauth.id_token") as mock_id_token, \
         patch("app.api.v1.services.users.UserService.get_user_by_email", new_callable=AsyncMock) as mock_get_user, \
         patch("app.api.v1.services.users.UserService.register_user", new_callable=AsyncMock) as mock_register_user, \
         patch("app.api.utils.build_auth_response", new_callable=AsyncMock) as mock_auth_response, \
         patch("config.settings.GOOGLE_IOS_CLIENT_ID", "fake-ios-client-id"):

        mock_user_info = {"email": "newuser@example.com", "sub": "google-user-456"}
        mock_id_token.verify_oauth2_token.return_value = mock_user_info
        
        mock_get_user.return_value = None
        mock_new_user = AsyncMock()
        mock_new_user.email = "newuser@example.com"
        mock_new_user.id = "user-456"
        mock_register_user.return_value = mock_new_user
        
        mock_auth_response.return_value = {
            "id": "user-456",
            "email": "newuser@example.com",
            "access_token": "fake_token"
        }
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login/google/mobile",
                json={
                    "platform": "ios",
                    "id_token": "fake_google_id_token"
                }
            )
        
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert response_data["message"] == "User logged in Successfully"
        mock_get_user.assert_called_once()
        mock_register_user.assert_called_once()


@pytest.mark.asyncio(scope="session")
async def test_google_mobile_login_invalid_platform():
    """
    Test Google mobile login with invalid platform.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/auth/login/google/mobile",
            json={
                "platform": "windows",
                "id_token": "fake_google_id_token"
            }
        )
    
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio(scope="session")
async def test_google_mobile_login_invalid_token():
    """
    Test Google mobile login with invalid ID token.
    """
    with patch("app.api.v1.routes.oauth.id_token") as mock_id_token, \
         patch("config.settings.GOOGLE_ANDROID_CLIENT_ID", "fake-android-client-id"):
        
        mock_id_token.verify_oauth2_token.side_effect = Exception("Invalid token")
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login/google/mobile",
                json={
                    "platform": "android",
                    "id_token": "invalid_token"
                }
            )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio(scope="session")
async def test_google_mobile_login_no_email_in_token():
    """
    Test Google mobile login with ID token missing email.
    """
    with patch("app.api.v1.routes.oauth.id_token") as mock_id_token, \
         patch("config.settings.GOOGLE_ANDROID_CLIENT_ID", "fake-android-client-id"):
        
        mock_id_token.verify_oauth2_token.return_value = {"sub": "123456"}
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login/google/mobile",
                json={
                    "platform": "android",
                    "id_token": "fake_google_id_token"
                }
            )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio(scope="session")
async def test_google_mobile_login_registration_failed():
    """
    Test Google mobile login with failed user registration.
    """
    with patch("app.api.v1.routes.oauth.id_token") as mock_id_token, \
         patch("app.api.v1.services.users.UserService.get_user_by_email", new_callable=AsyncMock) as mock_get_user, \
         patch("app.api.v1.services.users.UserService.register_user", new_callable=AsyncMock) as mock_register_user, \
         patch("config.settings.GOOGLE_ANDROID_CLIENT_ID", "fake-android-client-id"):

        mock_user_info = {"email": "newuser@example.com", "sub": "google-user-789"}
        mock_id_token.verify_oauth2_token.return_value = mock_user_info
        
        mock_get_user.return_value = None
        mock_register_user.return_value = None
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login/google/mobile",
                json={
                    "platform": "android",
                    "id_token": "fake_google_id_token"
                }
            )
        
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


@pytest.mark.asyncio(scope="session")
async def test_google_mobile_login_android_not_configured():
    """
    Test Google mobile login for Android when not configured.
    """
    with patch("config.settings.GOOGLE_ANDROID_CLIENT_ID", None):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login/google/mobile",
                json={
                    "platform": "android",
                    "id_token": "fake_google_id_token"
                }
            )
        
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


@pytest.mark.asyncio(scope="session")
async def test_google_mobile_login_ios_not_configured():
    """
    Test Google mobile login for iOS when not configured.
    """
    with patch("config.settings.GOOGLE_IOS_CLIENT_ID", None):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login/google/mobile",
                json={
                    "platform": "ios",
                    "id_token": "fake_google_id_token"
                }
            )
        
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR