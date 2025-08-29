import pytest
from app.api.v1.schemas.auth import UserCreate, ConfirmResetPasswordSchema
from app.api.exceptions.exceptions import PasswordMismatchError


def test_usercreate_passwords_match():
    """
    Should succeed when passwords match
    """
    data = {
        "email": "test@example.com",
        "password": "strongpassword",
        "confirm_password": "strongpassword"
    }
    user = UserCreate(**data)
    assert user.password == "strongpassword"
    assert user.confirm_password == "strongpassword"


def test_usercreate_passwords_mismatch():
    """
    Should raise PasswordMismatchError when passwords don't match
    """
    data = {
        "email": "test@example.com",
        "password": "strongpassword",
        "confirm_password": "wrongpassword"
    }
    with pytest.raises(PasswordMismatchError):
        UserCreate(**data)


def test_confirm_reset_password_match():
    """
    Should succeed when passwords match
    """
    data = {
        "reset_token": "sometoken",
        "new_password": "newstrongpassword",
        "confirm_password": "newstrongpassword"
    }
    schema = ConfirmResetPasswordSchema(**data)
    assert schema.new_password == "newstrongpassword"
    assert schema.confirm_password == "newstrongpassword"


def test_confirm_reset_password_mismatch():
    """
    Should raise PasswordMismatchError when passwords don't match
    """
    data = {
        "reset_token": "sometoken",
        "new_password": "newstrongpassword",
        "confirm_password": "wrongpassword"
    }
    with pytest.raises(PasswordMismatchError):
        ConfirmResetPasswordSchema(**data)
