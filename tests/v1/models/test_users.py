import pytest
from app.api.v1.models.users import User

def test_validate_email_valid():
    """
    Should not raise an error
    """
    user = User(email="test@example.com")
    assert user.email == "test@example.com"


def test_validate_email_invalid():
    """
    Should raise an AssertionError
    """
    with pytest.raises(AssertionError) as excinfo:
        User(email="invalidemail")
    assert str(excinfo.value) == "Invalid email format"
