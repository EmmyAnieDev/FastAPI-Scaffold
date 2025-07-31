class CustomException(Exception):
    """Base class for all custom application exceptions."""
    pass

class InvalidToken(CustomException):
    """Raised when a provided token is invalid or expired."""
    pass

class InvalidTokenPayload(CustomException):
    """Raised when a required field is missing from the token payload (e.g., email)."""
    pass

class InvalidCredentials(CustomException):
    """Raised when email or password provided is incorrect."""
    pass

class UserAlreadyExists(CustomException):
    """Raised when trying to register an already existing user."""
    pass

class Unauthorized(CustomException):
    """Raised when the user is not authorized to perform the action."""
    pass

class InsufficientPermission(CustomException):
    """Raised when the user lacks the required role or access level."""
    pass

class UserNotFound(CustomException):
    """Raised when a user cannot be found in the system."""
    pass

class MethodNotAllowed(CustomException):
    """Raised when a disallowed HTTP method is used."""
    pass

class BadRequest(CustomException):
    """Raised for general bad requests."""
    pass

class AccessTokenRequired(CustomException):
    """Raised when an access token is required but not provided."""
    pass

class RefreshTokenRequired(CustomException):
    """Raised when a refresh token is required but not provided."""
    pass

class RevokedToken(CustomException):
    """Raised when the token has been revoked (e.g., logged out)."""
    pass

class RefreshTokenExpired(CustomException):
    """Raised when the refresh token has expired."""
    pass

class PasswordMismatchError(CustomException):
    """Raised when the password and confirmation password do not match."""
    pass

class RegistrationInitiationFailed(CustomException):
    """Raised when the user registration initiation process fails."""
    pass

class UserDeletionFailed(CustomException):
    """Raised when a user could not be deleted due to a database or logic error."""
    pass