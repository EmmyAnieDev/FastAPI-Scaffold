from pydantic import BaseModel, EmailStr, Field, validator
from datetime import datetime
from typing import Optional, Literal

from app.api.exceptions.exceptions import PasswordMismatchError


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: Optional[str] = Field(default=None, min_length=8)
    confirm_password: Optional[str] = Field(default=None, min_length=8)
    provider: Optional[Literal["email", "google"]] = "email"

    @validator("confirm_password")
    def passwords_match(cls, v, values):
        if "password" in values and v != values["password"]:
            raise PasswordMismatchError()
        return v


class UserLogin(UserBase):
    password: str
    

class GoogleMobileLoginRequest(BaseModel):
    id_token: str
    platform: Literal["android", "ios"]


class ResetPasswordRequest(BaseModel):
    email: EmailStr


class VerifyResetOtpSchema(BaseModel):
    verification_token: str
    otp: str
    

class ConfirmResetPasswordSchema(BaseModel):
    verification_token: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)

    @validator("confirm_password")
    def passwords_match(cls, v, values):
        if "new_password" in values and v != values["new_password"]:
            raise PasswordMismatchError()
        return v


### Response Schemas ###

class AuthResponse(UserBase):
    id: str
    created_at: datetime
    access_token: str
    refresh_token: Optional[str] = None

    class Config:
        from_attributes = True


class TokenRefreshResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None


class LogoutResponse(BaseModel):
    pass
