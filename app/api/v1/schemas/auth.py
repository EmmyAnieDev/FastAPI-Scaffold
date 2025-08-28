from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional, Literal


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: Optional[str] = Field(default=None, min_length=8)
    provider: Optional[Literal["email", "google"]] = "email"


class UserLogin(UserBase):
    password: str
    

class GoogleMobileLoginRequest(BaseModel):
    id_token: str
    platform: Literal["android", "ios"]


### Rsponse Schemas ###

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