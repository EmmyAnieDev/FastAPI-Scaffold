from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)


class UserLogin(UserBase):
    password: str


### Rsponse Schemas ###

class AuthResponse(UserBase):
    id: str
    created_at: datetime
    access_token: str
    refresh_token: str

    class Config:
        orm_mode = True


class TokenRefreshResponse(BaseModel):
    access_token: str
    refresh_token: str


class LogoutResponse(BaseModel):
    pass