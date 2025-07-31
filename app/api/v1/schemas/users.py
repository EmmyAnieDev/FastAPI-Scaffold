from pydantic import BaseModel, EmailStr
from datetime import datetime


class UpdateUserRequest(BaseModel):
    email: EmailStr
    
### Rsponse Schemas ###

class UserResponse(BaseModel):
    id: str
    email: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DeleteUserResponse(BaseModel):
    pass 
