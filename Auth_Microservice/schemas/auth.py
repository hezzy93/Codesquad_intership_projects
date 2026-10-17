from pydantic import BaseModel, EmailStr, Field
import uuid
from datetime import datetime

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True