from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
from pydantic import EmailStr

class UserBase(SQLModel):
    email: EmailStr = Field(index=True, unique=True)

class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    history: List["LoginHistory"] = Relationship(back_populates="user")

# DTO-схемы для API
class UserAuth(UserBase):
    password: str

class TokenResponse(SQLModel):
    access_token: str
    refresh_token: str

class RefreshRequest(SQLModel):
    refresh_token: str