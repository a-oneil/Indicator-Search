from datetime import datetime
from pydantic import BaseModel, Field


class CreateUser(BaseModel):
    username: str
    password: str
    invite_key: str


class GetUser(BaseModel):
    api_key: str


class UserDetails(BaseModel):
    id: int
    username: str
    api_key: str
    time_created: datetime

    class Config:
        from_attributes = True


class Login(BaseModel):
    username: str = Field(default=None)
    password: str = Field(default=None)


class TokenData(BaseModel):
    username: str | None = None
