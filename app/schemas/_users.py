from datetime import datetime
from pydantic import BaseModel, Field


class CreateUser(BaseModel):
    username: str
    password: str
    invite_key: str


class GetUser(BaseModel):
    id: int
    username: str
    api_key: str
    time_created: datetime
    password_hash: str

    class Config:
        from_attributes = True


class Login(BaseModel):
    username: str = Field(default=None)
    password: str = Field(default=None)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    disabled: bool | None = None


class UserInDB(User):
    password_hash: str
