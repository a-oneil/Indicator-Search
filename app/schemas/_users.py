from pydantic import BaseModel
from datetime import datetime


class CreateUser(BaseModel):
    username: str
    password: str
    invite_key: str


class GetUser(BaseModel):
    id: int
    username: str
    api_key: str
    time_created: datetime

    class Config:
        from_attributes = True


class Login(BaseModel):
    username: str
    password: str
