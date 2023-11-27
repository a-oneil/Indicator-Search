from . import config
import bcrypt
from .models import User_Accounts
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from .schemas import TokenData
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, status

JWT_SECRET = config["JWT_SECRET"]
JWT_ALGORITHM = config["JWT_ALGORITHM"]
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = config["JWT_ACCESS_TOKEN_EXPIRE_MINUTES"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthenticationException(HTTPException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Unauthorized"
    headers = {"WWW-Authenticate": "Bearer"}

    def __init__(self, detail=None):
        if detail:
            self.detail = detail
        super().__init__(
            status_code=self.status_code, detail=self.detail, headers=self.headers
        )


def auth_api_key(request, db):
    user = User_Accounts.get_user_by_api_key(request.api_key, db)
    if not user:
        raise AuthenticationException("Invalid API key")
    return user


def check_user_login(username, password, db: Session):
    user = User_Accounts.get_user_by_username(username, db)
    if not user:
        return False
    if bcrypt.checkpw(password.encode(), user.password_hash):
        return user
    return False


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def frontend_auth_required(access_token, db):
    if not access_token:
        return False
    try:
        payload = jwt.decode(access_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return False
        token_data = TokenData(username=username)
    except JWTError:
        return False
    user = User_Accounts.get_user_by_username(token_data.username, db)
    if user is None:
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt
