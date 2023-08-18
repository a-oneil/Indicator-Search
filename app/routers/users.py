from fastapi import (
    APIRouter,
    Depends,
    status,
    Request,
    Form,
    BackgroundTasks,
    HTTPException,
    Security,
    Header,
)
import jwt
import secrets
import bcrypt
from datetime import datetime, timedelta
from .. import database, templates, config, schemas
from ..models import User_Accounts, Sessions
from ..database import get_db
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse, HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext


router = APIRouter(
    prefix="/user", tags=["Users Frontend Testing"], include_in_schema=True
)


@router.get("/", response_class=HTMLResponse)
def feeds(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        "user/user.html",
        {"request": request, "user": User_Accounts.get_all_users(db)},
    )


@router.post("/login", name="Login")
def login(request: schemas.Login, db: Session = Depends(get_db)):
    # case insensitive email search
    user = User_Accounts.get_user_by_username(db, request.username)
    if user:
        pw = request.password
        if bcrypt.checkpw(pw.encode("utf-8"), user.password_hash.encode("utf-8")):
            Sessions.create_session(db, user)
            return {}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username and/or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.delete("/logout", name="Logout")
def logout(request: Request, db: Session = Depends(get_db)):
    Session.deleteOne(id=request.user_session.id)
    return "Logged out successfully"  # FIX ME
