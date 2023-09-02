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
from ..models import User_Accounts
from ..database import get_db
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse, HTMLResponse
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordBearer,
)
from typing import Annotated
from passlib.context import CryptContext
from fastapi import FastAPI, Body, Depends
from ..schemas import Login, GetUser
from ..authentication import signJWT, jwtBearer, decodeJWT
import traceback

router = APIRouter(
    prefix="/user", tags=["Users Frontend Testing"], include_in_schema=True
)

# @router.post("/login", name="Login")
# def login(
#     request: Request,
#     username: str = Form(...),
#     password: str = Form(...),
#     db: Session = Depends(get_db),
# ):
#     user = User_Accounts.get_user_by_username(db, username)

#     if user:
#         pw = password
#         provided_password = pw.encode("utf-8")
#         stored_password_hash = user.password_hash

#         if bcrypt.checkpw(provided_password, stored_password_hash):
#             Sessions.create_session(db, user)
#             return {"Success": "Logged in successfully"}
#         else:
#             return {"Error": "Invalid username and/or password"}

#     raise HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Invalid username and/or password",
#         headers={"WWW-Authenticate": "Bearer"},
#     )


# dependencies=[Depends(jwtBearer())]

""" LOGIN """
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="user/token")


@router.get("/", response_class=HTMLResponse)
def feeds(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        "user/user.html",
        {"request": request},
    )


@router.post("/token")
def user_login(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
):
    if check_user_login(username, password, db):
        jwt_token = signJWT(username)
        # return jwt_token
        return templates.TemplateResponse(
            "user/success.html",
            {
                "request": request,
                "token": jwt_token,
            },
        )
    return templates.TemplateResponse(
        "user/user.html",
        {
            "request": request,
            "_message_header": "Error!",
            "_message_color": "red",
            "_message": "Invalid login!",
        },
    )


""" USER INFO """


@router.get("/info")
def user_info(
    request: Request,
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
):
    return templates.TemplateResponse(
        "user/info/info.html",
        {"request": request, "user": User_Accounts.get_all_users(db)},
    )


""" SIGN UP """


@router.get("/signup")
def signup_form(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        "user/signup/signup.html",
        {"request": request},
    )


@router.post("/signup/new")
def new_user(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
    invite_key: str = Form(...),
):
    try:
        if User_Accounts.get_user_by_username(db, username):
            raise Exception("Username already exists")

        if invite_key != config["USER_INVITE_KEY"]:
            raise Exception("Invalid invite key")

        new_user = User_Accounts(
            username=username,
            password_hash=bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()),
            api_key=secrets.token_urlsafe(32),
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return templates.TemplateResponse(
            "user/user.html",
            {
                "request": request,
                "_message_header": "Success!",
                "_message_color": "blue",
                "_message": "User created, please login!",
            },
        )

    except Exception as e:
        return templates.TemplateResponse(
            "user/signup/signup.html",
            {
                "request": request,
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": str(e),
            },
        )


""" UTILS - Move to user utils """


def check_user_login(username, password, db: Session):
    users = User_Accounts.get_all_users(db)
    for user in users:
        if user.username == username:
            if bcrypt.checkpw(password.encode("utf-8"), user.password_hash):
                return True
    return False
