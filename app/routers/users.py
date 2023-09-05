import secrets
import bcrypt
from datetime import timedelta
from .. import templates, config
from ..models import User_Accounts
from ..database import get_db
from fastapi import APIRouter, Depends, Request, Form, Cookie
from ..authentication import (
    check_user_login,
    create_access_token,
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    frontend_auth_required,
)
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from starlette.responses import HTMLResponse
from typing import Annotated, Optional

router = APIRouter(prefix="/user", include_in_schema=False)


@router.get("/", response_class=HTMLResponse)
def get_user(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    user = frontend_auth_required(access_token, db)

    return templates.TemplateResponse(
        "user/login.html",
        {"request": request, "user": user},
    )


@router.get("/delete/{api_key}", response_class=HTMLResponse)
def get_user(
    request: Request,
    api_key: str,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    user = frontend_auth_required(access_token, db)
    if user.api_key != api_key:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": "Failed to delete user!",
            },
        )
    else:
        db.delete(user)
        db.commit()
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "blue",
                "_message": "User deleted!",
            },
        )


@router.post("/token")
async def login_for_access_token(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    if frontend_auth_required(access_token, db):
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": "Already logged in!",
            },
        )
    user = check_user_login(form_data.username, form_data.password, db)
    if not user:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": "Invalid login!",
            },
        )
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    user = frontend_auth_required(access_token, db)
    response = templates.TemplateResponse(
        "user/login.html",
        {
            "request": request,
            "_message_header": "Success!",
            "_message_color": "blue",
            "_message": f"Successfully logged into {user.username}",
            "user": user,
        },
    )
    response.set_cookie(key="access_token", value=access_token)
    return response


@router.get("/logout")
async def logout(
    request: Request,
    access_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db),
):
    if not frontend_auth_required(access_token, db):
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": "Please log in!",
            },
        )
    else:
        response = templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "blue",
                "_message": "Successfully logged out",
            },
        )
        response.delete_cookie(key="access_token")
        return response


@router.get("/signup")
def signup_form(request: Request):
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
        if User_Accounts.get_user_by_username(username, db):
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
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "blue",
                "_message": "User created, please login!",
            },
        )

    except Exception as e:
        return templates.TemplateResponse(
            "user/signup/signup.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": str(e),
            },
        )
