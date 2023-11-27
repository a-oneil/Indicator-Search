import secrets
import bcrypt
from datetime import timedelta
from ... import templates, config
from ...models import User_Accounts, Indicators
from ...database import get_db
from fastapi import APIRouter, Depends, Request, Form, Cookie
from ...authentication import (
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


@router.get("/edit", response_class=HTMLResponse)
def edit_user(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    try:
        user = frontend_auth_required(access_token, db)
        if not user:
            raise Exception("Please log in!")

        return templates.TemplateResponse(
            "user/edit/edit.html",
            {"request": request, "user": user},
        )
    except Exception as e:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": str(e),
            },
        )


@router.post("/edit", response_class=HTMLResponse)
def update_user(
    request: Request,
    db: Session = Depends(get_db),
    password: str = Form(...),
    api_key: str = Form(...),
    access_token: Optional[str] = Cookie(None),
):
    try:
        user = frontend_auth_required(access_token, db)
        password = password.strip()
        api_key = api_key.strip()

        if not user:
            raise Exception("Please log in!")

        if password != user.password_hash:
            user.password_hash = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            )

        if api_key != user.api_key:
            user.api_key = api_key

        db.add(user)
        db.commit()
        db.refresh(user)

        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "blue",
                "_message": "User updated!",
                "user": user,
            },
        )
    except Exception as e:
        return templates.TemplateResponse(
            "user/edit/edit.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": str(e),
                "user": user,
            },
        )


@router.get("/delete", response_class=HTMLResponse)
def delete_user(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    try:
        user = frontend_auth_required(access_token, db)
        if not user:
            raise Exception("Please log in!")
        db.delete(user)
        db.commit()
        response = templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "blue",
                "_message": "User deleted!",
            },
        )
        response.delete_cookie(key="access_token")
        return response
    except Exception as e:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": str(e),
            },
        )


@router.post("/token", response_class=HTMLResponse)
async def login_for_access_token(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    try:
        if frontend_auth_required(access_token, db):
            raise Exception("Already logged in!")
        user = check_user_login(form_data.username, form_data.password, db)
        if not user:
            raise Exception("Invalid username or password")

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
                "_message": f"Logged into {user.username}",
                "user": user,
            },
        )
        response.set_cookie(key="access_token", value=access_token)
        return response
    except Exception as e:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": str(e),
            },
        )


@router.get("/logout", response_class=HTMLResponse)
async def logout(
    request: Request,
    access_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db),
):
    try:
        if not frontend_auth_required(access_token, db):
            raise Exception("Please log in!")

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

    except Exception as e:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": str(e),
            },
        )


@router.get("/signup", response_class=HTMLResponse)
def signup_form(request: Request):
    return templates.TemplateResponse(
        "user/signup/signup.html",
        {"request": request},
    )


@router.post("/signup/new", response_class=HTMLResponse)
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
            password_hash=bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
            api_key=secrets.token_urlsafe(24),
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


@router.get("/indicators/delete", response_class=HTMLResponse)
def delete_users_indicators(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    try:
        user = frontend_auth_required(access_token, db)
        if not user:
            raise Exception("Please log in!")

        indicators = Indicators.get_search_results(
            db,
            indicator_name=None,
            indicator_type=None,
            indicator_tags=None,
            indicator_id=None,
            indicator_notes=None,
            indicator_ioc_id=None,
            indicator_results=None,
            created_by=user.username,
        )

        if not indicators:
            raise Exception("No indicators found!")

        for indicator in indicators:
            db.delete(indicator)
            db.commit()

        db.refresh(user)

        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "blue",
                "_message": f"{len(indicators)} Indicators deleted!",
                "user": user,
            },
        )
    except Exception as e:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": str(e),
            },
        )
