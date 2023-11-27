import secrets
import bcrypt
from ... import config, schemas
from ...models import User_Accounts
from ...database import get_db
from sqlalchemy.orm import Session
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

router = APIRouter(prefix="/api")


@router.get(
    "/user", response_model=schemas.UserDetails, name="Get user details", tags=["Users"]
)
def get_user(api_key: str, db: Session = Depends(get_db)):
    user = User_Accounts.get_user_by_api_key(api_key, db)
    if not user:
        raise HTTPException(404, "User not found")
    return user


@router.delete("/user", name="Delete a user by their API key", tags=["Users"])
def delete_user(api_key: str, db: Session = Depends(get_db)):
    user = User_Accounts.get_user_by_api_key(api_key, db)
    if not user:
        raise HTTPException(404, "User not found")
    db.delete(user)
    db.commit()
    return HTTPException(200, f"User {user.username} deleted")


@router.post(
    "/user", name="Create a user", tags=["Users"], response_model=schemas.GetUser
)
def create_user(request: schemas.CreateUser, db: Session = Depends(get_db)):
    if User_Accounts.get_user_by_username(request.username, db):
        raise HTTPException(400, "Username already taken")

    if request.invite_key != config["USER_INVITE_KEY"]:
        raise HTTPException(401, "Invalid invite key")

    new_user = User_Accounts(
        username=request.username,
        password_hash=bcrypt.hashpw(request.password.encode("utf-8"), bcrypt.gensalt()),
        api_key=secrets.token_urlsafe(32),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user
