import secrets
import bcrypt
from fastapi import APIRouter, Depends
from .. import schemas, config
from ..models import User_Accounts
from ..database import get_db
from sqlalchemy.orm import Session
from typing import List
from fastapi import (
    APIRouter,
    Depends,
    status,
    HTTPException,
)


router = APIRouter(prefix="/api")

# fmt: off
@router.get("/users", name="Get all users", tags=["Users"], response_model=List[schemas.GetUser])
def get_all(db: Session = Depends(get_db)):
# fmt: on
    return User_Accounts.get_all_users(db)


# fmt: off
@router.get( "/users/{id}", response_model=schemas.GetUser, name="Get a user by id", tags=["Users"])
def get(id: int, db: Session = Depends(get_db)):
# fmt:on
    user = db.query(User_Accounts).filter(User_Accounts.id == id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


# fmt: off
@router.post("/users", name="Create a user",tags=["Users"], response_model=schemas.GetUser)
def create(request: schemas.CreateUser,db: Session = Depends(get_db)):
# fmt: on
    if User_Accounts.get_user_by_username(db, request.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is taken",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if request.invite_key != config["USER_INVITE_KEY"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid invite key"
        )

    new_user = User_Accounts(
        username=request.username,
        password_hash=bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt()),
        api_key=secrets.token_urlsafe(32),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user
