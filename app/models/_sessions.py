import os
import datetime
import json

from sqlalchemy import (
    Column,
    Integer,
    String,
    JSON,
    ForeignKey,
    text,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import Session, relationship, joinedload
import jwt
from fastapi import Request, Depends

from ..exceptions import AuthenticationException
from ..authentication import get_jwt_payload
from ..database import Base, get_db
from ._utils import BaseMixin


class Sessions(Base, BaseMixin):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True, unique=True)
    user_id = Column(Integer, ForeignKey("user_accounts.id"))
    user = relationship("User_Accounts", back_populates="session", lazy="joined")
    secret_key = Column(String, nullable=False)
    session_data = Column(JSON, nullable=False, server_default=text("'{}'"))

    def __repr__(self):
        return "<Session %r>" % self.__dict__

    @staticmethod
    def get_secret_key():
        return os.urandom(24)

    def encode_auth_token(
        self,
        db: Session = Depends(get_db),
    ):
        """
        Generates the Auth Token
        :return: string
        """
        payload = {
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30),
            "iat": datetime.datetime.utcnow(),
            "jti": self.id,  # The ID of the session is the JWT ID
        }

        # Remove dates so we don't have to deal with datetimes
        session_data = payload.copy()
        session_data.pop("exp")
        session_data.pop("iat")

        # Store payload as session data
        self.session_data = session_data
        db.commit()

        return jwt.encode(payload, self.secret_key, algorithm="HS256")


    @staticmethod
    def validate_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: dict
        """

        payload = get_jwt_payload(auth_token)
        if payload is None:
            # The payload could not be parsed
            raise AuthenticationException("The payload could not be parsed")

        # get the session ID
        session_id = payload.get("jti", None)
        session = (
            Session.query.filter_by(id=session_id)
            .options(joinedload(Session.user))
            .first()
        )

        if not session:
            raise AuthenticationException("JWT is invalid")

        try:
            payload = jwt.decode(auth_token, session.secret_key)
            return session
        except jwt.ExpiredSignatureError:
            raise AuthenticationException("Signature expired")
        except jwt.InvalidTokenError:
            raise AuthenticationException("Invalid JWT")

    @staticmethod
    def create_session(db: Session, user=None):
        session = Sessions(
            user_id=user.id,
            secret_key=Sessions.get_secret_key(),
            session_data=json.dumps({}),
        )
        if session:
            # set context local for user session
            Request.user_session = session
            db.add(session)
            db.commit()
        else:
            raise Exception("Could not create user session")
        return session

    @classmethod
    def get_by_id(cls, user_session_id, db: Session):
        return db.query(cls).filter(cls.user_id == user_session_id).first()