from sqlalchemy import Boolean, Column, Integer, String, DateTime, TypeDecorator
from sqlalchemy.sql import func
from sqlalchemy.orm import Session, relationship
from ..database import Base


class HexByteString(TypeDecorator):
    """Convert Python bytestring to string with hexadecimal digits and back for storage."""

    impl = String

    def process_bind_param(self, value, dialect):
        if not isinstance(value, bytes):
            raise TypeError("HexByteString columns support only bytes values.")
        return value.hex()

    def process_result_value(self, value, dialect):
        return bytes.fromhex(value) if value else None


class User_Accounts(Base):
    __tablename__ = "user_accounts"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    time_created = Column(DateTime(timezone=False), server_default=func.now())
    api_key = Column(String)
    password_hash = Column(HexByteString)
    disabled = Column(Boolean, default=True)
    indicators = relationship("Indicators", back_populates="creator")

    @classmethod
    def get_user_by_username(cls, username: str, db: Session):
        return db.query(cls).filter(cls.username == username).first()

    @classmethod
    def get_user_by_api_key(cls, api_key: str, db: Session):
        return db.query(cls).filter(cls.api_key == api_key).first()

    @classmethod
    def get_user_by_id(cls, user_id: int, db: Session):
        return db.query(cls).filter(cls.id == user_id).first()

    @classmethod
    def get_all_users(cls, db: Session):
        return db.query(cls).order_by(cls.id.desc()).all()
