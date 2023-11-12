from ..database import Base
from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    String,
    DateTime,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import Session


class FeedLists(Base):
    __tablename__ = "feedlists"
    id = Column(Integer, primary_key=True, index=True)
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())
    name = Column(String)
    description = Column(String)
    category = Column(String)
    list_type = Column(String)
    list_period = Column(String)
    url = Column(String)
    active = Column(Boolean, default=True)

    @classmethod
    def get_feedlists(cls, db: Session):
        return db.query(cls).order_by(cls.id.desc()).all()

    @classmethod
    def get_feedlist_by_id(cls, feedlist_id: int, db: Session):
        return db.query(cls).filter(cls.id == feedlist_id).first()

    @classmethod
    def get_feedlist_by_url(cls, url: str, db: Session):
        return db.query(cls).filter(cls.url == url).first()

    @classmethod
    def get_active_feedlists_by_type(cls, list_type: str, db: Session):
        return (
            db.query(cls)
            .filter(cls.active == True)
            .filter(cls.list_type == list_type)
            .all()
        )

    @classmethod
    def any_list_type_feedlists(cls, db: Session):
        return (
            db.query(cls)
            .filter(cls.active == True)
            .filter(cls.list_type == "any")
            .all()
        )
