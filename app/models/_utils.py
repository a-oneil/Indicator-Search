from sqlalchemy import (
    Column,
    DateTime,
)
from sqlalchemy.sql import func

from sqlalchemy.orm import Session


class BaseMixin(object):
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())
    # Makes sure the columns are added to the end of the table
    time_created._creation_order = 9998
    time_updated._creation_order = 9999

    @classmethod
    def create(cls, db: Session, **kw):
        obj = cls(**kw)
        db.session.add(obj)
        db.session.commit()
        return obj

    @classmethod
    def deleteOne(cls, db: Session, **kw):
        obj = cls.query.filter_by(**kw).first()
        if obj:
            db.session.delete(obj)
            db.session.commit()
