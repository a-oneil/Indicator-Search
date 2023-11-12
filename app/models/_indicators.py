from ..database import Base
from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    String,
    JSON,
    DateTime,
    Text,
    ForeignKey,
    and_,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import Session, relationship
from sqlalchemy.orm.attributes import flag_modified


class Indicators(Base):
    __tablename__ = "indicators"
    id = Column(Integer, primary_key=True, index=True)
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())
    creator = relationship("User_Accounts", back_populates="indicators")
    username = Column(String, ForeignKey("user_accounts.username"))
    indicator = Column(String)
    indicator_type = Column(String)
    results = Column(JSON)
    feedlist_results = Column(JSON)
    external_links = Column(JSON)
    tags = Column(JSON)
    notes = Column(Text)
    enrichments = Column(JSON)
    complete = Column(Boolean, default=False)
    ioc_id = Column(Integer, ForeignKey("iocs.id"))
    ioc = relationship("Iocs", uselist=False, back_populates="indicator_scan")

    @classmethod
    def get_search_results(
        cls,
        db: Session,
        indicator_id: int | None,
        indicator_name: str | None,
        indicator_type: str | None,
        indicator_tags: str | None,
        indicator_notes: str | None,
        indicator_results: str | None,
        indicator_ioc_id: int | None,
        created_by: str | None,
    ):
        results = db.query(cls).order_by(cls.id.desc())

        if indicator_id:
            try:
                indicator_id = int(indicator_id)
            except ValueError:
                raise ValueError("Indicator ID must be a number")
            results = results.filter(cls.id == indicator_id)
        if indicator_name:
            results = results.filter(
                cls.indicator.ilike(f"%{str(indicator_name).strip()}%")
            )
        if indicator_type:
            results = results.filter(
                cls.indicator_type.ilike(f"%{str(indicator_type).strip()}%")
            )
        if indicator_tags:
            results = results.filter(cls.tags.ilike(f"%{str(indicator_tags).strip()}%"))
        if indicator_notes:
            results = results.filter(
                cls.notes.ilike(f"%{str(indicator_notes).strip()}%")
            )
        if indicator_results:
            results = results.filter(
                cls.results.ilike(f"%{str(indicator_results).strip()}%")
            )

        if indicator_ioc_id:
            try:
                indicator_ioc_id = int(indicator_ioc_id)
            except ValueError:
                raise ValueError("Indicator ID must be a number")
            results = results.filter(cls.ioc_id == indicator_ioc_id)

        if created_by:
            results = results.filter(cls.username == created_by)
        query = results.all()

        return query

    @classmethod
    def get_recent_scans(cls, db: Session):
        return db.query(cls).order_by(cls.id.desc()).limit(10).all()

    @classmethod
    def get_related_indicators(cls, indicator, db: Session):
        related_indicators = (
            db.query(cls)
            .filter(
                and_(
                    cls.indicator.contains(indicator.indicator),
                    cls.id != indicator.id,
                )
            )
            .order_by(cls.id.desc())
            .limit(5)
            .all()
        )
        return related_indicators

    @classmethod
    def successful_scans(cls, db: Session):
        return db.query(cls).filter(cls.complete == True).count()

    @classmethod
    def failed_scans(cls, db: Session):
        return db.query(cls).filter(cls.tags.contains("error")).count()

    @classmethod
    def get_indicator_by_id(cls, indicator_id: int, db: Session):
        return db.query(cls).filter(cls.id == indicator_id).first()

    @classmethod
    def get_all_indicators(cls, db: Session):
        return db.query(cls).order_by(cls.id.desc()).all()

    @classmethod
    def update_notes(cls, indicator_id: int, notes: str, db: Session):
        indicator = db.query(cls).filter(cls.id == indicator_id).first()
        indicator.notes = notes
        tags_dict = indicator.tags if indicator.tags else {}
        if notes:
            tags_dict["note"] = True
        else:
            tags_dict.pop("note", None)
            db.commit()
        indicator.tags = tags_dict
        flag_modified(indicator, "tags")
        db.commit()
        db.refresh(indicator)
        return indicator

    @classmethod
    def save_feedlist_results(cls, indicator_id: int, feedlist_results, db: Session):
        indicator = db.query(cls).filter(cls.id == indicator_id).first()
        indicator.feedlist_results = feedlist_results
        db.commit()
        db.refresh(indicator)
        return indicator
