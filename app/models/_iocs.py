import datetime
from . import Indicators
from ..database import Base
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import Session, relationship
from sqlalchemy.orm.attributes import flag_modified


class Iocs(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True, index=True)
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    ageout = Column(DateTime(timezone=True))
    indicator = Column(String)
    indicator_type = Column(String)
    indicator_scan = relationship("Indicators", uselist=False, back_populates="ioc")
    indicator_id = Column(Integer)

    @classmethod
    def get_search_results(
        cls,
        db: Session,
        ioc_id: str | None,
        ioc_name: str | None,
        ioc_type: str | None,
        indicator_id: str | None,
    ):
        results = db.query(cls).order_by(cls.id.desc())

        if ioc_id:
            try:
                ioc_id = int(ioc_id)
            except ValueError:
                raise ValueError("Ioc ID must be a number")
            results = results.filter(cls.id == ioc_id)
        if ioc_name:
            results = results.filter(cls.indicator.ilike(f"%{str(ioc_name).strip()}%"))
        if ioc_type:
            results = results.filter(
                cls.indicator_type.ilike(f"%{str(ioc_type).strip()}%")
            )

        if indicator_id:
            try:
                indicator_id = int(indicator_id)
            except ValueError:
                raise ValueError("Indicator ID must be a number")
            results = results.filter(cls.indicator_id == indicator_id)

        query = results.all()

        return query

    @classmethod
    def get_ioc_by_id(cls, ioc_id: int, db: Session):
        return db.query(cls).filter(cls.id == ioc_id).first()

    @classmethod
    def get_all_iocs(cls, db: Session):
        return db.query(cls).order_by(cls.time_created.desc()).all()

    @classmethod
    def get_ioc_by_indicator(cls, indicator: str, db: Session):
        return db.query(cls).filter(cls.indicator == indicator).first()

    @classmethod
    def get_ioc_by_type(cls, indicator_type: str, db: Session):
        return (
            db.query(cls)
            .filter(cls.indicator_type == indicator_type)
            .order_by(cls.time_created.desc())
            .all()
        )

    @classmethod
    def mark_ioc(cls, indicator_id: int, db: Session):
        input_indicator = Indicators.get_indicator_by_id(indicator_id, db)

        if cls.get_ioc_by_indicator(input_indicator.indicator, db):
            raise Exception("IOC already exists")

        related_indicators = Indicators.get_search_results(
            db,
            indicator_id=None,
            indicator_name=input_indicator.indicator,
            indicator_type=None,
            indicator_tags=None,
            indicator_notes=None,
            indicator_results=None,
            indicator_ioc_id=None,
        )

        new_ioc = Iocs(
            ageout=datetime.date.today() + datetime.timedelta(days=14),
            indicator=input_indicator.indicator,
            indicator_type=input_indicator.indicator_type,
            indicator_scan=input_indicator,
            indicator_id=input_indicator.id,
        )
        db.add(new_ioc)
        db.commit()
        db.refresh(new_ioc)

        if related_indicators:
            for indicator in related_indicators:
                indicator.ioc_id = new_ioc.id
                tags_dict = indicator.tags if indicator.tags else {}
                tags_dict.update({"IOC": new_ioc.id})
                indicator.tags = tags_dict
                flag_modified(indicator, "tags")
                db.add(indicator)
                db.commit()

        db.refresh(input_indicator)
        return input_indicator

    @classmethod
    def remove_ioc(cls, ioc_id: int, db: Session):
        ioc = cls.get_ioc_by_id(ioc_id, db)
        if not ioc:
            raise Exception("IOC not found")

        iocd_indicators = Indicators.get_search_results(
            db,
            indicator_id=None,
            indicator_name=None,
            indicator_type=None,
            indicator_tags=None,
            indicator_notes=None,
            indicator_results=None,
            indicator_ioc_id=ioc_id,
        )

        if iocd_indicators:
            for indicator in iocd_indicators:
                indicator.ioc_id = None
                tags_dict = indicator.tags if indicator.tags else {}
                tags_dict.pop("IOC", None)
                indicator.tags = tags_dict
                flag_modified(indicator, "tags")
                db.add(indicator)
                db.commit()

        db.delete(ioc)
        db.commit()
        return {"Success": "IOC removed"}

    @classmethod
    def search_for_ioc(cls, indicator, db: Session):
        input_indicator = Indicators.get_indicator_by_id(indicator.id, db)
        ioc = cls.get_ioc_by_indicator(input_indicator.indicator, db)
        if ioc:
            input_indicator.ioc_id = ioc.id
            tags_dict = input_indicator.tags if input_indicator.tags else {}
            tags_dict.update({"IOC": ioc.id})
            input_indicator.tags = tags_dict
            flag_modified(input_indicator, "tags")
            db.add(input_indicator)
        return input_indicator

    @classmethod
    def ageout_iocs(cls, db: Session):
        iocs = (
            db.query(cls)
            .filter(cls.ageout < datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S"))
            .order_by(cls.time_created.desc())
            .all()
        )

        if iocs:
            for ioc in iocs:
                cls.remove_ioc(ioc.id, db)
            return {"Success": f"{len(iocs)} IOCs aged out"}
        else:
            raise Exception("No IOCs to age out")
