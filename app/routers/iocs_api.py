from fastapi import APIRouter, Depends, Request
from .. import schemas
from ..models import Iocs
from ..database import get_db
from ..authentication import auth_api_key
from sqlalchemy.orm import Session

from fastapi import APIRouter, Depends, Request

router = APIRouter(prefix="/api")


@router.get("/iocs", name="Get the whole Ioc list", tags=["IOCs"])
def get_all(db: Session = Depends(get_db)):
    return Iocs.get_all_iocs(db)


@router.get("/iocs/{ioc_id}", name="Get an IOC by ID", tags=["IOCs"])
def get(ioc_id: int, db: Session = Depends(get_db)):
    ioc = Iocs.get_ioc_by_id(ioc_id, db)
    if ioc is None:
        return {"Error": "IOC not found"}
    return ioc


@router.delete("/iocs/{ioc_id}", name="Delete an Ioc", tags=["IOCs"])
def delete(request: schemas.DeleteIOC, db: Session = Depends(get_db)):
    try:
        auth_api_key(request, db)
        return Iocs.remove_ioc(request.ioc_id, db)
    except Exception as e:
        return {"Error": str(e)}


@router.post("/iocs/search", name="Search for Iocs", tags=["IOCs"])
def search_iocs(request: schemas.SearchIocs, db: Session = Depends(get_db)):
    try:
        return Iocs.get_search_results(
            db,
            request.ioc_id,
            request.ioc_name,
            request.ioc_type,
            request.indicator_id,
        )
    except Exception:
        return {"Error": "No results found"}


@router.post("/iocs/ageout", name="Ageout IOCs", tags=["IOCs"])
def ageout(db: Session = Depends(get_db)):
    try:
        return Iocs.ageout_iocs(db)
    except Exception as e:
        return {"Error": str(e)}
