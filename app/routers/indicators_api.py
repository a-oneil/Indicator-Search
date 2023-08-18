from .. import schemas
from ..models import Iocs, Indicators, User_Accounts
from ..database import get_db
from ..osint import new_indicator_handler, get_type
from ..authentication import auth_api_key
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, Request, BackgroundTasks


router = APIRouter(prefix="/api")


# fmt: off
@router.post("/indicator", name="Create a new indicator", tags=["Indicators"])
def create(request: schemas.CreateIndicator, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
# fmt: on
    auth_api_key(request, db)
    try:
        indicator = str(request.indicator).strip()
        indicator_type = get_type(indicator)
        if indicator_type:
            user = User_Accounts.get_user_by_api_key(request.api_key, db)
            new_indicator = Indicators(
                indicator=indicator, indicator_type=indicator_type, username=user.username
            )
            db.add(new_indicator)
            db.commit()
            db.refresh(new_indicator)
            background_tasks.add_task(new_indicator_handler, new_indicator, db)
            return new_indicator
        else:
            raise Exception(
                "Must be a valid IPv4 Address, IPv6 Address, Hash, FQDN, URL, Email, or MAC Address"
            )
    except Exception as e:
        return {"Error": str(e)}

# fmt: off
@router.get("/indicator/{indicator_id}", name="Get results for an indicator", tags=["Indicators"])
def get(request: Request, indicator_id: int, db: Session = Depends(get_db)):
# fmt: on
    try:
        indicator = Indicators.get_indicator_by_id(indicator_id, db)
        if indicator:
            return indicator
        else:
            raise Exception("Indicator not found")
    except Exception as e:
        return {"Error": str(e)}

# fmt: off
@router.post("/indicator/search", name="Search for indicators", tags=["Indicators"])
def search(request: schemas.SearchIndicators, db: Session = Depends(get_db)):
# fmt: on
    try:
        results = Indicators.get_search_results(
            db,
            request.indicator_id,
            request.indicator_name,
            request.indicator_type,
            request.indicator_tags,
            request.indicator_notes,
            request.indicator_results,
            request.indicator_ioc_id,
        )

        return results
    except Exception:
        return {"Error": "No results found"}


# fmt: off
@router.put("/indicator/notes", name="Add notes to an indicator", tags=["Indicators"])
# fmt: on
def add_notes(request: schemas.AddNotes, db: Session = Depends(get_db)):
    try:
        auth_api_key(request, db)
        indicator = Indicators.get_indicator_by_id(request.indicator_id, db)
        if indicator:
            Indicators.update_notes(indicator.id, request.notes, db)
            db.refresh(indicator)
            return {
                "id": indicator.id,
                "indicator": indicator.indicator,
                "indicator_type": indicator.indicator_type,
                "notes": indicator.notes,
                "ioc_id": indicator.ioc_id,
            }
        else:
            raise Exception("Indicator not found")
    except Exception as e:
        return {"Error": str(e)}


# fmt: off
@router.get("/indicator/notes/{indicator_id}", name="Get notes from an indicator", tags=["Indicators"])
def get_notes(request: Request, indicator_id: int, db: Session = Depends(get_db)):
# fmt: on
    try:
        indicator = Indicators.get_indicator_by_id(indicator_id, db)
        if indicator:
            return {
                "id": indicator.id,
                "indicator": indicator.indicator,
                "indicator_type": indicator.indicator_type,
                "notes": indicator.notes,
                "ioc_id": indicator.ioc_id,
                }
        else:
            raise Exception("Indicator not found")
    except Exception as e:
        return {"Error": str(e)}


# fmt: off
@router.delete("/indicator/{indicator_id}", name="Delete an indicator", tags=["Indicators"])
def delete(request: schemas.DeleteIndicator, db: Session = Depends(get_db)):
# fmt: on
    try:
        auth_api_key(request, db)
        indicator = Indicators.get_indicator_by_id(request.indicator_id, db)
        if indicator:
            ioc = Iocs.get_ioc_by_id(indicator.ioc_id, db)
            if ioc:
                ioc.indicator_id = None
                db.add(ioc)
                db.commit()    
            db.delete(indicator)
            db.commit()
        else:
            raise Exception("Indicator not found")
        
        return {"Success": "Indicator deleted"}
    except Exception as e:
        return {"Error": str(e)}
