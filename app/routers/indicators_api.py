from .. import schemas
from ..models import Iocs, Indicators, User_Accounts
from ..database import get_db
from ..osint import new_indicator_handler, get_type, refang
from ..authentication import auth_api_key
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException


router = APIRouter(prefix="/api")


@router.post("/indicator", name="Create a new indicator", tags=["Indicators"])
def create_indicator(
    request: schemas.CreateIndicator,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    auth_api_key(request, db)
    indicator = str(request.indicator).strip()
    indicator = refang(indicator)
    indicator_type = get_type(indicator)
    if not indicator_type:
        raise HTTPException(
            400,
            "Must be a valid IPv4 Address, IPv6 Address, Hash, FQDN, URL, Email, Phone Number, User Agent, or MAC Address",
        )
    user = User_Accounts.get_user_by_api_key(request.api_key, db)
    new_indicator = Indicators(
        indicator=indicator,
        indicator_type=indicator_type,
        username=user.username,
    )
    db.add(new_indicator)
    db.commit()
    db.refresh(new_indicator)
    background_tasks.add_task(new_indicator_handler, new_indicator, user, db)
    return new_indicator


@router.get(
    "/indicator/{indicator_id}",
    name="Get results for an indicator",
    tags=["Indicators"],
)
def get_indicator_results(indicator_id: int, db: Session = Depends(get_db)):
    indicator = Indicators.get_indicator_by_id(indicator_id, db)
    if not indicator:
        raise HTTPException(404, "Indicator not found")
    return indicator


@router.post(
    "/indicator/searches", name="Search for scanned indicators", tags=["Indicators"]
)
def search_for_indicator(
    request: schemas.SearchIndicators, db: Session = Depends(get_db)
):
    results = Indicators.get_search_results(
        db,
        request.indicator_id,
        request.indicator_name,
        request.indicator_type,
        request.indicator_tags,
        request.indicator_notes,
        request.indicator_results,
        request.indicator_ioc_id,
        request.created_by,
    )

    if not results:
        raise HTTPException(404, "No results found")
    return results


@router.put("/indicator/notes", name="Add notes to an indicator", tags=["Indicators"])
def add_indicator_notes(request: schemas.CreateNote, db: Session = Depends(get_db)):
    auth_api_key(request, db)
    indicator = Indicators.get_indicator_by_id(request.indicator_id, db)
    if not indicator:
        raise HTTPException(404, "Indicator not found")
    Indicators.update_notes(indicator.id, request.notes, db)
    db.refresh(indicator)
    return {
        "id": indicator.id,
        "indicator": indicator.indicator,
        "indicator_type": indicator.indicator_type,
        "notes": indicator.notes,
        "ioc_id": indicator.ioc_id,
    }


@router.get(
    "/indicator/notes/{indicator_id}",
    name="Get notes from an indicator",
    tags=["Indicators"],
)
def get_notes(indicator_id: int, db: Session = Depends(get_db)):
    indicator = Indicators.get_indicator_by_id(indicator_id, db)
    if not indicator:
        raise HTTPException(404, "Indicator not found")
    return {
        "id": indicator.id,
        "indicator": indicator.indicator,
        "indicator_type": indicator.indicator_type,
        "notes": indicator.notes,
        "ioc_id": indicator.ioc_id,
    }


@router.delete(
    "/indicator/{indicator_id}", name="Delete an indicator", tags=["Indicators"]
)
def delete_indicator(request: schemas.DeleteIndicator, db: Session = Depends(get_db)):
    auth_api_key(request, db)
    indicator = Indicators.get_indicator_by_id(request.indicator_id, db)
    if not indicator:
        raise HTTPException(404, "Indicator not found")

    ioc = Iocs.get_ioc_by_id(indicator.ioc_id, db)
    if ioc:
        ioc.indicator_id = None
        db.add(ioc)
        db.commit()
    db.delete(indicator)
    db.commit()
    return HTTPException(200, f"Indicator {indicator.indicator} deleted")


@router.delete("/indicator", name="Delete all indicators", tags=["Indicators"])
def delete_all_indicators(
    request: schemas.DeleteAllIndicators, db: Session = Depends(get_db)
):
    auth_api_key(request, db)
    indicators = Indicators.get_all_indicators(db)
    if not indicators:
        HTTPException(404, "No indicators found")
    for indicator in indicators:
        ioc = Iocs.get_ioc_by_id(indicator.ioc_id, db)
        if ioc:
            ioc.indicator_id = None
            db.add(ioc)
            db.commit()
        db.delete(indicator)
        db.commit()
    return HTTPException(200, "All indicators deleted")
