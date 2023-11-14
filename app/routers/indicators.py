from fastapi import (
    APIRouter,
    Depends,
    Request,
    Form,
    BackgroundTasks,
    Cookie,
)
from .. import templates
from ..models import Indicators, Iocs
from ..database import get_db
from ..osint import new_indicator_handler, get_type, refang
from ..authentication import frontend_auth_required
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse, HTMLResponse
from typing import Optional

router = APIRouter(tags=["Indicators"], include_in_schema=False)

"""
Filter Functions
"""


def time_created_strftime(value):
    return value.strftime("%m/%d/%Y (%H:%M:%S UTC)")


def snakecase_to_title(value):
    value = value.replace("_", " ")
    return value.title()


def searchable(value):
    if get_type(value):
        return True
    else:
        return False


def tag_order(tag_dict):
    keys = list(tag_dict.keys())
    keys.sort()
    sorted_dict = {i: tag_dict[i] for i in keys}

    if "malicious" in sorted_dict:
        malicious_value = sorted_dict.pop("malicious")
        tag_dict = {"malicious": malicious_value, **sorted_dict}
        return tag_dict
    elif "suspicious" in sorted_dict:
        suspicious_value = sorted_dict.pop("suspicious")
        tag_dict = {"suspicious": suspicious_value, **sorted_dict}
        return tag_dict

    return sorted_dict


def supported_feedlist_types(indicator_type):
    if indicator_type in [
        "ipv4",
        "ipv6",
        "fqdn",
        "url",
        "email",
        "hash.md5",
        "hash.sha1",
        "hash.sha256",
        "hash.sha512",
    ]:
        return True
    else:
        return False


templates.env.filters["time_created_strftime"] = time_created_strftime
templates.env.filters["snakecase_to_title"] = snakecase_to_title
templates.env.filters["searchable"] = searchable
templates.env.filters["tag_order"] = tag_order
templates.env.filters["supported_feedlist_types"] = supported_feedlist_types


@router.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        "home/home.html",
        {
            "request": request,
            "recent_indicators": Indicators.get_recent_scans(db),
            "count_of_successful_scans": Indicators.successful_scans(db),
            "count_of_failed_scans": Indicators.failed_scans(db),
        },
    )


@router.get("/searches", response_class=HTMLResponse)
def search_for_indicator(
    request: Request,
    db: Session = Depends(get_db),
    indicator_id: str | None = None,
    indicator_name: str | None = None,
    indicator_type: str | None = None,
    indicator_tags: str | None = None,
    indicator_notes: str | None = None,
    indicator_results: str | None = None,
    indicator_ioc_id: str | None = None,
    created_by: str | None = None,
):
    try:
        results = Indicators.get_search_results(
            db,
            indicator_id,
            indicator_name,
            indicator_type,
            indicator_tags,
            indicator_notes,
            indicator_results,
            indicator_ioc_id,
            created_by,
        )

        return templates.TemplateResponse(
            "searches/searches.html",
            {
                "request": request,
                "search_results": results,
            },
        )
    except Exception as e:
        return templates.TemplateResponse(
            "searches/searches.html",
            {
                "request": request,
                "search_results": Indicators.get_all_indicators(db),
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": str(e),
            },
        )


@router.post("/indicator/create", response_class=HTMLResponse)
async def create_indicator(
    request: Request,
    background_tasks: BackgroundTasks,
    indicator: str = Form(...),
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    indicator = refang(indicator.strip())
    indicator_type = get_type(indicator)

    user = frontend_auth_required(access_token, db)
    if not user:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": "Please log in!",
            },
        )

    if indicator_type:
        new_indicator = Indicators(
            indicator=indicator,
            indicator_type=indicator_type,
            username=user.username,
        )
        db.add(new_indicator)
        db.commit()
        db.refresh(new_indicator)
        background_tasks.add_task(new_indicator_handler, new_indicator, user, db)
        return templates.TemplateResponse(
            "results/results.html",
            {"request": request, "indicator": new_indicator},
        )
    else:
        return templates.TemplateResponse(
            "home/home.html",
            {
                "request": request,
                "recent_indicators": Indicators.get_recent_scans(db),
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": "Must be a valid: IPv4 Address, IPv6 Address, Hash, FQDN, URL, Email, Phone Number, User Agent, or MAC Address",
                "count_of_successful_scans": Indicators.successful_scans(db),
                "count_of_failed_scans": Indicators.failed_scans(db),
            },
        )


@router.get("/indicator/results/{indicator_id}", response_class=HTMLResponse)
def get_indicator_results(
    indicator_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    indicator = Indicators.get_indicator_by_id(indicator_id, db)
    if indicator:
        return templates.TemplateResponse(
            "results/results.html",
            {
                "request": request,
                "indicator": indicator,
                "related_indicators": Indicators.get_related_indicators(indicator, db),
                "ioc": Iocs.get_ioc_by_id(indicator.ioc_id, db),
            },
        )
    else:
        return templates.TemplateResponse(
            "home/home.html",
            {
                "request": request,
                "recent_indicators": Indicators.get_recent_scans(db),
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": "Indicator not found!",
                "count_of_successful_scans": Indicators.successful_scans(db),
                "count_of_failed_scans": Indicators.failed_scans(db),
            },
        )


@router.post("/indicator/notes/{indicator_id}", response_class=HTMLResponse)
def add_indicator_notes(
    request: Request,
    indicator_id: int,
    notes=Form(None),
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    user = frontend_auth_required(access_token, db)
    if not user:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": "Please log in!",
            },
        )
    indicator = Indicators.get_indicator_by_id(indicator_id, db)
    if indicator:
        return templates.TemplateResponse(
            "results/results.html",
            {
                "request": request,
                "indicator": Indicators.update_notes(indicator.id, notes, db),
                "related_indicators": Indicators.get_related_indicators(indicator, db),
            },
        )
    else:
        return templates.TemplateResponse(
            "results/results.html",
            {
                "request": request,
                "indicator": indicator,
                "related_indicators": Indicators.get_related_indicators(indicator, db),
                "ioc": Iocs.get_ioc_by_id(indicator.ioc_id, db),
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": "Something went wrong with saving the notes.",
            },
        )


@router.get("/indicator/delete/{indicator_id}", response_class=HTMLResponse)
def delete_indicator(
    request: Request,
    indicator_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    user = frontend_auth_required(access_token, db)
    if not user:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": "Please log in!",
            },
        )
    indicator = Indicators.get_indicator_by_id(indicator_id, db)
    if not indicator:
        return templates.TemplateResponse(
            "home/home.html",
            {
                "request": request,
                "recent_indicators": Indicators.get_recent_scans(db),
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": "Indicator not found!",
                "count_of_successful_scans": Indicators.successful_scans(db),
                "count_of_failed_scans": Indicators.failed_scans(db),
            },
        )

    ioc = Iocs.get_ioc_by_id(indicator.ioc_id, db)
    if ioc:
        ioc.indicator_id = None
        db.add(ioc)
        db.commit()

    db.delete(indicator)
    db.commit()
    return templates.TemplateResponse(
        "home/home.html",
        {
            "request": request,
            "recent_indicators": Indicators.get_recent_scans(db),
            "count_of_successful_scans": Indicators.successful_scans(db),
            "count_of_failed_scans": Indicators.failed_scans(db),
            "_message": "Indicator deleted!",
            "_message_color": "blue",
        },
    )


@router.get("/searches/delete/{indicator_id}", response_class=HTMLResponse)
def delete_indicator_from_search(
    request: Request,
    indicator_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
    user = frontend_auth_required(access_token, db)
    if not user:
        return templates.TemplateResponse(
            "user/login.html",
            {
                "request": request,
                "_message_header": "",
                "_message_color": "red",
                "_message": "Please log in!",
            },
        )
    indicator = Indicators.get_indicator_by_id(indicator_id, db)
    if not indicator:
        return templates.TemplateResponse(
            "home/home.html",
            {
                "request": request,
                "recent_indicators": Indicators.get_recent_scans(db),
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": "Indicator not found!",
                "count_of_successful_scans": Indicators.successful_scans(db),
                "count_of_failed_scans": Indicators.failed_scans(db),
            },
        )

    ioc = Iocs.get_ioc_by_id(indicator.ioc_id, db)
    if ioc:
        ioc.indicator_id = None
        db.add(ioc)
        db.commit()

    db.delete(indicator)
    db.commit()
    return RedirectResponse(url=router.url_path_for("search_for_indicator"))
