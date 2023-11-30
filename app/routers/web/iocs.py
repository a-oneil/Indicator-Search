from fastapi import APIRouter, Depends, Request, Cookie
from ... import templates
from ...models import Iocs, Indicators
from ...database import get_db
from ...authentication import frontend_auth_required
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse, HTMLResponse
from typing import Optional

router = APIRouter(prefix="/iocs", tags=["IOCs"], include_in_schema=False)

"""
Filter Functions
"""


def time_created_strftime(value):
    return value.strftime("%m/%d/%Y (%H:%M:%S UTC)")


templates.env.filters["time_created_strftime"] = time_created_strftime


@router.get("/", response_class=HTMLResponse)
def search_iocs(
    request: Request,
    db: Session = Depends(get_db),
    ioc_id: str | None = None,
    ioc_name: str | None = None,
    ioc_type: str | None = None,
    indicator_id: str | None = None,
    access_token: Optional[str] = Cookie(None),
):
    _message = None
    try:
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
        results = Iocs.get_search_results(db, ioc_id, ioc_name, ioc_type, indicator_id)

        return templates.TemplateResponse(
            "iocs/search.html",
            {"request": request, "search_results": results, "_message": _message},
        )
    except Exception as e:
        return templates.TemplateResponse(
            "iocs/search.html",
            {
                "request": request,
                "search_results": Iocs.get_all_iocs(db),
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": str(e),
            },
        )


@router.get("/mark_ioc/{indicator_id}", response_class=HTMLResponse)
async def mark_ioc(
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
    try:
        marked_indicator = Iocs.mark_ioc(indicator_id, db)
        return templates.TemplateResponse(
            "results/results.html",
            {
                "request": request,
                "indicator": marked_indicator,
                "related_indicators": Indicators.get_related_indicators(
                    marked_indicator, db
                ),
                "_message_color": "blue",
                "_message_header": "Success!",
                "_message": f"Marked {marked_indicator.indicator} as an IOC",
                "ioc": Iocs.get_ioc_by_id(marked_indicator.ioc_id, db),
            },
        )
    except Exception as e:
        indicator = Indicators.get_indicator_by_id(indicator_id, db)
        return templates.TemplateResponse(
            "results/results.html",
            {
                "request": request,
                "indicator": indicator,
                "_message_color": "red",
                "_message_header": "Error!",
                "_message": str(e),
            },
        )


@router.get("/delete/{ioc_id}", response_class=HTMLResponse)
def delete(
    request: Request,
    ioc_id: int,
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
    Iocs.remove_ioc(ioc_id, db)
    return RedirectResponse(url=router.url_path_for("search_iocs"))


@router.get("/delete/results/{indicator_id}", response_class=HTMLResponse)
def delete_from_results(
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
    try:
        indicator = Indicators.get_indicator_by_id(indicator_id, db)
        Iocs.remove_ioc(indicator.ioc_id, db)
        db.refresh(indicator)
        return templates.TemplateResponse(
            "results/results.html",
            {
                "request": request,
                "indicator": indicator,
                "related_indicators": Indicators.get_related_indicators(indicator, db),
                "_message_color": "blue",
                "_message_header": "Success!",
                "_message": f"Removed {indicator.indicator} as an IOC",
            },
        )
    except Exception as e:
        return templates.TemplateResponse(
            "results/results.html",
            {
                "request": request,
                "indicator": indicator,
                "related_indicators": Indicators.get_related_indicators(indicator, db),
                "_message_color": "red",
                "_message_header": "Error!",
                "_message": str(e),
            },
        )
