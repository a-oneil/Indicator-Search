from .. import templates
from ..database import get_db
from ..models import FeedLists
from ..authentication import frontend_auth_required
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, status, Request, Form, Cookie
from starlette.responses import RedirectResponse, HTMLResponse
from typing import Optional

router = APIRouter(prefix="/feeds", tags=["Feed Lists"], include_in_schema=False)


@router.get("/", response_class=HTMLResponse)
def feeds(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        "feeds/feeds.html",
        {"request": request, "feed_lists": FeedLists.get_feedlists(db)},
    )


@router.post("/add", response_class=HTMLResponse)
def create_feedlist(
    request: Request,
    name: str = Form(...),
    category: str = Form(...),
    url: str = Form(...),
    list_type: str = Form(...),
    description: Optional[str] = Form(None),
    list_period: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
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
        url_already_in_feedlists = FeedLists.get_feedlist_by_url(url, db)
        if url_already_in_feedlists:
            raise Exception("URL already in feedlists")

        new_feedlist = FeedLists(
            name=name,
            category=category,
            list_type=list_type.lower(),
            list_period=list_period,
            url=url,
            description=description,
            active=True,
        )
        db.add(new_feedlist)
        db.commit()
        return RedirectResponse(
            url=router.url_path_for("feeds"), status_code=status.HTTP_303_SEE_OTHER
        )
    except Exception as e:
        return templates.TemplateResponse(
            "feeds/feeds.html",
            {
                "request": request,
                "feed_lists": FeedLists.get_feedlists(db),
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": str(e),
            },
        )


@router.get("/delete/{feedlists_id}", response_class=HTMLResponse)
def delete_feedlist(
    request: Request,
    feedlists_id: int,
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
    feedlist = FeedLists.get_feedlist_by_id(feedlists_id, db)
    url = router.url_path_for("feeds")
    if feedlist:
        db.delete(feedlist)
        db.commit()
        return templates.TemplateResponse(
            "feeds/feeds.html",
            {
                "request": request,
                "feed_lists": FeedLists.get_feedlists(db),
                "_message_color": "blue",
                "_message": "Feed deleted!",
            },
        )
    else:
        return RedirectResponse(url=url, status_code=status.HTTP_404_NOT_FOUND)


@router.get("/update/{feedlists_id}", response_class=HTMLResponse)
def disable_feedlist(
    request: Request,
    feedlists_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None),
):
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
        feedlist = FeedLists.get_feedlist_by_id(feedlists_id, db)
        url = router.url_path_for("feeds")
        if not feedlist:
            raise Exception("Feedlist not found")
        feedlist.active = not feedlist.active
        db.commit()
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    except Exception as e:
        return templates.TemplateResponse(
            "feeds/feeds.html",
            {
                "request": request,
                "feed_lists": FeedLists.get_feedlists(db),
                "_message_header": "Error!",
                "_message_color": "red",
                "_message": str(e),
            },
        )
