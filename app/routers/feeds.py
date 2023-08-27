from .. import templates
from ..database import get_db
from ..models import FeedLists
from fastapi import APIRouter
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, status, Request, Form
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
def create(
    name: str = Form(...),
    category: str = Form(...),
    url: str = Form(...),
    list_type: str = Form(...),
    description: Optional[str] = Form(None),
    list_period: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    url_already_in_feedlists = FeedLists.get_feedlist_by_url(url, db)
    if url_already_in_feedlists:
        raise Exception(f"{url} already exists in database.")

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


@router.get("/delete/{feedlists_id}", response_class=HTMLResponse)
def delete(feedlists_id: int, db: Session = Depends(get_db)):
    feedlist = FeedLists.get_feedlist_by_id(feedlists_id, db)
    url = router.url_path_for("feeds")
    if feedlist:
        db.delete(feedlist)
        db.commit()
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    else:
        return RedirectResponse(url=url, status_code=status.HTTP_404_NOT_FOUND)


@router.get("/update/{feedlists_id}", response_class=HTMLResponse)
def disable(request: Request, feedlists_id: int, db: Session = Depends(get_db)):
    feedlist = FeedLists.get_feedlist_by_id(feedlists_id, db)
    url = router.url_path_for("feeds")
    if feedlist:
        feedlist.active = not feedlist.active
        db.commit()
        return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
    else:
        return RedirectResponse(url=url, status_code=status.HTTP_404_NOT_FOUND)
