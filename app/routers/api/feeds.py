from ... import schemas
from ...models import FeedLists
from ...database import get_db
from ...authentication import auth_api_key
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException


router = APIRouter(prefix="/api")


@router.get("/feeds", name="Get all feedlists", tags=["Feed Lists"])
def get_all(db: Session = Depends(get_db)):
    feedlists = FeedLists.get_feedlists(db)
    if not feedlists:
        raise HTTPException(404, "No feedlists found")
    return feedlists


@router.get("/feeds/{feedlist_id}", name="Get a specific feed", tags=["Feed Lists"])
def get(feedlist_id: int, db: Session = Depends(get_db)):
    feedlist = FeedLists.get_feedlists_by_id(db, feedlist_id)
    if not feedlist:
        raise HTTPException(404, "Feedlist found")
    return feedlist


@router.post("/feeds", name="Add a new feed", tags=["Feed Lists"])
def create_feedlist(
    request: schemas.CreateFeedlist,
    db: Session = Depends(get_db),
):
    auth_api_key(request, db)
    url_already_in_feedlists = FeedLists.get_feedlist_by_url(request.url, db)
    if url_already_in_feedlists:
        raise HTTPException(400, f"{request.url} already exists in database.")

    if request.list_type.lower() not in ["any", "ip", "hash", "fqdn"]:
        raise HTTPException(400, "Incorrect feedlist type")

    new_feedlist = FeedLists(
        name=request.name,
        category=request.category,
        list_type=request.list_type.lower(),
        list_period=request.list_period,
        url=request.url,
        description=request.description,
        active=request.active,
    )
    db.add(new_feedlist)
    db.commit()
    db.refresh(new_feedlist)
    return new_feedlist


@router.post("/feeds/{feedlists_id}", name="Enable/Disable a feed", tags=["Feed Lists"])
def disable_feedlist(request: schemas.DisableFeedlist, db: Session = Depends(get_db)):
    auth_api_key(request, db)
    feedlist = FeedLists.get_feedlist_by_id(request.feedlist_id, db)
    if not feedlist:
        raise HTTPException(404, "Feedlist not found")
    feedlist.active = not feedlist.active
    db.commit()
    db.refresh(feedlist)
    return feedlist


@router.delete("/feeds/{feedlists_id}", name="Delete a feed", tags=["Feed Lists"])
def delete_feedlist(request: schemas.DeleteFeedlist, db: Session = Depends(get_db)):
    auth_api_key(request, db)
    feedlist = FeedLists.get_feedlist_by_id(request.feedlists_id, db)
    if not feedlist:
        raise HTTPException(404, "Feedlist not found")
    db.delete(feedlist)
    db.commit()
    return HTTPException(200, "Feedlist deleted")


@router.delete("/feeds", name="Delete all feedlists", tags=["Feed Lists"])
def delete_all_feedlist(
    request: schemas.DeleteAllFeedlists, db: Session = Depends(get_db)
):
    auth_api_key(request, db)
    feedlists = FeedLists.get_feedlists(db)
    if not feedlists:
        raise HTTPException(404, "No feedlists found")

    for feedlist in feedlists:
        db.delete(feedlist)
        db.commit()
    return HTTPException(200, "All feedlists deleted")
