from fastapi import APIRouter, Depends, Request
from .. import schemas
from ..models import FeedLists
from ..database import get_db
from ..authentication import auth_api_key
from sqlalchemy.orm import Session
from fastapi import (
    APIRouter,
    Depends,
    Request,
)


router = APIRouter(prefix="/api")


@router.get("/feeds", name="Get all feedlists", tags=["Feed Lists"])
def get_all(request: Request, db: Session = Depends(get_db)):
    return FeedLists.get_feedlists(db)


@router.get("/feeds/{feedlist_id}", name="Get a specific feed", tags=["Feed Lists"])
def get(request: Request, feedlist_id: int, db: Session = Depends(get_db)):
    feedlist = FeedLists.get_feedlists_by_id(db, feedlist_id)
    if feedlist:
        return feedlist
    else:
        return {"Error": "Feedlist not found"}


@router.post("/feeds", name="Add a new feed", tags=["Feed Lists"])
def create_feedlist(
    request: schemas.CreateFeedlist,
    db: Session = Depends(get_db),
):
    try:
        auth_api_key(request, db)
        url_already_in_feedlists = FeedLists.get_feedlist_by_url(request.url, db)
        if url_already_in_feedlists:
            raise Exception(f"{request.url} already exists in database.")

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
    except Exception as e:
        return {"Error": str(e)}


@router.post("/feeds/{feedlists_id}", name="Enable/Disable a feed", tags=["Feed Lists"])
def disable_feedlist(request: schemas.DisableFeedlist, db: Session = Depends(get_db)):
    auth_api_key(request, db)
    feedlist = FeedLists.get_feedlist_by_id(request.feedlist_id, db)
    try:
        auth_api_key(request, db)
        if feedlist:
            feedlist.active = not feedlist.active
            db.commit()
            db.refresh(feedlist)
            return feedlist
        else:
            raise Exception("Feedlist not found")
    except Exception as e:
        return {"Error": str(e)}


@router.delete("/feeds/{feedlists_id}", name="Delete a feed", tags=["Feed Lists"])
def delete_feedlist(request: schemas.DeleteFeedlist, db: Session = Depends(get_db)):
    try:
        auth_api_key(request, db)
        feedlist = FeedLists.get_feedlist_by_id(request.feedlists_id, db)
        if feedlist:
            db.delete(feedlist)
            db.commit()
            return {"Success": "Feedlist deleted successfully"}
        else:
            raise Exception("Feedlist not found")
    except Exception as e:
        return {"Error": str(e)}


@router.delete("/feeds", name="Delete all feedlists", tags=["Feed Lists"])
def delete_feedlist(request: schemas.DeleteAllFeedlists, db: Session = Depends(get_db)):
    try:
        auth_api_key(request, db)
        feedlists = FeedLists.get_feedlists(db)
        if feedlists:
            for feedlist in feedlists:
                db.delete(feedlist)
                db.commit()
            return {"Success": "All feedlists deleted"}
        else:
            raise Exception("Feedlist not found")
    except Exception as e:
        return {"Error": str(e)}
