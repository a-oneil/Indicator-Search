from pydantic import BaseModel
from typing import Optional


class AddFeedlist(BaseModel):
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    list_type: str
    list_period: Optional[str] = None
    url: str
    active: Optional[bool] = True
    api_key: str


class DeleteFeedlist(BaseModel):
    feedlist_id: int
    api_key: str


class DisableFeedlist(BaseModel):
    feedlist_id: int
    api_key: str
