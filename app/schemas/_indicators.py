from pydantic import BaseModel
from typing import Optional


class CreateIndicator(BaseModel):
    indicator: str
    api_key: str


class DeleteIndicator(BaseModel):
    indicator_id: int
    api_key: str


class DeleteAllIndicators(BaseModel):
    api_key: str


class CreateNote(BaseModel):
    indicator_id: int
    notes: str
    api_key: str


class SearchIndicators(BaseModel):
    indicator_id: Optional[str] = None
    indicator_name: Optional[str] = None
    indicator_type: Optional[str] = None
    indicator_tags: Optional[str] = None
    indicator_notes: Optional[str] = None
    indicator_results: Optional[str] = None
