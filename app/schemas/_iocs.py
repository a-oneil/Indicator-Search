from pydantic import BaseModel
from typing import Optional


class SearchIocs(BaseModel):
    api_key: str
    ioc_id: Optional[str] = None
    ioc_name: Optional[str] = None
    ioc_type: Optional[str] = None
    indicator_id: Optional[str] = None


class DeleteIOC(BaseModel):
    ioc_id: int
    api_key: str
