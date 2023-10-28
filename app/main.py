from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

from .models import Base
from .routers import (
    indicators,
    iocs,
    feeds,
    users,
    report,
    indicators_api,
    iocs_api,
    feeds_api,
    users_api,
)
from .database import engine

# Create the FastAPI app
app = FastAPI()

# Create the database tables
Base.metadata.create_all(engine)

# Serve static files from the directory "app/static"
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Include the routers we've defined
app.include_router(indicators.router)
app.include_router(iocs.router)
app.include_router(feeds.router)
app.include_router(report.router)
app.include_router(users.router)
app.include_router(indicators_api.router)
app.include_router(iocs_api.router)
app.include_router(feeds_api.router)
app.include_router(users_api.router)
