from fastapi import FastAPI
from starlette.staticfiles import StaticFiles
from .routers.web import feeds, indicators, iocs, report, users
from .routers.api import (
    feeds as feeds_api,
    indicators as indicators_api,
    iocs as iocs_api,
    users as users_api,
)
from .models import Base
from .database import engine

# Create the FastAPI app
app = FastAPI()

# Create the database tables
Base.metadata.create_all(engine)

# Serve static files from the directory "app/static"
app.mount("/static", StaticFiles(directory="app/routers/web/static"), name="static")

# Web routes
app.include_router(indicators.router)
app.include_router(iocs.router)
app.include_router(feeds.router)
app.include_router(report.router)
app.include_router(users.router)

# API routes
app.include_router(indicators_api.router)
app.include_router(iocs_api.router)
app.include_router(feeds_api.router)
app.include_router(users_api.router)
