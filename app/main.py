import time
from fastapi import FastAPI, Request, Depends
from starlette.staticfiles import StaticFiles

from .models import Sessions, Base
from .routers import indicators, iocs, feeds, users, indicators_api, iocs_api, feeds_api, users_api
from .database import engine, get_db
from sqlalchemy.orm import Session

# Create the FastAPI app
app = FastAPI()


@app.middleware("http")
async def add_process_time_header(request: Request, call_next, db: Session = Depends(get_db)):
    start_time = time.time()
    db = next(get_db())
    # Before response
    response = await call_next(request)

    # After response
    try:
        user_session = request.user_session
    except AttributeError:
        user_session = None
        # No active user session
        pass

    if user_session:
        # Refresh session
        
        session = db.query(Sessions).filter(Sessions.user_id == user_session.user_id).first()
        if session:
            response.headers["X-Authentication-JWT"] = session.encode_auth_token(db)

    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Create the database tables
Base.metadata.create_all(engine)

# Serve static files from the directory "app/static"
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Include the routers we've defined
app.include_router(indicators.router)
app.include_router(iocs.router)
app.include_router(feeds.router)
app.include_router(users.router)
app.include_router(indicators_api.router)
app.include_router(iocs_api.router)
app.include_router(feeds_api.router)
app.include_router(users_api.router)
