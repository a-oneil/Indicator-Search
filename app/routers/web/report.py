from fastapi import (
    APIRouter,
    Depends,
    Request,
    Form,
    Cookie,
)
import requests
from ... import templates
from ...database import get_db
from ...authentication import frontend_auth_required
from sqlalchemy.orm import Session
from starlette.responses import HTMLResponse
from typing import Optional

router = APIRouter(tags=["report"], include_in_schema=False)


@router.get("/report", response_class=HTMLResponse)
def home(
    request: Request,
    db: Session = Depends(get_db),
):
    return templates.TemplateResponse("report/report.html", {"request": request})


@router.post("/report/microsoft")
async def microsoft_report(
    request: Request,
    date: str = Form(...),
    time: str = Form(...),
    timeZone: str = Form(...),
    reporterEmail: str = Form(...),
    reporterName: str = Form(...),
    threatType: str = Form(...),
    incidentType: str = Form(...),
    source: str = Form(...),
    reportNotes: str = Form(...),
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

    try:
        if threatType == "IP Address":
            params = {
                "date": date,
                "time": time,
                "timeZone": timeZone,
                "reporterEmail": reporterEmail,
                "reporterName": reporterName,
                "reportNotes": reportNotes.strip(),
                "threatType": threatType,
                "incidentType": incidentType,
                "sourceIp": source,
                "testSubmission": False,
            }
        elif threatType == "URL":
            params = {
                "date": date,
                "time": time,
                "timeZone": timeZone,
                "reporterEmail": reporterEmail,
                "reporterName": reporterName,
                "reportNotes": reportNotes.strip(),
                "threatType": threatType,
                "incidentType": incidentType,
                "sourceUrl": source,
                "testSubmission": False,
            }
        else:
            raise Exception("Invalid Threat Type")

        response = requests.post(
            "https://api.msrc.microsoft.com/report/v2.0/abuse", data=params
        )

        if response.status_code != 200:
            raise Exception(response.reason)

        return templates.TemplateResponse(
            "report/report.html",
            {
                "request": request,
                "_message_color": "green",
                "_message": f"You have successfully submitted a Microsoft report for {source}",
            },
        )

    except Exception as e:
        return templates.TemplateResponse(
            "report/report.html",
            {
                "request": request,
                "_message_color": "red",
                "_message": f"Error submitting report\n{e}",
            },
        )


@router.post("/report/abuseipdb")
async def abuseipdb_report(
    request: Request,
    ip: str = Form(...),
    category: str = Form(...),
    comment: str = Form(...),
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

    try:
        response = requests.post(
            f"https://www.abuseipdb.com/report/json?category={category}&comment={comment.strip()}&ip={ip}"
        )

        if response.status_code != 200:
            raise Exception(response.reason)

        return templates.TemplateResponse(
            "report/report.html",
            {
                "request": request,
                "_message_color": "green",
                "_message": f"You have successfully submitted a Abuse IPDB report for {ip}",
            },
        )

    except Exception as e:
        return templates.TemplateResponse(
            "report/report.html",
            {
                "request": request,
                "_message_color": "red",
                "_message": f"Error submitting report\n{e}",
            },
        )
