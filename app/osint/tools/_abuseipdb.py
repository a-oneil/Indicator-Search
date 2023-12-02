import requests
from ... import config
from ..utils import (
    failed_to_run,
    missing_apikey,
)


def abuseipdb(indicator):
    try:
        if config["AB_API_KEY"] == "":
            return missing_apikey("abuseipdb")

        response = requests.request(
            method="GET",
            url="https://api.abuseipdb.com/api/v2/check",
            headers={
                "Accept": "application/json",
                "Key": config["AB_API_KEY"],
            },
            params={"ipAddress": indicator.indicator, "maxAgeInDays": "180"},
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="abuseipdb",
                status_code=response.status_code,
                reason=response.reason,
            )

        # fmt: off
        return (
            {
                "tool": "abuseipdb",
                "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                "results": {
                    "reports": response.json().get("data", {}).get("totalReports"),
                    "abuse_score": response.json().get("data", {}).get("abuseConfidenceScore"),
                    "last_report": response.json().get("data", {}).get("lastReportedAt"),
                },
            },
        )
        # fmt: on

    except Exception as error_message:
        return failed_to_run(tool_name="abuseipdb", error_message=error_message)
