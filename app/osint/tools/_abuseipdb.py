import httpx
from ... import config
from ..utils import (
    failed_to_run,
    missing_apikey,
    no_results_found,
)


async def abuseipdb(indicator, client: httpx.AsyncClient):
    try:
        if config["AB_API_KEY"] == "":
            return missing_apikey("abuseipdb")

        response = await client.get(
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
                reason=str(response.reason_phrase),
            )

        if not response.json().get("data", {}).get("lastReportedAt"):
            return no_results_found(tool_name="abuseipdb")

        return {
            "tool": "abuseipdb",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": {
                "reports": response.json().get("data", {}).get("totalReports"),
                "abuse_score": response.json()
                .get("data", {})
                .get("abuseConfidenceScore"),
                "last_report": response.json().get("data", {}).get("lastReportedAt"),
            },
        }

    except Exception as error_message:
        return failed_to_run(tool_name="abuseipdb", error_message=error_message)
