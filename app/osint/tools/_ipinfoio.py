import httpx
from ..utils import failed_to_run


async def ipinfoio(indicator, client: httpx.AsyncClient):
    try:
        response = await client.get(f"https://ipinfo.io/{indicator.indicator}")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="ipinfo.io",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        return {
            "tool": "ipinfo.io",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": response.reason_phrase,
            },
            "results": {
                "city": response.json().get("city"),
                "region": response.json().get("region"),
                "geolocation": response.json().get("loc"),
                "organization": response.json().get("org"),
                "postal_code": response.json().get("postal"),
                "timezone": response.json().get("timezone"),
            },
        }
    except Exception as error_message:
        return failed_to_run(tool_name="ipinfo.io", error_message=error_message)
