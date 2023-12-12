import httpx
from ..utils import failed_to_run


async def macvendors(indicator, client: httpx.AsyncClient):
    try:
        response = await client.get(f"https://api.macvendors.com/{indicator.indicator}")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="mac_vendors",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
            )

        return {
            "tool": "mac_vendors",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": {
                "manufacturer": response.text,
            },
        }
    except Exception as error_message:
        return failed_to_run(tool_name="mac_vendors", error_message=error_message)
