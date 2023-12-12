import httpx
import xmltodict
from ..utils import failed_to_run


async def stopforumspam_email(indicator, client: httpx.AsyncClient):
    try:
        response = await client.get(
            f"http://api.stopforumspam.org/api?email={indicator.indicator}",
        )
        results = xmltodict.parse(response.text)

        if response.status_code != 200:
            return failed_to_run(
                tool_name="stop_forum_spam_email",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
            )

        return {
            "tool": "stop_forum_spam_email",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": {
                "appears": results.get("response", {}).get("appears"),
                "frequency": results.get("response", {}).get("frequency"),
            },
        }
    except Exception as error_message:
        return failed_to_run(
            tool_name="stop_forum_spam_email", error_message=error_message
        )


async def stopforumspam_ip(indicator, client: httpx.AsyncClient):
    try:
        response = await client.get(
            f"http://api.stopforumspam.org/api?ip={indicator.indicator}",
        )
        results = xmltodict.parse(response.text)

        if response.status_code != 200:
            return failed_to_run(
                tool_name="stop_forum_spam_ip",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
            )

        return {
            "tool": "stop_forum_spam_ip",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": {
                "appears": results.get("response", {}).get("appears"),
                "frequency": results.get("response", {}).get("frequency"),
            },
        }
    except Exception as error_message:
        return failed_to_run(
            tool_name="stop_forum_spam_ip", error_message=error_message
        )
