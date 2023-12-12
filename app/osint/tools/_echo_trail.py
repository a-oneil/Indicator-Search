import httpx
from ... import config
from ..utils import (
    failed_to_run,
    missing_apikey,
    no_results_found,
)


async def echo_trail(indicator, client: httpx.AsyncClient):
    try:
        if config["ECHOTRAIL_API_KEY"] == "":
            return missing_apikey("echo_trail")

        response = await client.get(
            f"https://api.echotrail.io/v1/insights/{indicator.indicator}",
            headers={
                "X-Api-Key": str(config["ECHOTRAIL_API_KEY"]),
                "Content-Type": "application/json",
            },
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="echo_trail",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
            )

        if "EchoTrail has never observed" in response.json().get("message", ""):
            return no_results_found("echo_trail")

        return {
            "tool": "echo_trail",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": {
                "file_name": response.json().get("filenames"),
                "description": response.json().get("description"),
                "intel": response.json().get("intel"),
                "parents": response.json().get("parents"),
                "children": response.json().get("children"),
            },
        }

    except Exception as error_message:
        return failed_to_run(tool_name="echo_trail", error_message=error_message)
