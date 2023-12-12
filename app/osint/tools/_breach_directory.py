import httpx
from ... import config
from ..utils import failed_to_run, missing_apikey, no_results_found


async def breach_directory(indicator, client: httpx.AsyncClient):
    try:
        if config["BREACH_DIRECTORY_API_KEY"] == "":
            return missing_apikey("breach_directory")

        response = await client.get(
            "https://breachdirectory.p.rapidapi.com/",
            headers={
                "X-RapidAPI-Key": config["BREACH_DIRECTORY_API_KEY"],
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            },
            params={"func": "auto", "term": indicator.indicator},
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="breach_directory",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
            )

        if not response.json().get("result", []):
            return no_results_found("breach_directory")

        return {
            "tool": "breach_directory",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": {
                "found": response.json().get("found", {}),
                "frequency": response.json().get("result", []),
            },
        }
    except Exception as error_message:
        return failed_to_run(tool_name="breach_directory", error_message=error_message)
