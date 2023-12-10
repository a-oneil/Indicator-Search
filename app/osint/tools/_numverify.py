import httpx
from ... import config
from ..utils import (
    failed_to_run,
    missing_apikey,
)


async def numverify(indicator, client: httpx.AsyncClient):
    try:
        if config["NUMVERIFY_API_KEY"] == "":
            return missing_apikey("numverify")

        response = await client.get(
            f"http://apilayer.net/api/validate?access_key={config['NUMVERIFY_API_KEY']}&number={indicator.indicator}&format=1"
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="numverify",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        return {
            "tool": "numverify",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": response.reason_phrase,
            },
            "results": response.json(),
        }

    except Exception as error_message:
        return failed_to_run(tool_name="numverify", error_message=error_message)
