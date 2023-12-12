import httpx
from urllib.parse import quote
from ..utils import (
    no_results_found,
    failed_to_run,
    convert_fqdn_to_url,
)


async def shimon(indicator, client: httpx.AsyncClient):
    try:
        if indicator.indicator_type == "fqdn":
            encoded_url = quote(convert_fqdn_to_url(indicator.indicator), safe="")
        elif indicator.indicator_type == "url":
            encoded_url = quote(indicator.indicator, safe="")
        else:
            raise Exception("Invalid indicator type for shimon")

        response = await client.get(
            f"https://shimon-6983d71a338d.herokuapp.com/api/fingerprint/calculate?url={encoded_url}",
            headers={"accept": "application/json"},
        )

        if response.status_code == 500:
            return no_results_found("shimon")
        if response.status_code != 200:
            return failed_to_run(
                tool_name="shimon",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
            )

        return {
            "tool": "shimon",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": response.json(),
        }
    except Exception as error_message:
        return failed_to_run(tool_name="shimon", error_message=error_message)
