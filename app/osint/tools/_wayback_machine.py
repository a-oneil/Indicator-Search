import httpx
from ..utils import (
    no_results_found,
    failed_to_run,
    convert_email_to_fqdn,
    convert_url_to_fqdn,
)


async def wayback_machine(indicator, client: httpx.AsyncClient):
    try:
        if indicator.indicator_type == "fqdn":
            response = await client.get(
                f"http://archive.org/wayback/available?url={indicator.indicator}",
            )
        elif indicator.indicator_type == "email":
            response = await client.get(
                f"http://archive.org/wayback/available?url={convert_email_to_fqdn(indicator.indicator)}"
            )
        elif indicator.indicator_type == "url":
            response = await client.get(
                f"http://archive.org/wayback/available?url={convert_url_to_fqdn(indicator.indicator)}"
            )
        else:
            raise Exception("Invalid indicator type for wayback")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="wayback_machine",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
            )

        if not response.json().get("archived_snapshots"):
            return no_results_found("wayback_machine")

        return {
            "tool": "wayback_machine",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": response.json().get("archived_snapshots", {}).get("closest"),
        }
    except Exception as error_message:
        return failed_to_run(tool_name="wayback_machine", error_message=error_message)
