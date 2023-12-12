import httpx
from ..utils import (
    no_results_found,
    failed_to_run,
)


async def hacked_ip(indicator, client: httpx.AsyncClient):
    try:
        response = await client.get(
            f"http://www.hackedip.com/api.php?ip={indicator.indicator}",
        )

        if response.status_code != 200:
            return failed_to_run(tool_name="hacked_ip")

        results_list = []
        for item in response.json():
            item.remove(indicator.indicator)
            for i in item:
                x = i.replace(f"{indicator.indicator}|", "")
                results_list.append(x)

        if not results_list:
            return no_results_found("hacked_ip")

        return {
            "tool": "hacked_ip",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": {"active_threatlists": results_list},
        }
    except Exception as error_message:
        return failed_to_run(tool_name="hacked_ip", error_message=error_message)
