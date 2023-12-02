import requests
from ..utils import failed_to_run


def macvendors(indicator):
    try:
        response = requests.get(f"https://api.macvendors.com/{indicator.indicator}")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="mac_vendors",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
            {
                "tool": "mac_vendors",
                "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                "results": {
                    "manufacturer": response.text,
                },
            },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="mac_vendors", error_message=error_message)
