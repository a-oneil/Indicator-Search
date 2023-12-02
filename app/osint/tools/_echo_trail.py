import requests
from ... import config
from ..utils import (
    failed_to_run,
    missing_apikey,
    no_results_found,
)


def echo_trail(indicator):
    try:
        if config["ECHOTRAIL_API_KEY"] == "":
            return missing_apikey("echo_trail")

        response = requests.get(
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
                reason=response.reason,
            )

        if "EchoTrail has never observed" in response.json().get("message", ""):
            return no_results_found("echo_trail")

        return (
            # fmt: off
                {
                    "tool": "echo_trail",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "file_name": response.json().get("filenames"),
                        "description": response.json().get("description"),
                        "intel": response.json().get("intel"),
                        "parents": response.json().get("parents"),
                        "children": response.json().get("children"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="echo_trail", error_message=error_message)
