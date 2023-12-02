import requests
from ... import config
from ..utils import (
    no_results_found,
    failed_to_run,
    missing_apikey,
)


def greynoise_community(indicator):
    try:
        if config["GREYNOISE_COMMUNITY_API_KEY"] == "":
            return missing_apikey("greynoise_community")
        params = {"apikey": config["GREYNOISE_COMMUNITY_API_KEY"]}
        response = requests.get(
            f"https://api.greynoise.io/v3/community/{indicator.indicator}",
            params=params,
        )

        if "IP not observed" in response.json().get("message"):
            return no_results_found("greynoise_community")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="greynoise_community",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            {
                "tool": "greynoise_community",
                "outcome": {
                    "status": "results_found",
                    "error_message": None,
                    "status_code": response.status_code,
                    "reason": response.reason,
                },
                "results": {
                    "classification": response.json().get("classification"),
                    "noise": response.json().get("noise"),
                    "riot": response.json().get("riot"),
                    "name": response.json().get("name"),
                    "last_seen": response.json().get("last_seen"),
                },
            },
        )
    except Exception as error_message:
        return failed_to_run(
            tool_name="greynoise_community", error_message=error_message
        )
