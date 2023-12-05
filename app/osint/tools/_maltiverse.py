import requests
from ... import config
from ..utils import (
    no_results_found,
    failed_to_run,
    missing_apikey,
)


def maltiverse(indicator):
    try:
        if config["MALTIVERSE_API_KEY"] == "":
            return missing_apikey("maltiverse")

        header = {"X-API-Key": config["MALTIVERSE_API_KEY"]}
        api = "https://api.maltiverse.com"

        if indicator.indicator_type == "hash.md5":
            result = requests.get(
                f"{api}/sample/md5/{indicator.indicator}", headers=header
            )

        elif indicator.indicator_type == "hash.sha1":
            result = requests.get(
                f"{api}/sample/sha1/{indicator.indicator}", headers=header
            )

        elif indicator.indicator_type == "hash.sha256":
            result = requests.get(f"{api}/sample/{indicator.indicator}", headers=header)

        elif indicator.indicator_type == "hash.sha512":
            result = requests.get(
                f"{api}/sample/sha512/{indicator.indicator}", headers=header
            )

        elif indicator.indicator_type == "fqdn":
            result = requests.get(
                f"{api}/hostname/{indicator.indicator}", headers=header
            )

        elif indicator.indicator_type == "ipv4":
            result = requests.get(f"{api}/ip/{indicator.indicator}", headers=header)

        else:
            raise Exception("Invalid indicator type for maltiverse")

        if result.status_code != 200:
            return failed_to_run(
                tool_name="maltiverse",
                error_message=result.reason,
                status_code=result.status_code,
            )

        if not result.get("classification", ""):
            return no_results_found("maltiverse")

        if (
            result.get("classification", "") == "neutral"
            and not result.get("blacklist", [])
            and not result.get("tag", [])
        ):
            return no_results_found("maltiverse")

        return (
            {
                "tool": "maltiverse",
                "outcome": {
                    "status": "results_found",
                    "error_message": None,
                    "status_code": None,
                    "reason": None,
                },
                "results": {
                    "classification": result.get("classification", ""),
                    "blacklist": result.get("blacklist", []),
                    "tags": result.get("tag", []),
                },
            },
        )
    except Exception as error_message:
        return failed_to_run(tool_name="maltiverse", error_message=error_message)
