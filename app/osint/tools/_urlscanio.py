import requests
from ..utils import (
    no_results_found,
    failed_to_run,
    convert_url_to_fqdn,
)


def urlscanio(indicator):
    try:
        if indicator.indicator_type == "url":
            domain = convert_url_to_fqdn(indicator.indicator)
        else:
            domain = indicator.indicator

        response = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="urlscan.io",
                status_code=response.status_code,
                reason=response.reason,
            )

        if not response.json().get("results"):
            return no_results_found("urlscan.io")

        last_scan_response = {}
        for scan in response.json().get("results"):
            if domain in scan.get("task").get("domain"):
                last_scan_response = requests.get(
                    f"https://urlscan.io/api/v1/result/{scan.get('task').get('uuid')}/",
                )
                break

        if not last_scan_response:
            return no_results_found("urlscan.io")

        return (
            # fmt: off
                {
                    "tool": "urlscan.io",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "last_scan_guid": last_scan_response.json().get("task").get("uuid"),
                        "last_scan_url": last_scan_response.json().get("task").get("reportURL"),
                        "last_scan_time": last_scan_response.json().get("task").get("time"),
                        "last_scan_score": last_scan_response.json().get("verdicts").get("overall").get("score"),
                        "categories": last_scan_response.json().get("verdicts").get("overall").get("categories"),
                        "malicious": last_scan_response.json().get("verdicts").get("overall").get("malicious"),
                        "tags": last_scan_response.json().get("verdicts").get("overall").get("tags"),
                        "last_scan_screenshot": last_scan_response.json().get("task").get("screenshotURL"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="urlscan.io", error_message=error_message)
