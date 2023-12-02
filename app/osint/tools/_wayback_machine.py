import requests
from ..utils import (
    no_results_found,
    failed_to_run,
    convert_email_to_fqdn,
    convert_url_to_fqdn,
)


def wayback_machine(indicator):
    try:
        if indicator.indicator_type == "fqdn":
            response = requests.get(
                f"http://archive.org/wayback/available?url={indicator.indicator}",
            )
        elif indicator.indicator_type == "email":
            response = requests.get(
                f"http://archive.org/wayback/available?url={convert_email_to_fqdn(indicator.indicator)}"
            )
        elif indicator.indicator_type == "url":
            response = requests.get(
                f"http://archive.org/wayback/available?url={convert_url_to_fqdn(indicator.indicator)}"
            )
        else:
            raise Exception("Invalid indicator type for wayback")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="wayback_machine",
                status_code=response.status_code,
                reason=response.reason,
            )

        if not response.json().get("archived_snapshots"):
            return no_results_found("wayback_machine")

        return (
            # fmt: off
                {
                    "tool": "wayback_machine",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": response.json().get("archived_snapshots", {}).get("closest")
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="wayback_machine", error_message=error_message)
