import requests
from ..utils import (
    failed_to_run,
    no_results_found,
)


def circl_lu(indicator):
    try:
        if indicator.indicator_type == "hash.md5":
            response = requests.get(
                f"https://hashlookup.circl.lu/lookup/md5/{indicator.indicator}",
            )
        elif indicator.indicator_type == "hash.sha1":
            response = requests.get(
                f"https://hashlookup.circl.lu/lookup/sha1/{indicator.indicator}",
            )
        elif indicator.indicator_type == "hash.sha256":
            response = requests.get(
                f"https://hashlookup.circl.lu/lookup/sha256/{indicator.indicator}",
            )

        if "Non existing" in response.json().get("message", ""):
            return no_results_found("circl.lu")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="circl.lu",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "circl.lu",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "file_name": response.json().get("FileName"),
                        "file_size_kb": response.json().get("FileSize"),
                        "product_code": response.json().get("ProductCode"),
                        "mimetype": response.json().get("mimetype"),
                        "source": response.json().get("source"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="circl.lu", error_message=error_message)
