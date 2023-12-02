import requests
from ..utils import (
    no_results_found,
    failed_to_run,
)


def inquestlabs(indicator):
    try:
        hash_type = None
        kind = None
        if indicator.indicator_type == "hash.md5":
            hash_type = "md5"
        elif indicator.indicator_type == "hash.sha1":
            hash_type = "sha1"
        elif indicator.indicator_type == "hash.sha256":
            hash_type = "sha256"
        elif indicator.indicator_type == "hash.sha512":
            hash_type = "sha512"
        elif indicator.indicator_type == "fqdn":
            kind = "domain"
        elif indicator.indicator_type == "email":
            kind = "email"
        elif indicator.indicator_type == "ipv4":
            kind = "ip"
        elif indicator.indicator_type == "url":
            kind = "url"

        if hash_type:
            response = requests.get(
                f"https://labs.inquest.net/api/dfi/search/hash/{hash_type}",
                params={"hash": f"{indicator.indicator}"},
                headers={"accept": "application/json"},
            )

        elif kind:
            response = requests.get(
                f"https://labs.inquest.net/api/dfi/search/ioc/{kind}",
                params={"keyword": f"{indicator.indicator}"},
                headers={"accept": "application/json"},
            )

        else:
            raise Exception("Invalid indicator type for inquest_labs")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="inquest_labs",
                status_code=response.status_code,
                reason=response.reason,
            )

        if response.json().get("success") is False:
            return no_results_found("inquest_labs")

        if not response.json().get("data"):
            return no_results_found("inquest_labs")

        return (
            # fmt: off
                {
                    "tool": "inquest_labs",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "classification": response.json().get("data", [])[0].get("classification"),
                        "file_type": response.json().get("data", [])[0].get("file_type"),
                        "first_seen": response.json().get("data", [])[0].get("first_seen"),
                        "inquest_alerts": response.json().get("data", [])[0].get("inquest_alerts"),
                        "mime_type": response.json().get("data", [])[0].get("mime_type"),
                        "subcategory": response.json().get("data", [])[0].get("subcategory"),
                        "subcategory_url": response.json().get("data", [])[0].get("subcategory_url"),
                        "tags": response.json().get("data", [])[0].get("tags"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="inquest_labs", error_message=error_message)
