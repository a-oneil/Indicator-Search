from ... import config
from maltiverse import Maltiverse
from ..utils import (
    no_results_found,
    failed_to_run,
    missing_apikey,
)


def maltiverse(indicator):
    try:
        if config["MALTIVERSE_API_KEY"] == "":
            return missing_apikey("maltiverse")

        maltiverse = Maltiverse(auth_token=config["MALTIVERSE_API_KEY"])

        if indicator.indicator_type == "hash.md5":
            result = maltiverse.sample_get_by_md5(indicator.indicator)

        elif indicator.indicator_type == "hash.sha1":
            result = maltiverse.sample_get_by_sha1(indicator.indicator)

        elif indicator.indicator_type == "hash.sha256":
            result = maltiverse.sample_get_by_sha256(indicator.indicator)

        elif indicator.indicator_type == "hash.sha512":
            result = maltiverse.sample_get_by_sha512(indicator.indicator)

        elif indicator.indicator_type == "fqdn":
            result = maltiverse.hostname_get(indicator.indicator)

        elif indicator.indicator_type == "ipv4":
            result = maltiverse.ip_get(indicator.indicator)

        elif indicator.indicator_type == "url":
            result = maltiverse.url_get(indicator.indicator)

        else:
            raise Exception("Invalid indicator type for maltiverse")

        if not result:
            raise no_results_found("maltiverse")

        if not result.get("classification", ""):
            return no_results_found("maltiverse")

        if (
            result.get("classification", "") == "neutral"
            and not result.get("blacklist", [])
            and not result.get("tag", [])
        ):
            return no_results_found("maltiverse")

        return (
            # fmt: off
                {
                    "tool": "maltiverse",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": None, "reason": None},
                    "results": {
                        "classification": result.get("classification", ""),
                        "blacklist": result.get("blacklist", []),
                        "tags": result.get("tag", []),

                        },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="maltiverse", error_message=error_message)
