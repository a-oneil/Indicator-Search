import requests
from ..utils import (
    no_results_found,
    failed_to_run,
)


def tweetfeed_live(indicator):
    def query_api(url):
        try:
            return requests.get(url)
        except Exception as error_message:
            return failed_to_run(
                tool_name="tweetfeed.live", error_message=error_message
            )

    try:
        results = {}

        if indicator.indicator_type == "ipv4":
            response = query_api("https://api.tweetfeed.live/v1/month/ip")
        elif indicator.indicator_type == "fqdn":
            response = query_api("https://api.tweetfeed.live/v1/month/domain")
        elif indicator.indicator_type == "url":
            response = query_api("https://api.tweetfeed.live/v1/month/url")
        elif indicator.indicator_type == "hash.md5":
            response = query_api("https://api.tweetfeed.live/v1/month/md5")
        elif indicator.indicator_type == "hash.sha256":
            response = query_api("https://api.tweetfeed.live/v1/month/sha256")
        else:
            response = None

        if response.status_code != 200:
            return failed_to_run(
                tool_name="tweetfeed.live",
                status_code=response.status_code,
                reason=response.reason,
            )

        if response.json():
            for each in response.json():
                if indicator.indicator in each["value"]:
                    results.update(each)

        if not results:
            return no_results_found("tweetfeed.live")

        return (
            {
                "tool": "tweetfeed.live",
                "outcome": {
                    "status": "results_found",
                    "error_message": None,
                    "status_code": response.status_code,
                    "reason": response.reason,
                },
                "results": results,
            },
        )
    except Exception as error_message:
        return failed_to_run(tool_name="tweetfeed.live", error_message=error_message)
