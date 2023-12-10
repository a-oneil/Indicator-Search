import httpx
from ..utils import (
    no_results_found,
    failed_to_run,
)


async def tweetfeed_live(indicator, client: httpx.AsyncClient):
    async def query_api(url):
        try:
            return await client.get(url)
        except Exception as error_message:
            return failed_to_run(
                tool_name="tweetfeed.live", error_message=error_message
            )

    try:
        results = {}

        if indicator.indicator_type == "ipv4":
            response = await query_api("https://api.tweetfeed.live/v1/month/ip")
        elif indicator.indicator_type == "fqdn":
            response = await query_api("https://api.tweetfeed.live/v1/month/domain")
        elif indicator.indicator_type == "url":
            response = await query_api("https://api.tweetfeed.live/v1/month/url")
        elif indicator.indicator_type == "hash.md5":
            response = await query_api("https://api.tweetfeed.live/v1/month/md5")
        elif indicator.indicator_type == "hash.sha256":
            response = await query_api("https://api.tweetfeed.live/v1/month/sha256")
        else:
            response = None

        if response.status_code != 200:
            return failed_to_run(
                tool_name="tweetfeed.live",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        if response.json():
            for each in response.json():
                if indicator.indicator in each["value"]:
                    results.update(each)

        if not results:
            return no_results_found("tweetfeed.live")

        return {
            "tool": "tweetfeed.live",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": response.reason_phrase,
            },
            "results": results,
        }
    except Exception as error_message:
        return failed_to_run(tool_name="tweetfeed.live", error_message=error_message)
