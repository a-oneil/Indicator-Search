import httpx
from ..utils import (
    failed_to_run,
    no_results_found,
)


async def circl_lu(indicator, client: httpx.AsyncClient):
    try:
        if indicator.indicator_type == "hash.md5":
            response = await client.get(
                f"https://hashlookup.circl.lu/lookup/md5/{indicator.indicator}",
            )
        elif indicator.indicator_type == "hash.sha1":
            response = await client.get(
                f"https://hashlookup.circl.lu/lookup/sha1/{indicator.indicator}",
            )
        elif indicator.indicator_type == "hash.sha256":
            response = await client.get(
                f"https://hashlookup.circl.lu/lookup/sha256/{indicator.indicator}",
            )

        if "Non existing" in response.json().get("message", ""):
            return no_results_found("circl.lu")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="circl.lu",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
            )

        return {
            "tool": "circl.lu",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": {
                "file_name": response.json().get("FileName"),
                "file_size_kb": response.json().get("FileSize"),
                "product_code": response.json().get("ProductCode"),
                "mimetype": response.json().get("mimetype"),
                "source": response.json().get("source"),
                "known_malicious": response.json().get("KnownMalicious"),
            },
        }
    except Exception as error_message:
        return failed_to_run(tool_name="circl.lu", error_message=error_message)
