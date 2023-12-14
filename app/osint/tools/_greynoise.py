import httpx
from ... import config
from ..utils import (
    no_results_found,
    failed_to_run,
    missing_apikey,
)


async def greynoise_community(indicator, client: httpx.AsyncClient):
    try:
        if config["GREYNOISE_API_KEY"] == "":
            return missing_apikey("greynoise_community")

        # If the user has enterprise, don't run community
        if config["GREYNOISE_ENTERPRISE"]:
            return missing_apikey("greynoise_enterprise")

        response = await client.get(
            f"https://api.greynoise.io/v3/community/{indicator.indicator}",
            headers={
                "key": config["GREYNOISE_API_KEY"],
                "Accept": "application/json",
            },
        )

        if "IP not observed" in response.json().get("message"):
            return no_results_found("greynoise_community")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="greynoise_community",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
                error_message=response.json().get("message"),
            )

        return {
            "tool": "greynoise_community",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": str(response.reason_phrase),
            },
            "results": {
                "classification": response.json().get("classification"),
                "noise": response.json().get("noise"),
                "riot": response.json().get("riot"),
                "name": response.json().get("name"),
                "last_seen": response.json().get("last_seen"),
            },
        }
    except Exception as error_message:
        return failed_to_run(
            tool_name="greynoise_community", error_message=error_message
        )


async def greynoise_enterprise(indicator, client: httpx.AsyncClient):
    try:
        if config["GREYNOISE_API_KEY"] == "":
            return missing_apikey("greynoise_enterprise")

        if not config["GREYNOISE_ENTERPRISE"]:
            return missing_apikey("greynoise_enterprise")

        headers = {
            "key": config["GREYNOISE_API_KEY"],
            "Accept": "application/json",
        }

        ip_address = indicator.indicator
        output = []

        quick_response = await client.get(
            "https://api.greynoise.io/v2/noise/quick/" + ip_address, headers=headers
        )

        if quick_response.json().get("code") == "0x00":
            return no_results_found("greynoise_enterprise")

        if quick_response.status_code != 200:
            return failed_to_run(
                tool_name="greynoise_enterprise",
                status_code=quick_response.status_code,
                reason=str(quick_response.reason_phrase),
                error_message=quick_response.json().get("message"),
            )

        context_json = {}
        riot_json = {}
        if quick_response.json()["noise"]:
            context_response = await client.get(
                "https://api.greynoise.io/v2/noise/context/" + ip_address,
                headers=headers,
            )
            context_json = context_response.json()
            context_json.pop("raw_data", None)
            context_json.pop("cve", None)

        if quick_response.json()["riot"]:
            riot_response = await client.get(
                "https://api.greynoise.io/v2/riot/" + ip_address, headers=headers
            )
            riot_json = riot_response.json()
            riot_json.pop("ip", None)

        if context_json and riot_json:
            response = context_json.copy()
            response.update(riot_json)
            output.append(response)
        elif context_json:
            output = context_json
        elif riot_json:
            output = riot_json
        else:
            output = quick_response.json()

        return {
            "tool": "greynoise_enterprise",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": quick_response.status_code,
                "reason": str(quick_response.reason_phrase),
            },
            "results": output,
        }

    except Exception as error_message:
        return failed_to_run(
            tool_name="greynoise_enterprise", error_message=error_message
        )
