import requests
from ... import config
from ..utils import (
    no_results_found,
    failed_to_run,
    missing_apikey,
)


def greynoise_community(indicator):
    try:
        if config["GREYNOISE_API_KEY"] == "":
            return missing_apikey("greynoise_community")
        params = {"apikey": config["GREYNOISE_API_KEY"]}
        response = requests.get(
            f"https://api.greynoise.io/v3/community/{indicator.indicator}",
            params=params,
        )

        if "IP not observed" in response.json().get("message"):
            return no_results_found("greynoise_community")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="greynoise_community",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            {
                "tool": "greynoise_community",
                "outcome": {
                    "status": "results_found",
                    "error_message": None,
                    "status_code": response.status_code,
                    "reason": response.reason,
                },
                "results": {
                    "classification": response.json().get("classification"),
                    "noise": response.json().get("noise"),
                    "riot": response.json().get("riot"),
                    "name": response.json().get("name"),
                    "last_seen": response.json().get("last_seen"),
                },
            },
        )
    except Exception as error_message:
        return failed_to_run(
            tool_name="greynoise_community", error_message=error_message
        )


def greynoise_enterprise(indicator):
    try:
        if config["GREYNOISE_API_KEY"] == "":
            return missing_apikey("greynoise_enterprise")

        if not config["GREYNOISE_ENTERPRISE"]:
            return missing_apikey("greynoise_enterprise")

        context_url = "https://api.greynoise.io/v2/noise/context/"
        quick_url = "https://api.greynoise.io/v2/noise/quick/"
        riot_url = "https://api.greynoise.io/v2/riot/"
        metadata_url = "https://api.greynoise.io/v2/meta/metadata"

        headers = {
            "key": config["GREYNOISE_API_KEY"],
            "Accept": "application/json",
            "User-Agent": "sample-python-script",
        }

        ip_address = indicator.indicator
        output = []

        def build_tag_details(metadata, tags):
            detailed_tags = []
            for tag in tags:
                for detailed_tag in metadata["metadata"]:
                    if tag == detailed_tag["name"]:
                        detailed_tags.append(detailed_tag)
            return detailed_tags

        quick_response = requests.get(quick_url + ip_address, headers=headers)

        context_json = {}
        riot_json = {}
        if quick_response.json()["noise"]:
            context_response = requests.get(context_url + ip_address, headers=headers)
            context_json = context_response.json()
            if len(context_json["tags"]) >= 1:
                tags_response = requests.get(metadata_url, headers=headers)
                tags_json = tags_response.json()
                updated_tags = build_tag_details(tags_json, context_json["tags"])
                context_json.pop("tags")
                context_json["tags"] = updated_tags
        if quick_response.json()["riot"]:
            riot_response = requests.get(riot_url + ip_address, headers=headers)
            riot_json = riot_response.json()

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

        return output

        # params = {"apikey": config["GREYNOISE_API_KEY"]}
        # response = requests.get(
        #     f"https://api.greynoise.io/v3/community/{indicator.indicator}",
        #     params=params,
        # )

        # if "IP not observed" in response.json().get("message"):
        #     return no_results_found("greynoise_enterprise")

        # if response.status_code != 200:
        #     return failed_to_run(
        #         tool_name="greynoise_enterprise",
        #         status_code=response.status_code,
        #         reason=response.reason,
        #     )

        # return (
        #     {
        #         "tool": "greynoise_enterprise",
        #         "outcome": {
        #             "status": "results_found",
        #             "error_message": None,
        #             "status_code": response.status_code,
        #             "reason": response.reason,
        #         },
        #         "results": {
        #             "classification": response.json().get("classification"),
        #             "noise": response.json().get("noise"),
        #             "riot": response.json().get("riot"),
        #             "name": response.json().get("name"),
        #             "last_seen": response.json().get("last_seen"),
        #         },
        #     },
        # )
    except Exception as error_message:
        return failed_to_run(
            tool_name="greynoise_enterprise", error_message=error_message
        )
