import httpx
import json
from ... import config
from ..utils import (
    failed_to_run,
    missing_apikey,
)


async def whatsmybrowser_ua(indicator, client: httpx.AsyncClient):
    try:
        if config["WHATSMYBROWSER_API_KEY"] == "":
            return missing_apikey("whatsmybrowser")

        response = await client.post(
            "https://api.whatismybrowser.com/api/v2/user_agent_parse",
            data=json.dumps(
                {
                    "user_agent": indicator.indicator,
                    "parse_options": {},
                }
            ),
            headers={
                "X-API-KEY": config["WHATSMYBROWSER_API_KEY"],
            },
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="whatsmybrowser_ua",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        # fmt: off
        return {
                    "tool": "whatsmybrowser_ua",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason_phrase},
                    "results": {
                        "is_abusive": response.json().get("parse", {}).get("is_abusive"),
                        "simple_software_string": response.json().get("parse", {}).get("simple_software_string"),
                        "software": response.json().get("parse", {}).get("software"),
                        "software_name": response.json().get("parse", {}).get("software_name"),
                        "software_version": response.json().get("parse", {}).get("software_version"),
                        "software_version_full": response.json().get("parse", {}).get("software_version_full"),
                        "operating_system": response.json().get("parse", {}).get("operating_system"),
                        "operating_system_name": response.json().get("parse", {}).get("operating_system_name"),
                        "operating_system_version_full": response.json().get("parse", {}).get("operating_system_version_full"),
                    }
                }
        # fmt: on

    except Exception as error_message:
        return failed_to_run(tool_name="whatsmybrowser_ua", error_message=error_message)
