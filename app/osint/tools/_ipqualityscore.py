import httpx
from ... import config
from ..utils import (
    failed_to_run,
    missing_apikey,
)


async def ipqualityscore_ip(indicator, client: httpx.AsyncClient):
    try:
        if config["IPQS_API_KEY"] == "":
            return missing_apikey("ip_quality_score")

        response = await client.get(
            f"https://us.ipqualityscore.com/api/json/ip/{config['IPQS_API_KEY']}/{indicator.indicator}",
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="ip_quality_score",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        return {
            "tool": "ip_quality_score",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": response.reason_phrase,
            },
            "results": {
                "isp": response.json().get("ISP"),
                "organization": response.json().get("organization"),
                "country": response.json().get("country_code"),
                "city": response.json().get("city"),
                "mobile": response.json().get("mobile"),
                "is_crawler": response.json().get("is_crawler"),
                "connection_type": response.json().get("connection_type"),
                "recent_abuse": response.json().get("recent_abuse"),
                "bot_status": response.json().get("bot_status"),
                "vpn": response.json().get("vpn", ""),
                "active_vpn": response.json().get("active_vpn"),
                "tor": response.json().get("tor", ""),
                "active_tor": response.json().get("active_tor"),
                "fraud_score": response.json().get("fraud_score"),
                "abuse_velocity": response.json().get("abuse_velocity"),
            },
        }
    except Exception as error_message:
        return failed_to_run(tool_name="ip_quality_score", error_message=error_message)


async def ipqualityscore_phone(indicator, client: httpx.AsyncClient):
    try:
        if config["IPQS_API_KEY"] == "":
            return missing_apikey("ipqualityscore")

        response = await client.get(
            f"https://us.ipqualityscore.com/api/json/phone/{config['IPQS_API_KEY']}/{indicator.indicator}",
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="ip_quality_score_phone",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        return {
            "tool": "ip_quality_score_phone",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": response.status_code,
                "reason": response.reason_phrase,
            },
            "results": response.json(),
        }
    except Exception as error_message:
        return failed_to_run(
            tool_name="ip_quality_score_phone", error_message=error_message
        )
