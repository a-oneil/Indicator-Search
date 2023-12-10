import httpx
from ... import config
from ..utils import (
    no_results_found,
    failed_to_run,
    convert_email_to_fqdn,
    convert_fqdn_to_url,
    missing_apikey,
)


async def urlvoid(indicator, client: httpx.AsyncClient):
    try:
        if config["APIVOID_API_KEY"] == "":
            return missing_apikey("url_void")

        if indicator.indicator_type == "fqdn":
            fqdn = convert_fqdn_to_url(indicator.indicator)
            response = await client.get(
                f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={config['APIVOID_API_KEY']}&host={fqdn}",
            )
        elif indicator.indicator_type == "url":
            url = indicator.indicator
            response = await client.get(
                f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={config['APIVOID_API_KEY']}&url={url}",
            )
        elif indicator.indicator_type == "email":
            fqdn = convert_email_to_fqdn(indicator.indicator)
            response = await client.get(
                f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={config['APIVOID_API_KEY']}&host={fqdn}",
            )
        else:
            raise Exception("Invalid indicator type for URLVoid")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="url_void",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        blacklists = (
            response.json()
            .get("data", {})
            .get("report", {})
            .get("domain_blacklist", {})
            .get("engines")
        )
        blacklists_list = []

        for each in blacklists if blacklists else []:
            if each.get("detected") and each.get("name") not in blacklists_list:
                blacklists_list.append(each.get("name"))

        security_checks = (
            response.json().get("data", {}).get("report", {}).get("security_checks", {})
        )
        security_checks_list = []
        if security_checks:
            for k, v in security_checks.items():
                if v and k not in security_checks_list:
                    security_checks_list.append(k)

            # fmt: off
            return {
                        "tool": "url_void",
                        "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason_phrase},
                        "results": {
                            "dns_records": response.json().get("data", {}).get("report", {}).get("dns_records", {}).get("mx", {}).get("records", []),
                            "detections": response.json().get("data", {}).get("report", {}).get("domain_blacklist", {}).get("detections"),
                            "scanners_detected": blacklists_list,
                            "security_checks": security_checks_list,
                            "risk_score": response.json().get("data", {}).get("report", {}).get("risk_score", "").get("result"),
                            "redirection": response.json().get("data", {}).get("report", {}).get("redirection", {}),
                        },
                    }
            # fmt: on
        else:
            return no_results_found("url_void")

    except Exception as error_message:
        return failed_to_run(tool_name="url_void", error_message=error_message)
