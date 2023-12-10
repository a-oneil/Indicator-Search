import httpx
import datetime
import base64
from ... import config
from ..utils import (
    no_results_found,
    failed_to_run,
    convert_email_to_fqdn,
    convert_fqdn_to_url,
    convert_url_to_fqdn,
    missing_apikey,
)


async def virustotal_ip(indicator, client: httpx.AsyncClient):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            return missing_apikey("virustotal_ip")
        response = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{indicator.indicator}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("virustotal_ip")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="virustotal_ip",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        # fmt: off
        return {
                    "tool": "virustotal_ip",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason_phrase},
                    "results": {
                        "last analysis date": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("last_analysis_date")).strftime('%c') if response.json().get("data").get("attributes").get("last_analysis_date") else "",
                        "harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "reputation": response.json().get("data").get("attributes").get("reputation"),
                        "tags": response.json().get("data").get("attributes").get("tags"),
                    },
                }
        # fmt: on
    except Exception as error_message:
        return failed_to_run(tool_name="virustotal_ip", error_message=error_message)


async def virustotal_domain(indicator, client: httpx.AsyncClient):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            return missing_apikey("virustotal_domain")

        if indicator.indicator_type == "url":
            domain = convert_url_to_fqdn(indicator.indicator)
        elif indicator.indicator_type == "email":
            domain = convert_email_to_fqdn(indicator.indicator)
        else:
            domain = indicator.indicator

        response = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("virustotal_domain")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="virustotal_domain",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        # fmt: off
        return {
                    "tool": "virustotal_domain",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason_phrase},
                    "results": {
                        "whois": response.json().get("data").get("attributes").get("whois"),
                        "creation_date": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("creation_date")).strftime('%c') if response.json().get("data").get("attributes").get("creation_date") else "",
                        "whois_date": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("whois_date")).strftime('%c') if response.json().get("data").get("attributes").get("whois_date") else "",
                        "harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "categories": response.json().get("data").get("attributes").get("categories"),
                        "tld": response.json().get("data").get("attributes").get("tld"),
                        "tags": response.json().get("data").get("attributes").get("tags"),
                        "community_votes": response.json().get("data").get("attributes").get("total_votes"),
                        "last_analysis": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("last_analysis_date")).strftime('%c') if response.json().get("data").get("attributes").get("last_analysis_date") else ""
                    },
                }
        # fmt: on
    except Exception as error_message:
        return failed_to_run(tool_name="virustotal_domain", error_message=error_message)


async def virustotal_url(indicator, client: httpx.AsyncClient):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            return missing_apikey("virustotal_url")

        if indicator.indicator_type == "fqdn":
            url_id = (
                base64.urlsafe_b64encode(
                    convert_fqdn_to_url(indicator.indicator).encode()
                )
                .decode()
                .strip("=")
            )
        else:
            url_id = (
                base64.urlsafe_b64encode(indicator.indicator.encode())
                .decode()
                .strip("=")
            )

        response = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("virustotal_url")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="virustotal_url",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        # fmt: off
        return {
                    "tool": "virustotal_url",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason_phrase},
                    "results": {
                        "harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "url": response.json().get("data").get("attributes").get("url"),
                        "final_url": response.json().get("data").get("attributes").get("final_url"),
                        "last_response_code": response.json().get("data").get("attributes").get("last_http_response_code"),
                        "redirection_chain": response.json().get("data").get("attributes").get("redirection_chain"),
                        "tld": response.json().get("data").get("attributes").get("tld"),
                        "threat_names": response.json().get("data").get("attributes").get("threat_names"),
                        "tags": response.json().get("data").get("attributes").get("tags"),
                        "community_votes": response.json().get("data").get("attributes").get("total_votes"),
                        "categories": response.json().get("data").get("attributes").get("categories"),
                    },
                }
        # fmt: on

    except Exception as error_message:
        return failed_to_run(tool_name="virustotal_url", error_message=error_message)


async def virustotal_hash(indicator, client: httpx.AsyncClient):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            return missing_apikey("virustotal_hash")

        response = await client.get(
            f"https://www.virustotal.com/api/v3/files/{indicator.indicator}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("virustotal_hash")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="virustotal_hash",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        # fmt: off
        return {
                    "tool": "virustotal_hash",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason_phrase},
                    "results": {
                        "harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "suggested_threat_label": response.json().get("data").get("attributes").get("popular_threat_classification", {}).get("suggested_threat_label"),
                        "popular_threat_category": response.json().get("data").get("attributes").get("popular_threat_classification").get("popular_threat_category")[0].get("value") if response.json().get("data").get("attributes").get("popular_threat_classification", {}).get("popular_threat_category", []) else None,
                        "community_votes": response.json().get("data").get("attributes").get("total_votes"),
                        "name": response.json().get("data").get("attributes").get("meaningful_names"),
                        "names": response.json().get("data").get("attributes").get("names"),
                        "type": response.json().get("data").get("attributes").get("magic"),
                        "type_tag": response.json().get("data").get("attributes").get("type_tag"),
                        "tags": response.json().get("data").get("attributes").get("tags"),
                        "times_submitted": response.json().get("data").get("attributes").get("times_submitted"),
                        "product": response.json().get("data").get("attributes").get("signature_info", {}).get("product"),
                        "product_description": response.json().get("data").get("attributes").get("signature_info", {}).get("description"),
                        "signed": response.json().get("data").get("attributes").get("signature_info", {}).get("verified"),
                        "signing_date": response.json().get("data").get("attributes").get("signature_info", {}).get("signing date"),
                        "md5": response.json().get("data").get("attributes").get("md5"),
                        "sha1": response.json().get("data").get("attributes").get("sha1"),
                        "sha256": response.json().get("data").get("attributes").get("sha256"),
                    },
                }
        # fmt: on
    except Exception as error_message:
        return failed_to_run(tool_name="virustotal_hash", error_message=error_message)
