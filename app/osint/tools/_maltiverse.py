import httpx
from ... import config
from ..utils import (
    no_results_found,
    failed_to_run,
    missing_apikey,
)


async def maltiverse(indicator, client: httpx.AsyncClient):
    try:
        if config["MALTIVERSE_API_KEY"] == "":
            return missing_apikey("maltiverse")

        header = {"X-API-Key": config["MALTIVERSE_API_KEY"]}
        api = "https://api.maltiverse.com"

        if indicator.indicator_type == "hash.md5":
            results = await client.get(
                f"{api}/sample/md5/{indicator.indicator}", headers=header
            )

        elif indicator.indicator_type == "hash.sha1":
            results = await client.get(
                f"{api}/sample/sha1/{indicator.indicator}", headers=header
            )

        elif indicator.indicator_type == "hash.sha256":
            results = await client.get(
                f"{api}/sample/{indicator.indicator}", headers=header
            )

        elif indicator.indicator_type == "hash.sha512":
            results = await client.get(
                f"{api}/sample/sha512/{indicator.indicator}", headers=header
            )

        elif indicator.indicator_type == "fqdn":
            results = await client.get(
                f"{api}/hostname/{indicator.indicator}", headers=header
            )

        elif indicator.indicator_type == "ipv4":
            results = await client.get(
                f"{api}/ip/{indicator.indicator}", headers=header
            )

        else:
            raise Exception("Invalid indicator type for maltiverse")

        if results.status_code != 200:
            return failed_to_run(
                tool_name="maltiverse",
                error_message=results.reason_phrase,
                status_code=results.status_code,
            )

        if not results.json().get("classification"):
            return no_results_found("maltiverse")

        if (
            results.json().get("classification", "") == "neutral"
            and not results.json().get("blacklist")
            and not results.json().get("tag")
        ):
            return no_results_found("maltiverse")

        # fmt: off
        if indicator.indicator_type == "ipv4":
            return {
                    "tool": "maltiverse",
                    "outcome": {
                        "status": "results_found",
                        "error_message": None,
                        "status_code": None,
                        "reason": None,
                    },
                    "results": {
                        "classification": results.json().get("classification", ""),
                        "blacklist": results.json().get("blacklist"),
                        "tags": results.json().get("tag"),
                        "hostname": results.json().get("hostname"),
                        "is_cdn": results.json().get("is_cdn"),
                        "is_cnc": results.json().get("is_cnc"),
                        "is_distributing_malware": results.json().get("is_distributing_malware"),
                        "is_hosting": results.json().get("is_hosting"),
                        "is_iot_threat": results.json().get("is_iot_threat"),
                        "is_known_attacker": results.json().get("is_known_attacker"),
                        "is_known_scanner": results.json().get("is_known_scanner"),
                        "is_mining_pool": results.json().get("is_mining_pool"),
                        "is_open_proxy": results.json().get("is_open_proxy"),
                        "is_sinkhole": results.json().get("is_sinkhole"),
                        "is_tor_node": results.json().get("is_tor_node"),
                        "is_vpn_node": results.json().get("is_vpn_node"),
                        "registrant_name": results.json().get("registrant_name"),
                    },
                }

        elif indicator.indicator_type == "fqdn":
            return {
                    "tool": "maltiverse",
                    "outcome": {
                        "status": "results_found",
                        "error_message": None,
                        "status_code": None,
                        "reason": None,
                    },
                    "results": {
                        "classification": results.json().get("classification"),
                        "blacklist": results.json().get("blacklist"),
                        "tags": results.json().get("tag"),
                        "ip": results.json().get("ip"),
                        "creation_time": results.json().get("creation_time"),
                        "email": results.json().get("email"),
                        "domain_length": results.json().get("domain_lenght"),
                        "modification_time": results.json().get("modification_time"),
                        "nameserver": results.json().get("nameserver"),
                        "resolved_ip": results.json().get("resolved_ip"),
                    },
                }
        
        else:
            return {
                    "tool": "maltiverse",
                    "outcome": {
                        "status": "results_found",
                        "error_message": None,
                        "status_code": None,
                        "reason": None,
                    },
                    "results": {
                        "classification": results.json().get("classification"),
                        "filename": results.json().get("filename"),
                        "filetype": results.json().get("filetype"),
                        "blacklist": results.json().get("blacklist"),
                        "tags": results.json().get("tag"),
                        "contacted_host": results.json().get("contacted_host"),
                        "dns_request": results.json().get("dns_request"),
                        "suricata_alerts": results.json().get("network_suricata_alert"),
                        "process_list": results.json().get("process_list")
                    },
                }

    except Exception as error_message:
        return failed_to_run(tool_name="maltiverse", error_message=error_message)
