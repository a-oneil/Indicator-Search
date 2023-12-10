import httpx
from ... import config
from ..utils import (
    failed_to_run,
    missing_apikey,
)


async def emailrepio(indicator, client: httpx.AsyncClient):
    try:
        if config["EMAILREP_API_KEY"] == "":
            return missing_apikey("emailrep.io")
        header = {"Key": config["EMAILREP_API_KEY"]}
        response = await client.get(
            f"https://emailrep.io/{indicator.indicator}",
            headers=header,
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="emailrep.io",
                status_code=response.status_code,
                reason=response.reason_phrase,
            )

        # fmt: off
        return {
                    "tool": "emailrep.io",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason_phrase},
                    "results": {
                        "reputation": response.json().get("reputation"),
                        "suspicious": response.json().get("suspicious"),
                        "references": response.json().get("references"),
                        "blacklisted": response.json().get("details", {}).get("blacklisted"),
                        "malicious_activity": response.json().get("details", {}).get("malicious_activity"),
                        "malicious_activity_recent": response.json().get("details", {}).get("malicious_activity_recent"),
                        "credential_leaked": response.json().get("details", {}).get("credentials_leaked"),
                        "credentials_leaked_recent": response.json().get("details", {}).get("credentials_leaked_recent"),
                        "data_breach": response.json().get("details", {}).get("data_breach"),
                        "first_seen": response.json().get("details", {}).get("first_seen"),
                        "last_seen": response.json().get("details", {}).get("last_seen"),
                        "domain_exists": response.json().get("details", {}).get("domain_exists"),
                        "domain_reputation": response.json().get("details", {}).get("domain_reputation"),
                        "new_domain": response.json().get("details", {}).get("new_domain"),
                        "days_since_domain_creation": response.json().get("details", {}).get("days_since_domain_creation"),
                        "suspicious_tld": response.json().get("details", {}).get("suspicious_tld"),
                        "spam": response.json().get("details", {}).get("spam"),
                        "free_provider": response.json().get("details", {}).get("free_provider"),
                        "disposable": response.json().get("details", {}).get("disposable"),
                        "deliverable": response.json().get("details", {}).get("deliverable"),
                        "accept_all": response.json().get("details", {}).get("accept_all"),
                        "valid_mx": response.json().get("details", {}).get("valid_mx"),
                        "primary_mx": response.json().get("details", {}).get("primary_mx"),
                        "spoofable": response.json().get("details", {}).get("spoofable"),
                        "spf_strict": response.json().get("details", {}).get("spf_strict"),
                        "dmar_enforced": response.json().get("details", {}).get("dmarc_enforced"),
                        "profiles": response.json().get("details", {}).get("profiles", []),
                    },
                }
    # fmt: on
    except Exception as error_message:
        return failed_to_run(tool_name="emailrep.io", error_message=error_message)
