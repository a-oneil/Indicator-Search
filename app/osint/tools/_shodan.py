from ... import config
from shodan import Shodan
from ..utils import (
    no_results_found,
    failed_to_run,
    missing_apikey,
)


def shodan(indicator):
    try:
        if config["SHODAN_API_KEY"] == "":
            return missing_apikey("shodan")

        try:
            api = Shodan(config["SHODAN_API_KEY"])
            host = api.host(indicator.indicator)
        except Exception:
            return no_results_found("shodan")

        return (
            # fmt: off
                {
                    "tool": "shodan",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": None, "reason": None},
                    "results": {
                        "hostnames": host.get("hostnames"),
                        "domains": host.get("domains"),
                        "tags": host.get("tags"),
                        "last_update": host.get("last_update"),
                        "city": host.get("city"),
                        "asn": host.get("asn"),
                        "isp": host.get("isp"),
                        "country": host.get("country_name"),
                        "region": host.get("region_code"),
                        "os": host.get("os"),
                        "ports": host.get("ports"),
                        "vulns": host.get("vulns"),
                        "url": f"https://www.shodan.io/host/{indicator.indicator}",
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="shodan", error_message=error_message)
