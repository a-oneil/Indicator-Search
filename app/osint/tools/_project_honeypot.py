import httpbl
from ... import config
from ..utils import (
    no_results_found,
    failed_to_run,
    missing_apikey,
)


def project_honeypot(indicator):
    # https://www.projecthoneypot.org/httpbl_api.php
    try:
        if config["PROJECT_HONEYPOT_API_KEY"] == "":
            return missing_apikey("project_honeypot")

        bl = httpbl.HttpBL(config["PROJECT_HONEYPOT_API_KEY"])
        response = bl.query(indicator.indicator)

        if not (response.get("days_since_last_activity") and response.get("type")):
            return no_results_found("project_honeypot")

        return (
            # fmt: off
                {
                    "tool": "project_honeypot",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": None, "reason": None},
                    "results": {
                        "days_since_last_activity": response.get("days_since_last_activity"),
                        "name": response.get("name"),
                        "threat_score": response.get("threat_score"),
                        "type": (", ".join([httpbl.DESCRIPTIONS[t] for t in response["type"]])) if response.get("type") else "",
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="project_honeypot", error_message=error_message)
