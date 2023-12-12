import httpx
from ... import config
from ..utils import (
    failed_to_run,
    missing_apikey,
    no_results_found,
)


async def hybrid_analysis(indicator, client: httpx.AsyncClient):
    # https://www.hybrid-analysis.com/docs/api/v2
    try:
        if config["HYBRID_ANALYSIS_API_KEY"] == "":
            return missing_apikey("hybrid_analysis")

        response = await client.post(
            "https://hybrid-analysis.com/api/v2/search/hash",
            headers={
                "accept": "application/json",
                "user-agent": "Falcon Sandbox",
                "api-key": config["HYBRID_ANALYSIS_API_KEY"],
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"hash": indicator.indicator},
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="hybrid_analysis",
                status_code=response.status_code,
                reason=str(response.reason_phrase),
            )

        if not response.json():
            return no_results_found("hybrid_analysis")

        response = response.json()[0]
        return {
            "tool": "hybrid_analysis",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": None,
                "reason": None,
            },
            "results": {
                "file_name": response.get("submissions")[0].get("filename"),
                "type": response.get("type"),
                "job_environment": response.get("environment_description"),
                "av_detect": response.get("av_detect"),
                "vx_family": response.get("vx_family"),
                "verdict": response.get("verdict"),
                "threat_score": response.get("threat_score"),
                "sha1": response.get("sha1"),
                "sha256": response.get("sha256"),
                "sha512": response.get("sha512"),
                "classification": response.get("classification_tags"),
                "tags": response.get("tags"),
            },
        }

    except Exception as error_message:
        return failed_to_run(tool_name="hybrid_analysis", error_message=error_message)
