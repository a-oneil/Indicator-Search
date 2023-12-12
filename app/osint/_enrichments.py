from .utils import remove_duplicate_keys


def enrichments_handler(indicator):
    enrichments = {}

    if not indicator.results:
        return None

    for tool in indicator.results:
        if not tool.get("outcome").get("status") == "results_found":
            continue

        funcs = [
            urlscan,
            geo_data,
        ]

        for func in funcs:
            func_output = func(tool)
            if func_output:
                enrichments.update(func_output)

    return remove_duplicate_keys(enrichments) if enrichments else {}


def geo_data(tool):
    if tool.get("tool") == "ipinfo.io" and tool.get("results").get("geolocation"):
        geo = tool.get("results").get("geolocation")
        geo = geo.split(",")
        return {"geo_data": [geo[0], geo[1]]}


def urlscan(tool):
    # fmt: off
    if tool.get("tool") == "urlscan.io" and tool.get("results").get("last_scan_screenshot"):
        return {"last_scan_screenshot": tool.get("results").get("last_scan_screenshot")}
    # fmt: on
