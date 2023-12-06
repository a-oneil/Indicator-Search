from .utils import remove_duplicate_keys
from ._gpt import get_indicator_summary


def enrichments_handler(indicator):
    enrichments = {}

    if indicator.results:
        enrichments.update({"description": get_indicator_summary(indicator.results)})

    if indicator.indicator_type == "ipv4":
        enrichments.update(geo_data(indicator))

    elif indicator.indicator_type == "ipv6":
        enrichments.update(geo_data(indicator))

    elif indicator.indicator_type == "fqdn":
        enrichments.update(urlscan(indicator))

    elif indicator.indicator_type == "url":
        enrichments.update(urlscan(indicator))

    elif indicator.indicator_type == "email":
        pass

    elif indicator.indicator_type == "hash.md5":
        pass

    elif indicator.indicator_type == "hash.sha1":
        pass

    elif indicator.indicator_type == "hash.sha256":
        pass

    elif indicator.indicator_type == "hash.sha512":
        pass

    elif indicator.indicator_type == "mac":
        pass

    return remove_duplicate_keys(enrichments) if enrichments else {}


def geo_data(indicator):
    enrichment = {}
    for result in indicator.results if indicator.results else []:
        if result.get("tool") == "ipinfo.io":
            if result.get("results").get("geolocation"):
                geo = result.get("results").get("geolocation")
                geo = geo.split(",")
                enrichment.update({"geo_data": [geo[0], geo[1]]})
    return enrichment


def urlscan(indicator):
    enrichment = {}
    for result in indicator.results if indicator.results else []:
        if result.get("tool") == "urlscan.io":
            if result.get("results").get("last_scan_screenshot"):
                # fmt: off
                enrichment.update({"last_scan_screenshot": result.get("results").get("last_scan_screenshot")})
                # fmt: on
    return enrichment
