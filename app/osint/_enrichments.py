from .utils import remove_duplicate_keys


def enrichments_handler(indicator):
    enrichments = {}

    if indicator.indicator_type == "ipv4":
        enrichments.update(geo_data(indicator))

    elif indicator.indicator_type == "ipv6":
        pass

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
    results = {}
    for site in indicator.results if indicator.results else []:
        if site.get("site") == "IPinfo.io":
            if site.get("results").get("GeoLocation"):
                geo = site.get("results").get("GeoLocation")
                geo = geo.split(",")
                results.update({"Geo Data": [geo[0], geo[1]]})
    return results


def urlscan(indicator):
    results = {}
    for site in indicator.results if indicator.results else []:
        if site.get("site") == "URLScan.io":
            if site.get("results").get("Last Scan Screenshot"):
                # fmt: off
                results.update({"Last Scan Screenshot": site.get("results").get("Last Scan Screenshot")})
                # fmt: on
    return results
