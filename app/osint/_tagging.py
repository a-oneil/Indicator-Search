from .utils import remove_duplicate_keys
from datetime import datetime, timedelta


def tagging_handler(indicator, db):
    tags = {}

    tags.update(feedlist_results(indicator))

    if indicator.indicator_type == "ipv4":
        tags.update(geo_data(indicator))
        tags.update(tweetfeed(indicator))
        tags.update(greynoise(indicator))
        tags.update(virustotal(indicator))

    elif indicator.indicator_type == "ipv6":
        pass

    elif indicator.indicator_type == "fqdn":
        tags.update(tweetfeed(indicator))
        tags.update(virustotal(indicator))
        tags.update(urlscan(indicator))

    elif indicator.indicator_type == "url":
        tags.update(tweetfeed(indicator))
        tags.update(virustotal(indicator))
        tags.update(urlscan(indicator))

    elif indicator.indicator_type == "email":
        tags.update(breach_directory(indicator))

    elif indicator.indicator_type == "hash.md5":
        tags.update(tweetfeed(indicator))
        tags.update(virustotal(indicator))
        tags.update(known_binaries(indicator))

    elif indicator.indicator_type == "hash.sha1":
        tags.update(virustotal(indicator))
        tags.update(known_binaries(indicator))

    elif indicator.indicator_type == "hash.sha256":
        tags.update(tweetfeed(indicator))
        tags.update(virustotal(indicator))
        tags.update(known_binaries(indicator))

    elif indicator.indicator_type == "hash.sha512":
        tags.update(virustotal(indicator))

    elif indicator.indicator_type == "mac":
        pass

    # If the indicator is tagged as malicious AND suspicious, remove the suspicious tag
    if tags and ("malicious" in tags or "suspicious" in tags):
        tags.pop("suspicious", None)

    return remove_duplicate_keys(tags) if tags else {}


def feedlist_results(indicator):
    tags = {}
    if indicator.feedlist_results:
        tags.update({"feedlist_match": True, "suspicious": True})
    return tags


def geo_data(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        # fmt: off
        if site.get("site") == "ip_whois":
            tags.update({"country": site.get("results").get("country")})
        
        if site.get("site") == "ip_quality_score":
            if site.get("results").get("mobile"):
                tags.update({"mobile": site.get("results").get("mobile")})
            
            if site.get("results").get("tor"):
                tags.update({"tor": site.get("results").get("tor")})
            
            if site.get("results").get("proxy"):
                tags.update({"proxy": site.get("results").get("proxy")})
                
            if site.get("results").get("connection_type"):
                tags.update({"connection_type": site.get("results").get("connection_type")})

        # fmt: on
    return tags


def virustotal(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        # fmt: off
        if site.get("site") == "virustotal_hash":
            if site.get("results").get("suggested_threat_label"):
                tags.update({"signature": site.get("results").get("suggested_threat_label")})
            
            if site.get("results").get("popular_threat_category"):
                tags.update({"category": site.get("results").get("popular_threat_category")})


        if site.get("site") in ["virustotal_url", "virustotal_hash", "virustotal_domain", "virustotal_ip"]: 
            malicious_hits = site.get("results").get("malicious", 0)
            undetected_hits = site.get("results").get("undetected", 0)
            suspicious_hits = site.get("results").get("suspicious", 0)
            harmless_hits = site.get("results").get("harmless", 0)
            total_hits = int(malicious_hits) + int(undetected_hits) + int(suspicious_hits) + int(harmless_hits)

            if malicious_hits:
                tags.update({"vt_hits": f"{malicious_hits}/{total_hits}"})
                if malicious_hits >= 3 and malicious_hits < 10:
                    tags.update({"suspicious": True})
                if malicious_hits >= 10:
                    tags.update({"malicious": True})
            if site.get("results").get("creation_date"):
                # Parse the input time string into a datetime object
                date_object = datetime.strptime(site.get("results").get("creation_date"), "%a %b %d %H:%M:%S %Y")
                # Calculate the current date
                current_date = datetime.now()
                # Calculate the date 3 months ago from the current date
                three_months_ago = current_date - timedelta(days=90)
                # Check if the parsed date is within the last 3 months
                if date_object >= three_months_ago and date_object <= current_date:
                    tags.update({"newly_created_domain": True})
        # fmt: on
    return tags


def tweetfeed(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if site.get("site") == "tweetfeed.live" and site.get("results").get("value"):
            tags.update({"tweetfeed_match": True})
    return tags


def greynoise(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if (
            site.get("site") == "greynoise_community"
            and site.get("results").get("classification", "") == "malicious"
        ):
            tags.update({"malicious": True})
    return tags


def urlscan(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if (
            site.get("site") == "urlscan.io"
            and site.get("results").get("malicious", "") == "malicious"
        ):
            tags.update({"malicious": True})
    return tags


def known_binaries(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if site.get("site") in ["circl.lu", "echo_trail"] and site.get("results").get(
            "file_name", ""
        ):
            tags.update({"known_binary": True})
    return tags


def breach_directory(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if site.get("site") == "breach_directory":
            if site.get("results").get("found"):
                tags.update({"data_breach": True})
    return tags
