from .utils import remove_duplicate_keys
from datetime import datetime, timedelta


def tagging_handler(indicator):
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
    if tags and ("malicious" in tags and "suspicious" in tags):
        tags.pop("suspicious", None)

    return remove_duplicate_keys(tags) if tags else {}


def feedlist_results(indicator):
    tags = {}
    if indicator.feedlist_results:
        tags.update({"feedlist_match": True, "suspicious": True})
    return tags


def geo_data(indicator):
    tags = {}
    for result in indicator.results if indicator.results else []:
        # fmt: off
        if result.get("tool") == "ip_whois":
            tags.update({"country": result.get("results").get("country")})
        
        if result.get("tool") == "ip_quality_score":
            if result.get("results").get("mobile"):
                tags.update({"mobile": result.get("results").get("mobile")})
            
            if result.get("results").get("tor"):
                tags.update({"tor": result.get("results").get("tor")})
            
            if result.get("results").get("proxy"):
                tags.update({"proxy": result.get("results").get("proxy")})
                
            if result.get("results").get("connection_type"):
                if not result.get("results").get("connection_type") == "Premium required.":
                    tags.update({"connection_type": result.get("results").get("connection_type")})

        # fmt: on
    return tags


def virustotal(indicator):
    tags = {}
    for result in indicator.results if indicator.results else []:
        # fmt: off
        if result.get("tool") == "virustotal_hash":
            if result.get("results").get("suggested_threat_label"):
                tags.update({"signature": result.get("results").get("suggested_threat_label")})
            
            if result.get("results").get("popular_threat_category"):
                tags.update({"category": result.get("results").get("popular_threat_category")})

        if result.get("tool") in ["virustotal_url", "virustotal_hash", "virustotal_domain", "virustotal_ip"]: 
            malicious_hits = result.get("results").get("malicious", 0)
            undetected_hits = result.get("results").get("undetected", 0)
            suspicious_hits = result.get("results").get("suspicious", 0)
            harmless_hits = result.get("results").get("harmless", 0)
            total_hits = int(malicious_hits) + int(undetected_hits) + int(suspicious_hits) + int(harmless_hits)

            if malicious_hits:
                tags.update({"vt_hits": f"{malicious_hits}/{total_hits}"})
                if malicious_hits >= 3 and malicious_hits < 10:
                    tags.update({"suspicious": True})
                if malicious_hits >= 10:
                    tags.update({"malicious": True})
            if result.get("results").get("creation_date"):
                # Parse the input time string into a datetime object
                date_object = datetime.strptime(result.get("results").get("creation_date"), "%a %b %d %H:%M:%S %Y")
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
    for result in indicator.results if indicator.results else []:
        if result.get("tool") == "tweetfeed.live" and result.get("results").get(
            "value"
        ):
            tags.update({"tweetfeed_match": True})
    return tags


def greynoise(indicator):
    tags = {}
    for result in indicator.results if indicator.results else []:
        if (
            result.get("tool") == "greynoise_community"
            and result.get("results").get("classification", "") == "malicious"
        ):
            tags.update({"malicious": True})
    return tags


def urlscan(indicator):
    tags = {}
    for result in indicator.results if indicator.results else []:
        if (
            result.get("tool") == "urlscan.io"
            and result.get("results").get("malicious", "") == "malicious"
        ):
            tags.update({"malicious": True})
    return tags


def known_binaries(indicator):
    tags = {}
    for result in indicator.results if indicator.results else []:
        if result.get("tool") in ["circl.lu", "echo_trail"] and result.get(
            "results"
        ).get("file_name", ""):
            tags.update({"known_binary": True})
    return tags


def breach_directory(indicator):
    tags = {}
    for result in indicator.results if indicator.results else []:
        if result.get("tool") == "breach_directory":
            if result.get("results").get("found"):
                tags.update({"data_breach": True})
    return tags
