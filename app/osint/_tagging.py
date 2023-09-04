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

    return remove_duplicate_keys(tags) if tags else {}


def feedlist_results(indicator):
    tags = {}
    if indicator.feedlist_results:
        tags.update({"Feedlist Match": True})
    return tags


def geo_data(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        # fmt: off
        if site.get("site") == "IP Whois":
            tags.update({"Country": site.get("results").get("Country")})
        
        if site.get("site") == "IP Quality Score":
            if site.get("results").get("Mobile"):
                tags.update({"Mobile": site.get("results").get("Mobile")})
            
            if site.get("results").get("Tor"):
                tags.update({"Tor": site.get("results").get("Tor")})
            
            if site.get("results").get("Proxy"):
                tags.update({"Proxy": site.get("results").get("Proxy")})
                
            if site.get("results").get("Connection Type"):
                tags.update({"Connection Type": site.get("results").get("Connection Type")})

        # fmt: on
    return tags


def virustotal(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        # fmt: off
        if site.get("site") == "VirusTotal Hash":
            if site.get("results").get("Suggested Threat Label"):
                tags.update({"Signature": site.get("results").get("Suggested Threat Label")})
            
            if site.get("results").get("Popular Threat Category"):
                tags.update({"Category": site.get("results").get("Popular Threat Category")})


        if site.get("site") in ["VirusTotal URL", "VirusTotal Hash", "VirusTotal Domain", "VirusTotal IP"]: 
            malicious_hits = site.get("results").get("Malicious", 0)
            undetected_hits = site.get("results").get("Undetected", 0)
            suspicious_hits = site.get("results").get("Suspicious", 0)
            harmless_hits = site.get("results").get("Harmless", 0)
            total_hits = int(malicious_hits) + int(undetected_hits) + int(suspicious_hits) + int(harmless_hits)

            if malicious_hits:
                tags.update({"VT Hits": f"{malicious_hits}/{total_hits}"})
                if malicious_hits >= 3 and malicious_hits < 10:
                    tags.update({"Suspicious": True})
                if malicious_hits >= 10:
                    tags.update({"Malicious": True})
            if site.get("results").get("Creation Date"):
                # Parse the input time string into a datetime object
                date_object = datetime.strptime(site.get("results").get("Creation Date"), "%a %b %d %H:%M:%S %Y")
                # Calculate the current date
                current_date = datetime.now()
                # Calculate the date 3 months ago from the current date
                three_months_ago = current_date - timedelta(days=90)
                # Check if the parsed date is within the last 3 months
                if date_object >= three_months_ago and date_object <= current_date:
                    tags.update({"Newly Created Domain": True})
        # fmt: on
    return tags


def tweetfeed(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if site.get("site") == "Tweetfeed.live" and site.get("results").get("value"):
            tags.update({"Tweetfeed Match": True})
    return tags


def greynoise(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if (
            site.get("site") == "Greynoise Community"
            and site.get("results").get("Classification", "") == "malicious"
        ):
            tags.update({"Malicious": True})
    return tags


def urlscan(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if (
            site.get("site") == "URLScan.io"
            and site.get("results").get("Malicious", "") == "malicious"
        ):
            tags.update({"Malicious": True})
    return tags


def known_binaries(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if site.get("site") in ["Circl.lu", "Echo Trail"] and site.get("results").get(
            "File Name", ""
        ):
            tags.update({"Known Binary": True})
    return tags


def breach_directory(indicator):
    tags = {}
    for site in indicator.results if indicator.results else []:
        if site.get("site") == "Breach Directory":
            if site.get("results").get("Found"):
                tags.update({"Data Breach": True})
    return tags
