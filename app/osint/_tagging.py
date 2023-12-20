from .utils import remove_duplicate_keys, top_domains_list
from datetime import datetime, timedelta


def tagging_handler(indicator):
    # "Note, IOC, Error" tags are not handled here
    tags = {}

    if not indicator.results:
        return None

    # Always ran tags, regardless of the tool
    if feedlist_match(indicator):
        tags.update(feedlist_match(indicator))

    if top_2k_domain(indicator):
        tags.update(top_2k_domain(indicator))

    for tool in indicator.results:
        if not tool.get("outcome").get("status") == "results_found":
            continue

        funcs = [
            malicious,
            suspicious,
            new_domain,
            tweetfeed_match,
            known_binary,
            category,
            signature,
            vt_hits,
            country,
            mobile,
            tor,
            proxy,
            data_breach,
            connection_type,
        ]

        for func in funcs:
            func_output = func(tool)
            if func_output:
                tags.update(func_output)

    # If the indicator is tagged as malicious AND suspicious, remove the suspicious tag
    if tags and ("malicious" in tags and "suspicious" in tags):
        tags.pop("suspicious", None)

    return remove_duplicate_keys(tags) if tags else []


def malicious(tool):
    t = {"malicious": True}
    # fmt: off
    if tool.get("tool") == "urlscan.io" and tool.get("results").get("malicious") == "malicious":
        return t

    if tool.get("tool") == "greynoise_community" and tool.get("results").get("classification") == "malicious":
        return t

    if tool.get("tool") in ["virustotal_url", "virustotal_hash", "virustotal_domain", "virustotal_ip"]:
        malicious_hits = tool.get("results").get("malicious", 0)
        if malicious_hits and malicious_hits >= 8:
            return t
    # fmt: on


def suspicious(tool):
    t = {"suspicious": True}
    # fmt: off
    if tool.get("tool") in ["virustotal_url", "virustotal_hash", "virustotal_domain", "virustotal_ip"]:
        suspicious_hits = tool.get("results").get("suspicious", 0)
        if suspicious_hits and suspicious_hits >= 3:
            return t
    # fmt: on


def top_2k_domain(indicator):
    t = {"top_2k_domain": True}
    if indicator.indicator in top_domains_list():
        return t


def new_domain(tool):
    t = {"newly_created_domain": True}
    # fmt: off
    if tool.get("tool") in ["virustotal_url", "virustotal_domain"]:
        if tool.get("results").get("creation_date"):
            date_object = datetime.strptime(tool.get("results").get("creation_date"), "%a %b %d %H:%M:%S %Y")
            current_date = datetime.now()
            three_months_ago = current_date - timedelta(days=90)
            if date_object >= three_months_ago and date_object <= current_date:
                return t
    # fmt: on


def tweetfeed_match(tool):
    t = {"tweetfeed_match": True}
    if tool.get("tool") == "tweetfeed.live" and tool.get("results").get("value"):
        return t


def feedlist_match(indicator):
    t = {"feedlist_match": True, "suspicious": True}
    if indicator.feedlist_results:
        return t


def known_binary(tool):
    t = {"known_binary": True}
    # fmt: off
    if tool.get("tool") in ["circl.lu", "echo_trail"] and tool.get("results").get("file_name"):
        return t
    # fmt: on


def category(tool):
    # fmt: off
    if tool.get("tool") == "virustotal_hash" and tool.get("results").get("popular_threat_category"):
        return {"category": tool.get("results").get("popular_threat_category")}
    # fmt: on


def signature(tool):
    # fmt: off
    if tool.get("tool") == "virustotal_hash":
        if tool.get("results").get("suggested_threat_label"):
            return {"signature": tool.get("results").get("suggested_threat_label")}
    # fmt: on


def vt_hits(tool):
    # fmt: off
    if tool.get("tool") in ["virustotal_url", "virustotal_hash", "virustotal_domain", "virustotal_ip"]:
        malicious_hits = tool.get("results").get("malicious", 0)
        undetected_hits = tool.get("results").get("undetected", 0)
        suspicious_hits = tool.get("results").get("suspicious", 0)
        harmless_hits = tool.get("results").get("harmless", 0)
        total_hits = int(malicious_hits) + int(undetected_hits) + int(suspicious_hits) + int(harmless_hits)

        if malicious_hits:
            return {"vt_hits": f"{malicious_hits}/{total_hits}"}
    # fmt: on


def country(tool):
    if tool.get("tool") == "ip_quality_score" and tool.get("results").get("country"):
        return {"country": tool.get("results").get("country")}


def mobile(tool):
    if tool.get("tool") == "ip_quality_score" and tool.get("results").get("mobile"):
        return {"mobile": tool.get("results").get("mobile")}


def tor(tool):
    if tool.get("tool") == "ip_quality_score" and tool.get("results").get("tor"):
        return {"tor": tool.get("results").get("tor")}


def proxy(tool):
    if tool.get("tool") == "ip_quality_score" and tool.get("results").get("proxy"):
        return {"proxy": tool.get("results").get("proxy")}


def data_breach(tool):
    if tool.get("tool") == "breach_directory" and tool.get("results").get("found"):
        return {"data_breach": True}


def connection_type(tool):
    if tool.get("tool") == "ip_quality_score" and tool.get("results").get(
        "connection_type"
    ):
        if not tool.get("results").get("connection_type") == "Premium required.":
            return {"connection_type": tool.get("results").get("connection_type")}
