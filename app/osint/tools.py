import requests
import xmltodict
import datetime
import ipwhois
import httpbl
import base64
import json
from .. import config, notifications
from ..models import FeedLists, Indicators
from maltiverse import Maltiverse
from shodan import Shodan
from urllib.parse import quote
from .utils import (
    no_results_found,
    failed_to_run,
    get_feedlist_type,
    remove_ip_address,
    convert_email_to_fqdn,
    convert_fqdn_to_url,
    convert_url_to_fqdn,
    missing_apikey,
)


def search_feedlists(indicator, db):
    def perform_search(indicator, feedlist, list_type):
        try:
            if indicator.indicator_type == "url":
                search_string = convert_url_to_fqdn(indicator.indicator)
            elif indicator.indicator_type == "email":
                search_string = convert_email_to_fqdn(indicator.indicator)
            else:
                search_string = indicator.indicator

            req = requests.get(feedlist.url)
            if req.status_code == 200:
                results = {}
                lines = req.text.splitlines()
                for line in lines:
                    line = remove_ip_address(line) if list_type == "fqdn" else line
                    if (
                        search_string in line
                        and not ("feedlist", feedlist.name) in results.items()
                    ):
                        results.update(
                            {
                                "feedlist_id": feedlist.id,
                                "match": line,
                                "feedlist": feedlist.name,
                                "description": feedlist.description,
                                "category": feedlist.category,
                                "list_period": feedlist.list_period,
                                "list_type": feedlist.list_type,
                                "url": feedlist.url,
                            }
                        )
            else:
                raise Exception("Did not get a 200 OK response from the feedlist.")

            if results:
                return results
            else:
                return None

        except Exception as e:
            raise Exception(
                f"Error during searching through {feedlist.name}(ID-{feedlist.id}) {str(e)} "
            )

    results = []

    list_type = get_feedlist_type(indicator)

    if list_type:
        feedlists_to_search = []

        list_type_match = FeedLists.get_active_feedlists_by_type(list_type, db)
        if list_type_match:
            for x in list_type_match:
                feedlists_to_search.append(x)

        any_type_lists = FeedLists.any_list_type_feedlists(db)
        if any_type_lists:
            for x in any_type_lists:
                feedlists_to_search.append(x)

        if not feedlists_to_search:
            return None

        notifications.console_output(
            f"{len(feedlists_to_search)} {list_type} feedlists enabled. Searching feedlists now",
            indicator,
            "BLUE",
        )

        for feedlist in feedlists_to_search:
            try:
                notifications.console_output(
                    f"Searching for indicator in {feedlist.name} - {feedlist.list_type}",
                    indicator,
                    "BLUE",
                )
                search_results = perform_search(indicator, feedlist, list_type)
                if search_results:
                    results.append(search_results)

            except Exception as e:
                notifications.console_output(str(e), indicator, "RED")
                continue

    if results:
        return Indicators.save_feedlist_results(indicator.id, results, db)
    else:
        return None


def ipinfoio(indicator):
    try:
        response = requests.get(f"https://ipinfo.io/{indicator.indicator}")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="ipinfo.io",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
            {
                "tool": "ipinfo.io",
                "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                "results": {
                    "city": response.json().get("city"),
                    "region": response.json().get("region"),
                    "geolocation": response.json().get("loc"),
                    "organization": response.json().get("org"),
                    "postal_code": response.json().get("postal"),
                    "timezone": response.json().get("timezone"),
                },
            },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="ipinfo.io", error_message=error_message)


def search_ipwhois(indicator):
    try:
        obj = ipwhois.IPWhois(indicator.indicator)
        return (
            # fmt: off
            {
                "tool": "ip_whois",
                "outcome": {"status": "results_found", "error_message": None, "status_code": None, "reason": None},
                "results": {
                    "asn_number": obj.lookup_rws().get("asn"),
                    "asn_registry": obj.lookup_rws().get("asn_registry"),
                    "asn_date": obj.lookup_rws().get("asn_date"),
                    "cidr": obj.lookup_rws().get("nets")[0].get("cidr"),
                    "description": obj.lookup_rws().get("nets")[0].get("description"),
                    "country": obj.lookup_rws().get("nets")[0].get("country"),
                    "state": obj.lookup_rws().get("nets")[0].get("state"),
                    "city": obj.lookup_rws().get("nets")[0].get("city"),
                    "address": obj.lookup_rws().get("nets")[0].get("address"),
                    "postal_code": obj.lookup_rws().get("nets")[0].get("postal_code"),
                    "abuse_emails": obj.lookup_rws().get("nets")[0].get("emails"),
                    "tech_emails": obj.lookup_rws().get("nets")[0].get("tech_emails"),
                },
            },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="ip_whois", error_message=error_message)


def ipqualityscore(indicator):
    try:
        if config["IPQS_API_KEY"] == "":
            return missing_apikey("ip_quality_score")

        response = requests.get(
            f"https://us.ipqualityscore.com/api/json/ip/{config['IPQS_API_KEY']}/{indicator.indicator}",
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="ip_quality_score",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "ip_quality_score",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "isp": response.json().get("ISP", ""),
                        "organization": response.json().get("organization", ""),
                        "country": response.json().get("country_code", ""),
                        "city": response.json().get("city", ""),
                        "mobile": response.json().get("mobile", ""),
                        "is_crawler": response.json().get("is_crawler", ""),
                        "connection_type": response.json().get("connection_type", ""),
                        "recent_abuse": response.json().get("recent_abuse", ""),
                        "bot_status": response.json().get("bot_status", ""),
                        "vpn": response.json().get("vpn", ""),
                        "active_vpn": response.json().get("active_vpn", ""),
                        "tor": response.json().get("tor", ""),
                        "active_tor": response.json().get("active_tor", ""),
                        "fraud_score": response.json().get("fraud_score", ""),
                        "abuse_velocity": response.json().get("abuse_velocity", ""), 
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="ip_quality_score", error_message=error_message)


def virustotal_ip(indicator):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            return missing_apikey("virustotal_ip")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{indicator.indicator}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("virustotal_ip")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="virustotal_ip",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "virustotal_ip",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "last analysis date": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("last_analysis_date")).strftime('%c') if response.json().get("data").get("attributes").get("last_analysis_date") else "",
                        "harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "reputation": response.json().get("data").get("attributes").get("reputation"),
                        "tags": response.json().get("data").get("attributes").get("tags"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="virustotal_ip", error_message=error_message)


def virustotal_domain(indicator):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            return missing_apikey("virustotal_domain")

        if indicator.indicator_type == "url":
            domain = convert_url_to_fqdn(indicator.indicator)
        elif indicator.indicator_type == "email":
            domain = convert_email_to_fqdn(indicator.indicator)
        else:
            domain = indicator.indicator

        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("virustotal_domain")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="virustotal_domain",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "virustotal_domain",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "whois": response.json().get("data").get("attributes").get("whois"),
                        "creation_date": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("creation_date")).strftime('%c') if response.json().get("data").get("attributes").get("creation_date") else "",
                        "whois_date": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("whois_date")).strftime('%c') if response.json().get("data").get("attributes").get("whois_date") else "",
                        "harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "categories": response.json().get("data").get("attributes").get("categories"),
                        "tld": response.json().get("data").get("attributes").get("tld"),
                        "tags": response.json().get("data").get("attributes").get("tags"),
                        "community_votes": response.json().get("data").get("attributes").get("total_votes"),
                        "last_analysis": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("last_analysis_date")).strftime('%c') if response.json().get("data").get("attributes").get("last_analysis_date") else ""
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="virustotal_domain", error_message=error_message)


def virustotal_url(indicator):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            return missing_apikey("virustotal_url")

        if indicator.indicator_type == "fqdn":
            url_id = (
                base64.urlsafe_b64encode(
                    convert_fqdn_to_url(indicator.indicator).encode()
                )
                .decode()
                .strip("=")
            )
        else:
            url_id = (
                base64.urlsafe_b64encode(indicator.indicator.encode())
                .decode()
                .strip("=")
            )

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("virustotal_url")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="virustotal_url",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "virustotal_url",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "url": response.json().get("data").get("attributes").get("url"),
                        "final_url": response.json().get("data").get("attributes").get("final_url"),
                        "last_response_code": response.json().get("data").get("attributes").get("last_http_response_code"),
                        "redirection_chain": response.json().get("data").get("attributes").get("redirection_chain"),
                        "tld": response.json().get("data").get("attributes").get("tld"),
                        "threat_names": response.json().get("data").get("attributes").get("threat_names"),
                        "tags": response.json().get("data").get("attributes").get("tags"),
                        "community_votes": response.json().get("data").get("attributes").get("total_votes"),
                        "categories": response.json().get("data").get("attributes").get("categories"),
                    },
                },
            # fmt: on
        )

    except Exception as error_message:
        return failed_to_run(tool_name="virustotal_url", error_message=error_message)


def virustotal_hash(indicator):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            return missing_apikey("virustotal_hash")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{indicator.indicator}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("virustotal_hash")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="virustotal_hash",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "virustotal_hash",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "suggested_threat_label": response.json().get("data").get("attributes").get("popular_threat_classification", {}).get("suggested_threat_label"),
                        "popular_threat_category": response.json().get("data").get("attributes").get("popular_threat_classification").get("popular_threat_category")[0].get("value") if response.json().get("data").get("attributes").get("popular_threat_classification", {}).get("popular_threat_category", []) else None,
                        "community_votes": response.json().get("data").get("attributes").get("total_votes"),
                        "name": response.json().get("data").get("attributes").get("meaningful_names"),
                        "names": response.json().get("data").get("attributes").get("names"),
                        "type": response.json().get("data").get("attributes").get("magic"),
                        "type_tag": response.json().get("data").get("attributes").get("type_tag"),
                        "tags": response.json().get("data").get("attributes").get("tags"),
                        "times_submitted": response.json().get("data").get("attributes").get("times_submitted"),
                        "product": response.json().get("data").get("attributes").get("signature_info", {}).get("product"),
                        "product_description": response.json().get("data").get("attributes").get("signature_info", {}).get("description"),
                        "signed": response.json().get("data").get("attributes").get("signature_info", {}).get("verified"),
                        "signing_date": response.json().get("data").get("attributes").get("signature_info", {}).get("signing date"),
                        "md5": response.json().get("data").get("attributes").get("md5"),
                        "sha1": response.json().get("data").get("attributes").get("sha1"),
                        "sha256": response.json().get("data").get("attributes").get("sha256"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="virustotal_hash", error_message=error_message)


def greynoise_community(indicator):
    try:
        if config["GREYNOISE_COMMUNITY_API_KEY"] == "":
            return missing_apikey("greynoise_community")
        params = {"apikey": config["GREYNOISE_COMMUNITY_API_KEY"]}
        response = requests.get(
            f"https://api.greynoise.io/v3/community/{indicator.indicator}",
            params=params,
        )

        if "IP not observed" in response.json().get("message"):
            return no_results_found("greynoise_community")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="greynoise_community",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "greynoise_community",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "classification": response.json().get("classification"),
                        "noise": response.json().get("noise"),
                        "riot": response.json().get("riot"),
                        "name": response.json().get("name"),
                        "last_seen": response.json().get("last_seen"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(
            tool_name="greynoise_community", error_message=error_message
        )


def hacked_ip_threatlist(indicator):
    try:
        response = requests.get(
            f"http://www.hackedip.com/api.php?ip={indicator.indicator}",
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="hacked_ip",
                status_code=response.status_code,
                reson=response.reason,
            )

        results_list = []
        for item in response.json():
            item.remove(indicator.indicator)
            for i in item:
                x = i.replace(f"{indicator.indicator}|", "")
                results_list.append(x)

        if not results_list:
            return no_results_found("hacked_ip")

        return (
            # fmt: off
                {
                    "tool": "hacked_ip",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "active_threatlists": results_list
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="hacked_ip", error_message=error_message)


def urlvoid(indicator):
    try:
        if config["APIVOID_API_KEY"] == "":
            return missing_apikey("url_void")

        if indicator.indicator_type == "fqdn":
            fqdn = convert_fqdn_to_url(indicator.indicator)
            response = requests.get(
                f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={config['APIVOID_API_KEY']}&host={fqdn}",
            )
        elif indicator.indicator_type == "url":
            url = indicator.indicator
            response = requests.get(
                f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={config['APIVOID_API_KEY']}&url={url}",
            )
        elif indicator.indicator_type == "email":
            fqdn = convert_email_to_fqdn(indicator.indicator)
            response = requests.get(
                f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={config['APIVOID_API_KEY']}&host={fqdn}",
            )
        else:
            raise Exception("Invalid indicator type for URLVoid")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="url_void",
                status_code=response.status_code,
                reason=response.reason,
            )

        blacklists = (
            response.json()
            .get("data", {})
            .get("report", {})
            .get("domain_blacklist", {})
            .get("engines")
        )
        blacklists_list = []

        for each in blacklists if blacklists else []:
            if each.get("detected") == True and each.get("name") not in blacklists_list:
                blacklists_list.append(each.get("name"))

        security_checks = (
            response.json().get("data", {}).get("report", {}).get("security_checks", {})
        )
        security_checks_list = []
        if security_checks:
            for k, v in security_checks.items():
                if v == True and k not in security_checks_list:
                    security_checks_list.append(k)

            return (
                # fmt: off
                    {
                        "tool": "url_void",
                        "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                        "results": {
                            "dns_records": response.json().get("data", {}).get("report", {}).get("dns_records", {}).get("mx", {}).get("records", []),
                            "detections": response.json().get("data", {}).get("report", {}).get("domain_blacklist", {}).get("detections"),
                            "scanners_detected": blacklists_list,
                            "security_checks": security_checks_list,
                            "risk_score": response.json().get("data", {}).get("report", {}).get("risk_score", "").get("result"),
                            "redirection": response.json().get("data", {}).get("report", {}).get("redirection", {}),
                        },
                    },
                # fmt: on
            )
        else:
            return no_results_found("url_void")

    except Exception as error_message:
        return failed_to_run(tool_name="url_void", error_message=error_message)


def macvendors(indicator):
    try:
        response = requests.get(f"https://api.macvendors.com/{indicator.indicator}")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="mac_vendors",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
            {
                "tool": "mac_vendors",
                "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                "results": {
                    "manufacturer": response.text,
                },
            },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="mac_vendors", error_message=error_message)


def stopforumspam_email(indicator):
    try:
        response = requests.get(
            f"http://api.stopforumspam.org/api?email={indicator.indicator}",
        )
        results = xmltodict.parse(response.text)

        if response.status_code != 200:
            return failed_to_run(
                tool_name="stop_forum_spam_email",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "stop_forum_spam_email",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "appears": results.get("response", {}).get("appears"),
                        "frequency": results.get("response", {}).get("frequency")
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(
            tool_name="stop_forum_spam_email", error_message=error_message
        )


def stopforumspam_ip(indicator):
    try:
        response = requests.get(
            f"http://api.stopforumspam.org/api?ip={indicator.indicator}",
        )
        results = xmltodict.parse(response.text)

        if response.status_code != 200:
            return failed_to_run(
                tool_name="stop_forum_spam_ip",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "stop_forum_spam_ip",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "appears": results.get("response", {}).get("appears"),
                        "frequency": results.get("response", {}).get("frequency")
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(
            tool_name="stop_forum_spam_ip", error_message=error_message
        )


def abuse_ipdb(indicator):
    try:
        if config["AB_API_KEY"] == "":
            return missing_apikey("abuseipdb")

        response = requests.request(
            method="GET",
            url="https://api.abuseipdb.com/api/v2/check",
            headers={
                "Accept": "application/json",
                "Key": config["AB_API_KEY"],
            },
            params={"ipAddress": indicator.indicator, "maxAgeInDays": "180"},
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="abuseipdb",
                status_code=response.status_code,
                reason=response.reason,
            )

        # fmt: off
        return (
            {
                "tool": "abuseipdb",
                "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                "results": {
                    "reports": response.json().get("data", {}).get("totalReports"),
                    "abuse_score": response.json().get("data", {}).get("abuseConfidenceScore"),
                    "last_report": response.json().get("data", {}).get("lastReportedAt"),
                },
            },
        )
        # fmt: on

    except Exception as error_message:
        return failed_to_run(tool_name="abuseipdb", error_message=error_message)


def emailrepio(indicator):
    try:
        if config["EMAILREP_API_KEY"] == "":
            return missing_apikey("emailrep.io")
        header = {"Key": config["EMAILREP_API_KEY"]}
        response = requests.get(
            f"https://emailrep.io/{indicator.indicator}",
            headers=header,
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="emailrep.io",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "emailrep.io",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "reputation": response.json().get("reputation"),
                        "suspicious": response.json().get("suspicious"),
                        "references": response.json().get("references"),
                        "blacklisted": response.json().get("details",{}).get("blacklisted"),
                        "malicious_activity": response.json().get("details",{}).get("malicious_activity"),
                        "malicious_activity_recent": response.json().get("details",{}).get("malicious_activity_recent"),
                        "credential_leaked": response.json().get("details",{}).get("credentials_leaked"),
                        "credentials_leaked_recent": response.json().get("details",{}).get("credentials_leaked_recent"),
                        "data_breach": response.json().get("details",{}).get("data_breach"),
                        "first_seen": response.json().get("details",{}).get("first_seen"),
                        "last_seen": response.json().get("details",{}).get("last_seen"),
                        "domain_exists": response.json().get("details",{}).get("domain_exists"),
                        "domain_reputation": response.json().get("details",{}).get("domain_reputation"),
                        "new_domain": response.json().get("details",{}).get("new_domain"),
                        "days_since_domain_creation": response.json().get("details",{}).get("days_since_domain_creation"),
                        "suspicious_tld": response.json().get("details",{}).get("suspicious_tld"),
                        "spam": response.json().get("details",{}).get("spam"),
                        "free_provider": response.json().get("details",{}).get("free_provider"),
                        "disposable": response.json().get("details",{}).get("disposable"),
                        "deliverable": response.json().get("details",{}).get("deliverable"),
                        "accept_all": response.json().get("details",{}).get("accept_all"),
                        "valid_mx": response.json().get("details",{}).get("valid_mx"),
                        "primary_mx": response.json().get("details",{}).get("primary_mx"),
                        "spoofable": response.json().get("details",{}).get("spoofable"),
                        "spf_strict": response.json().get("details",{}).get("spf_strict"),
                        "dmar_enforced": response.json().get("details",{}).get("dmarc_enforced"),
                        "profiles": response.json().get("details",{}).get("profiles",[]),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="emailrep.io", error_message=error_message)


def tweetfeed_live(indicator):
    def query_api(url):
        try:
            return requests.get(url)
        except Exception as error_message:
            raise Exception(f"Failed to query API {str(e)}")

    try:
        results = {}

        if indicator.indicator_type == "ipv4":
            response = query_api("https://api.tweetfeed.live/v1/month/ip")
        elif indicator.indicator_type == "fqdn":
            response = query_api("https://api.tweetfeed.live/v1/month/domain")
        elif indicator.indicator_type == "url":
            response = query_api("https://api.tweetfeed.live/v1/month/url")
        elif indicator.indicator_type == "hash.md5":
            response = query_api("https://api.tweetfeed.live/v1/month/md5")
        elif indicator.indicator_type == "hash.sha256":
            response = query_api("https://api.tweetfeed.live/v1/month/sha256")
        else:
            response = None

        if response.status_code != 200:
            return failed_to_run(
                tool_name="tweetfeed.live",
                status_code=response.status_code,
                reason=response.reason,
            )

        if response.json():
            for each in response.json():
                if indicator.indicator in each["value"]:
                    results.update(each)

        if not results:
            return no_results_found("tweetfeed.live")

        return (
            {
                "tool": "tweetfeed.live",
                "outcome": {
                    "status": "results_found",
                    "error_message": None,
                    "status_code": response.status_code,
                    "reason": response.reason,
                },
                "results": results,
            },
        )
    except Exception as error_message:
        return failed_to_run(tool_name="tweetfeed.live", error_message=error_message)


def urlscanio(indicator):
    try:
        if indicator.indicator_type == "url":
            domain = convert_url_to_fqdn(indicator.indicator)
        else:
            domain = indicator.indicator

        response = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="urlscan.io",
                status_code=response.status_code,
                reason=response.reason,
            )

        if not response.json().get("results"):
            return no_results_found("urlscan.io")

        last_scan_response = {}
        for scan in response.json().get("results"):
            if domain in scan.get("task").get("domain"):
                last_scan_response = requests.get(
                    f"https://urlscan.io/api/v1/result/{scan.get('task').get('uuid')}/",
                )
                break

        if not last_scan_response:
            return no_results_found("urlscan.io")

        return (
            # fmt: off
                {
                    "tool": "urlscan.io",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "last_scan_guid": last_scan_response.json().get("task").get("uuid"),
                        "last_scan_url": last_scan_response.json().get("task").get("reportURL"),
                        "last_scan_time": last_scan_response.json().get("task").get("time"),
                        "last_scan_score": last_scan_response.json().get("verdicts").get("overall").get("score"),
                        "categories": last_scan_response.json().get("verdicts").get("overall").get("categories"),
                        "malicious": last_scan_response.json().get("verdicts").get("overall").get("malicious"),
                        "tags": last_scan_response.json().get("verdicts").get("overall").get("tags"),
                        "last_scan_screenshot": last_scan_response.json().get("task").get("screenshotURL"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="urlscan.io", error_message=error_message)


def circl_lu(indicator):
    try:
        if indicator.indicator_type == "hash.md5":
            response = requests.get(
                f"https://hashlookup.circl.lu/lookup/md5/{indicator.indicator}",
            )
        elif indicator.indicator_type == "hash.sha1":
            response = requests.get(
                f"https://hashlookup.circl.lu/lookup/sha1/{indicator.indicator}",
            )
        elif indicator.indicator_type == "hash.sha256":
            response = requests.get(
                f"https://hashlookup.circl.lu/lookup/sha256/{indicator.indicator}",
            )

        if "Non existing" in response.json().get("message", ""):
            return no_results_found("circl.lu")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="circl.lu",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "circl.lu",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "file_name": response.json().get("FileName"),
                        "file_size_kb": response.json().get("FileSize"),
                        "product_code": response.json().get("ProductCode"),
                        "mimetype": response.json().get("mimetype"),
                        "source": response.json().get("source"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="circl.lu", error_message=error_message)


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


def echo_trail(indicator):
    try:
        if config["ECHOTRAIL_API_KEY"] == "":
            return missing_apikey("echo_trail")

        response = requests.get(
            f"https://api.echotrail.io/v1/insights/{indicator.indicator}",
            headers={
                "X-Api-Key": str(config["ECHOTRAIL_API_KEY"]),
                "Content-Type": "application/json",
            },
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="echo_trail",
                status_code=response.status_code,
                reason=response.reason,
            )

        if "EchoTrail has never observed" in response.json().get("message", ""):
            return no_results_found("echo_trail")

        return (
            # fmt: off
                {
                    "tool": "echo_trail",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "file_name": response.json().get("filenames"),
                        "description": response.json().get("description"),
                        "intel": response.json().get("intel"),
                        "parents": response.json().get("parents"),
                        "children": response.json().get("children"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="echo_trail", error_message=error_message)


def hybrid_analysis(indicator):
    # https://www.hybrid-analysis.com/docs/api/v2
    try:
        if config["HYBRID_ANALYSIS_API_KEY"] == "":
            return missing_apikey("hybrid_analysis")

        response = requests.post(
            f"https://hybrid-analysis.com/api/v2/search/hash",
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
                reason=response.reason,
            )

        if not response.json():
            return no_results_found("hybrid_analysis")

        response = response.json()[0]
        return (
            # fmt: off
                {
                    "tool": "hybrid_analysis",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": None, "reason": None},
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
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="hybrid_analysis", error_message=error_message)


def breach_directory(indicator):
    try:
        if config["BREACH_DIRECTORY_API_KEY"] == "":
            return missing_apikey("breach_directory")

        response = requests.get(
            "https://breachdirectory.p.rapidapi.com/",
            headers={
                "X-RapidAPI-Key": config["BREACH_DIRECTORY_API_KEY"],
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            },
            params={"func": "auto", "term": indicator.indicator},
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="breach_directory",
                status_code=response.status_code,
                reason=response.reason,
            )

        if not response.json().get("result", []):
            return no_results_found("breach_directory")

        return (
            # fmt: off
                {
                    "tool": "breach_directory",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "found": response.json().get("found", {}),
                        "frequency": response.json().get("result", [])
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="breach_directory", error_message=error_message)


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


def malware_bazzar(indicator):
    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": indicator.indicator},
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="malware_bazzar",
                status_code=response.status_code,
                reason=response.reason,
            )

        if not response.json().get("query_status") == "ok":
            return no_results_found("malware_bazzar")

        return (
            # fmt: off
                {
                    "tool": "malware_bazzar",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "file_type": response.json().get("data")[0].get("file_type"),
                        "signature": response.json().get("data")[0].get("signature"),
                        "file_name": response.json().get("data")[0].get("file_name"),
                        "delivery_method": response.json().get("delivery_method"),
                        "tags": response.json().get("tags"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="malware_bazzar", error_message=error_message)


def inquestlabs(indicator):
    try:
        hash_type = None
        kind = None
        if indicator.indicator_type == "hash.md5":
            hash_type = "md5"
        elif indicator.indicator_type == "hash.sha1":
            hash_type = "sha1"
        elif indicator.indicator_type == "hash.sha256":
            hash_type = "sha256"
        elif indicator.indicator_type == "hash.sha512":
            hash_type = "sha512"
        elif indicator.indicator_type == "fqdn":
            kind = "domain"
        elif indicator.indicator_type == "email":
            kind = "email"
        elif indicator.indicator_type == "ipv4":
            kind = "ip"
        elif indicator.indicator_type == "url":
            kind = "url"

        if hash_type:
            response = requests.get(
                f"https://labs.inquest.net/api/dfi/search/hash/{hash_type}",
                params={"hash": f"{indicator.indicator}"},
                headers={"accept": "application/json"},
            )

        elif kind:
            response = requests.get(
                f"https://labs.inquest.net/api/dfi/search/ioc/{kind}",
                params={"keyword": f"{indicator.indicator}"},
                headers={"accept": "application/json"},
            )

        else:
            raise Exception("Invalid indicator type for inquest_labs")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="inquest_labs",
                status_code=response.status_code,
                reason=response.reason,
            )

        if response.json().get("success") is False:
            return no_results_found("inquest_labs")

        if not response.json().get("data"):
            return no_results_found("inquest_labs")

        return (
            # fmt: off
                {
                    "tool": "inquest_labs",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "classification": response.json().get("data", [])[0].get("classification"),
                        "file_type": response.json().get("data", [])[0].get("file_type"),
                        "first_seen": response.json().get("data", [])[0].get("first_seen"),
                        "inquest_alerts": response.json().get("data", [])[0].get("inquest_alerts"),
                        "mime_type": response.json().get("data", [])[0].get("mime_type"),
                        "subcategory": response.json().get("data", [])[0].get("subcategory"),
                        "subcategory_url": response.json().get("data", [])[0].get("subcategory_url"),
                        "tags": response.json().get("data", [])[0].get("tags"),
                    },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="inquest_labs", error_message=error_message)


def maltiverse(indicator):
    try:
        if config["MALTIVERSE_API_KEY"] == "":
            return missing_apikey("maltiverse")

        maltiverse = Maltiverse(auth_token=config["MALTIVERSE_API_KEY"])

        if indicator.indicator_type == "hash.md5":
            result = maltiverse.sample_get_by_md5(indicator.indicator)

        elif indicator.indicator_type == "hash.sha1":
            result = maltiverse.sample_get_by_sha1(indicator.indicator)

        elif indicator.indicator_type == "hash.sha256":
            result = maltiverse.sample_get_by_sha256(indicator.indicator)

        elif indicator.indicator_type == "hash.sha512":
            result = maltiverse.sample_get_by_sha512(indicator.indicator)

        elif indicator.indicator_type == "fqdn":
            result = maltiverse.hostname_get(indicator.indicator)

        elif indicator.indicator_type == "ipv4":
            result = maltiverse.ip_get(indicator.indicator)

        elif indicator.indicator_type == "url":
            result = maltiverse.url_get(indicator.indicator)

        else:
            raise Exception("Invalid indicator type for maltiverse")

        if not result:
            raise no_results_found("maltiverse")

        if not result.get("classification", ""):
            return no_results_found("maltiverse")

        if (
            result.get("classification", "") == "neutral"
            and not result.get("blacklist", [])
            and not result.get("tag", [])
        ):
            return no_results_found("maltiverse")

        return (
            # fmt: off
                {
                    "tool": "maltiverse",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": None, "reason": None},
                    "results": {
                        "classification": result.get("classification", ""),
                        "blacklist": result.get("blacklist", []),
                        "tags": result.get("tag", []),

                        },
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="maltiverse", error_message=error_message)


def numverify(indicator):
    try:
        if config["NUMVERIFY_API_KEY"] == "":
            return missing_apikey("numverify")

        response = requests.get(
            f"http://apilayer.net/api/validate?access_key={config['NUMVERIFY_API_KEY']}&number={indicator.indicator}&format=1"
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="numverify",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "numverify",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": response.json()
                },
            # fmt: on
        )

    except Exception as error_message:
        return failed_to_run(tool_name="numverify", error_message=error_message)


def ipqualityscore_phone(indicator):
    try:
        if config["IPQS_API_KEY"] == "":
            return missing_apikey("ipqualityscore")

        response = requests.get(
            f"https://us.ipqualityscore.com/api/json/phone/{config['IPQS_API_KEY']}/{indicator.indicator}",
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="ip_quality_score_phone",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "ip_quality_score_phone",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(
            tool_name="ip_quality_score_phone", error_message=error_message
        )


def wayback_machine(indicator):
    try:
        if indicator.indicator_type == "fqdn":
            response = requests.get(
                f"http://archive.org/wayback/available?url={indicator.indicator}",
            )
        elif indicator.indicator_type == "email":
            response = requests.get(
                f"http://archive.org/wayback/available?url={convert_email_to_fqdn(indicator.indicator)}"
            )
        elif indicator.indicator_type == "url":
            response = requests.get(
                f"http://archive.org/wayback/available?url={convert_url_to_fqdn(indicator.indicator)}"
            )
        else:
            raise Exception("Invalid indicator type for wayback")

        if response.status_code != 200:
            return failed_to_run(
                tool_name="wayback_machine",
                status_code=response.status_code,
                reason=response.reason,
            )

        if not response.json().get("archived_snapshots"):
            return no_results_found("wayback_machine")

        return (
            # fmt: off
                {
                    "tool": "wayback_machine",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": response.json().get("archived_snapshots", {}).get("closest")
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="wayback_machine", error_message=error_message)


def kickbox_disposible_email(indicator):
    try:
        response = requests.get(
            f"https://open.kickbox.com/v1/disposable/{indicator.indicator}",
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="kickbox_disposible_email",
                status_code=response.status_code,
                reason=response.reason,
            )

        if not response.json().get("disposable"):
            return no_results_found("kickbox_disposible_email")

        return (
            # fmt: off
                {
                    "tool": "kickbox_disposible_email",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": response.json().get("disposable", {})
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(
            tool_name="kickbox_disposible_email", error_message=error_message
        )


def whatsmybrowser_ua(indicator):
    try:
        if config["WHATSMYBROWSER_API_KEY"] == "":
            return missing_apikey("whatsmybrowser")

        response = requests.post(
            "https://api.whatismybrowser.com/api/v2/user_agent_parse",
            data=json.dumps(
                {
                    "user_agent": indicator.indicator,
                    "parse_options": {},
                }
            ),
            headers={
                "X-API-KEY": config["WHATSMYBROWSER_API_KEY"],
            },
        )

        if response.status_code != 200:
            return failed_to_run(
                tool_name="whatsmybrowser_ua",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "whatsmybrowser_ua",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": {
                        "is_abusive": response.json().get("parse", {}).get("is_abusive"),
                        "simple_software_string": response.json().get("parse", {}).get("simple_software_string"),
                        "software": response.json().get("parse", {}).get("software"),
                        "software_name": response.json().get("parse", {}).get("software_name"),
                        "software_version": response.json().get("parse", {}).get("software_version"),
                        "software_version_full": response.json().get("parse", {}).get("software_version_full"),
                        "operating_system": response.json().get("parse", {}).get("operating_system"),
                        "operating_system_name": response.json().get("parse", {}).get("operating_system_name"),
                        "operating_system_version_full": response.json().get("parse", {}).get("operating_system_version_full"),
                    }
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="whatsmybrowser_ua", error_message=error_message)


def shimon(indicator):
    try:
        if indicator.indicator_type == "fqdn":
            encoded_url = quote(convert_fqdn_to_url(indicator.indicator), safe="")
        elif indicator.indicator_type == "url":
            encoded_url = quote(indicator.indicator, safe="")
        else:
            raise Exception("Invalid indicator type for shimon")

        response = requests.get(
            f"https://shimon-6983d71a338d.herokuapp.com/api/fingerprint/calculate?url={encoded_url}",
            headers={"accept": "application/json"},
        )

        if response.status_code == 500:
            return no_results_found("shimon")
        if response.status_code != 200:
            return failed_to_run(
                tool_name="shimon",
                status_code=response.status_code,
                reason=response.reason,
            )

        return (
            # fmt: off
                {
                    "tool": "shimon",
                    "outcome": {"status": "results_found", "error_message": None, "status_code": response.status_code, "reason": response.reason},
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as error_message:
        return failed_to_run(tool_name="shimon", error_message=error_message)
