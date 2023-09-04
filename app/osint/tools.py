import requests
import xmltodict
import datetime
import ipwhois
import httpbl
import time
import base64
from .. import config, notifications
from ..models import FeedLists
from maltiverse import Maltiverse
from shodan import Shodan
from .utils import (
    no_results_found,
    failed_to_run,
    status_code_error,
    get_feedlist_type,
    remove_ip_address,
    convert_email_to_fqdn,
    convert_fqdn_to_url,
    convert_url_to_fqdn,
)


def search_feedlists(indicator, db):
    def perform_search(indicator, feedlist, list_type):
        try:
            req = requests.get(feedlist.url)
            if req.status_code == 200:
                results = {}
                lines = req.text.splitlines()
                for line in lines:
                    line = remove_ip_address(line) if list_type == "fqdn" else line
                    if (
                        indicator.indicator in line
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
        feedlists = FeedLists.get_active_feedlists_by_type(list_type, db)

        if not feedlists:
            return None

        notifications.console_output(
            f"{len(feedlists)} {list_type} feedlists enabled. Searching feedlists now",
            indicator,
            "BLUE",
        )

        for feedlist in feedlists:
            try:
                search_results = perform_search(indicator, feedlist, list_type)
                if search_results:
                    results.append(search_results)

            except Exception as e:
                notifications.console_output(str(e), indicator, "RED")
                continue

    if results:
        notifications.console_output(
            f"{len(results)} feedlist matches found", indicator, "BLUE"
        )
        return results
    else:
        return None


def ipinfoio(indicator):
    try:
        response = requests.get(f"https://ipinfo.io/{indicator.indicator}")

        if response.status_code != 200:
            return status_code_error("IPinfo.io", response.status_code, response.reason)

        return (
            # fmt: off
            {
                "site": "IPinfo.io",
                "results": {
                    "City": response.json().get("city"),
                    "Region": response.json().get("region"),
                    "GeoLocation": response.json().get("loc"),
                    "Organization": response.json().get("org"),
                    "Postal": response.json().get("postal"),
                    "Timezone": response.json().get("timezone"),
                },
            },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("IPinfo.io", e)


def search_ipwhois(indicator):
    try:
        obj = ipwhois.IPWhois(indicator.indicator)
        return (
            {
                "site": "IP Whois",
                "results": {
                    "ASN Number": obj.lookup_rws().get("asn"),
                    "ASN Registry": obj.lookup_rws().get("asn_registry"),
                    "ASN Date": obj.lookup_rws().get("asn_date"),
                    "CIDR": obj.lookup_rws().get("nets")[0].get("cidr"),
                    "Description": obj.lookup_rws().get("nets")[0].get("description"),
                    "Country": obj.lookup_rws().get("nets")[0].get("country"),
                    "State": obj.lookup_rws().get("nets")[0].get("state"),
                    "City": obj.lookup_rws().get("nets")[0].get("city"),
                    "Address": obj.lookup_rws().get("nets")[0].get("address"),
                    "Postal Code": obj.lookup_rws().get("nets")[0].get("postal_code"),
                    "Abuse Emails": obj.lookup_rws().get("nets")[0].get("emails"),
                    "Tech Emails": obj.lookup_rws().get("nets")[0].get("tech_emails"),
                },
            },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("IP Whois", e)


def ipqualityscore(indicator):
    try:
        if config["IPQS_API_KEY"] == "":
            raise Exception("IPQS_API_KEY is not set in .env file.")

        response = requests.get(
            f"https://us.ipqualityscore.com/api/json/ip/{config['IPQS_API_KEY']}/{indicator.indicator}",
        )

        if response.status_code != 200:
            return status_code_error(
                "IP Quality Score", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "IP Quality Score",
                    "results": {
                        "ISP": response.json().get("ISP", ""),
                        "Organization": response.json().get("organization", ""),
                        "Country": response.json().get("country_code", ""),
                        "City": response.json().get("city", ""),
                        "Mobile": response.json().get("mobile", ""),
                        "Is Crawler": response.json().get("is_crawler", ""),
                        "Connection Type": response.json().get("connection_type", ""),
                        "Recent Abuse": response.json().get("recent_abuse", ""),
                        "Bot Status": response.json().get("bot_status", ""),
                        "VPN": response.json().get("vpn", ""),
                        "Active VPN": response.json().get("active_vpn", ""),
                        "TOR": response.json().get("tor", ""),
                        "Active Tor": response.json().get("active_tor", ""),
                        "Fraud Score": response.json().get("fraud_score", ""),
                        "Abuse Velocity": response.json().get("abuse_velocity", ""),
                        
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("IP Quality Score", e)


def virustotal_ip(indicator):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            raise Exception("VIRUSTOTAL_API_KEY is not set in .env file.")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{indicator.indicator}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("VirusTotal IP")

        if response.status_code != 200:
            return status_code_error(
                "VirusTotal IP", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "VirusTotal IP",
                    "results": {
                        "Last Analysis Date": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("last_analysis_date")).strftime('%c') if response.json().get("data").get("attributes").get("last_analysis_date") else "",
                        "Harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "Malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "Suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "Undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "Reputation": response.json().get("data").get("attributes").get("reputation"),
                        "Tags": response.json().get("data").get("attributes").get("tags"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("VirusTotal IP", e)


def virustotal_domain(indicator):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            raise Exception("VIRUSTOTAL_API_KEY is not set in .env file.")

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
            return no_results_found("VirusTotal Domain")

        if response.status_code != 200:
            return status_code_error(
                "VirusTotal Domain", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "VirusTotal Domain",
                    "results": {
                        "Whois": response.json().get("data").get("attributes").get("whois"),
                        "Creation Date": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("creation_date")).strftime('%c') if response.json().get("data").get("attributes").get("creation_date") else "",
                        "Whois Date": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("whois_date")).strftime('%c') if response.json().get("data").get("attributes").get("whois_date") else "",
                        "Harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "Malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "Suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "Undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "Categories": response.json().get("data").get("attributes").get("categories"),
                        "TLD": response.json().get("data").get("attributes").get("tld"),
                        "Tags": response.json().get("data").get("attributes").get("tags"),
                        "Community Votes": response.json().get("data").get("attributes").get("total_votes"),
                        "Categories": response.json().get("data").get("attributes").get("categories"),
                        "Last Analysis": datetime.datetime.fromtimestamp(response.json().get("data").get("attributes").get("last_analysis_date")).strftime('%c') if response.json().get("data").get("attributes").get("last_analysis_date") else ""
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("VirusTotal Domain", e)


def virustotal_url(indicator):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            raise Exception("VIRUSTOTAL_API_KEY is not set in .env file.")

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
            return no_results_found("VirusTotal URL")

        if response.status_code != 200:
            return status_code_error(
                "VirusTotal URL", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "VirusTotal URL",
                    "results": {
                        "Harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "Malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "Suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "Undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "URL": response.json().get("data").get("attributes").get("url"),
                        "Final URL": response.json().get("data").get("attributes").get("final_url"),
                        "Last Response Code": response.json().get("data").get("attributes").get("last_http_response_code"),
                        "Redirection Chain": response.json().get("data").get("attributes").get("redirection_chain"),
                        "TLD": response.json().get("data").get("attributes").get("tld"),
                        "Threat Names": response.json().get("data").get("attributes").get("threat_names"),
                        "Tags": response.json().get("data").get("attributes").get("tags"),
                        "Community Votes": response.json().get("data").get("attributes").get("total_votes"),
                        "Categories": response.json().get("data").get("attributes").get("categories"),
                    },
                },
            # fmt: on
        )

    except Exception as e:
        return failed_to_run("VirusTotal URL", e)


def virustotal_hash(indicator):
    try:
        if config["VIRUSTOTAL_API_KEY"] == "":
            raise Exception("VIRUSTOTAL_API_KEY is not set in .env file.")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{indicator.indicator}",
            headers={
                "x-apikey": config["VIRUSTOTAL_API_KEY"],
                "Accept": "application/json",
            },
        )

        if response.json().get("error", {}).get("code"):
            return no_results_found("VirusTotal Hash")

        if response.status_code != 200:
            return status_code_error(
                "VirusTotal Hash", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "VirusTotal Hash",
                    "results": {
                        "Harmless": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("harmless"),
                        "Malicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("malicious"),
                        "Suspicious": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("suspicious"),
                        "Undetected": response.json().get("data").get("attributes").get("last_analysis_stats", {}).get("undetected"),
                        "Suggested Threat Label": response.json().get("data").get("attributes").get("popular_threat_classification", {}).get("suggested_threat_label"),
                        "Popular Threat Category": response.json().get("data").get("attributes").get("popular_threat_classification").get("popular_threat_category")[0].get("value") if response.json().get("data").get("attributes").get("popular_threat_classification", {}).get("popular_threat_category", []) else None,
                        "Community Votes": response.json().get("data").get("attributes").get("total_votes"),
                        "Name": response.json().get("data").get("attributes").get("meaningful_names"),
                        "Names": response.json().get("data").get("attributes").get("names"),
                        "Type": response.json().get("data").get("attributes").get("magic"),
                        "Type Tag": response.json().get("data").get("attributes").get("type_tag"),
                        "Tags": response.json().get("data").get("attributes").get("tags"),
                        "Times Submitted": response.json().get("data").get("attributes").get("times_submitted"),
                        "Product": response.json().get("data").get("attributes").get("signature_info", {}).get("product"),
                        "Product Description": response.json().get("data").get("attributes").get("signature_info", {}).get("description"),
                        "Signed": response.json().get("data").get("attributes").get("signature_info", {}).get("verified"),
                        "Signing Date": response.json().get("data").get("attributes").get("signature_info", {}).get("signing date"),
                        "MD5": response.json().get("data").get("attributes").get("md5"),
                        "SHA1": response.json().get("data").get("attributes").get("sha1"),
                        "SHA256": response.json().get("data").get("attributes").get("sha256"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("VirusTotal Hash", e)


def greynoise_community(indicator):
    try:
        if config["GREYNOISE_COMMUNITY_API_KEY"] == "":
            raise Exception("GREYNOISE_COMMUNITY_API_KEY is not set in .env file.")
        params = {"apikey": config["GREYNOISE_COMMUNITY_API_KEY"]}
        response = requests.get(
            f"https://api.greynoise.io/v3/community/{indicator.indicator}",
            params=params,
        )

        if "IP not observed" in response.json().get("message"):
            return no_results_found("Greynoise Community")

        if response.status_code != 200:
            return status_code_error(
                "Greynoise Community", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "Greynoise Community",
                    "results": {
                        "Classification": response.json().get("classification"),
                        "Noise": response.json().get("noise"),
                        "Riot": response.json().get("riot"),
                        "Name": response.json().get("name"),
                        "Last Seen": response.json().get("last_seen"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Greynoise Community", e)


def hacked_ip_threatlist(indicator):
    try:
        response = requests.get(
            f"http://www.hackedip.com/api.php?ip={indicator.indicator}",
        )

        if response.status_code != 200:
            return status_code_error("Hacked IP", response.status_code, response.reason)

        results_list = []
        for item in response.json():
            item.remove(indicator.indicator)
            for i in item:
                x = i.replace(f"{indicator.indicator}|", "")
                results_list.append(x)

        if not results_list:
            return no_results_found("Hacked IP")

        return (
            # fmt: off
                {
                    "site": "Hacked IP",
                    "results": {
                        "Active Threatlists": results_list
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Hacked IP", e)


def urlvoid(indicator):
    try:
        if config["APIVOID_API_KEY"] == "":
            raise Exception("APIVOID_API_KEY is not set in .env file.")

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
            return status_code_error("URL Void", response.status_code, response.reason)

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
                        "site": "URL Void",
                        "results": {
                            "DNS Records": response.json().get("data", {}).get("report", {}).get("dns_records", {}).get("mx", {}).get("records", []),
                            "Detections": response.json().get("data", {}).get("report", {}).get("domain_blacklist", {}).get("detections"),
                            "Scanners Detected": blacklists_list,
                            "Security Checks": security_checks_list,
                            "Risk Score": response.json().get("data", {}).get("report", {}).get("risk_score", "").get("result"),
                            "Redirection": response.json().get("data", {}).get("report", {}).get("redirection", {}),
                        },
                    },
                # fmt: on
            )
        else:
            return no_results_found("URL Void")

    except Exception as e:
        return failed_to_run("URL Void", e)


def macvendors(indicator):
    try:
        response = requests.get(f"https://api.macvendors.com/{indicator.indicator}")

        if response.status_code != 200:
            return status_code_error(
                "MAC Vendors", response.status_code, response.reason
            )

        return (
            {
                "site": "MAC Vendors",
                "results": {
                    "Manufacturer": response.text,
                },
            },
        )
    except Exception as e:
        return failed_to_run("MAC Vendors", e)


def stopforumspam_email(indicator):
    try:
        response = requests.get(
            f"http://api.stopforumspam.org/api?email={indicator.indicator}",
        )
        results = xmltodict.parse(response.text)

        if response.status_code != 200:
            return status_code_error(
                "Stop Forum Spam IP", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "Stop Forum Spam Email",
                    "results":{
                        "Appears": results.get("response", {}).get("appears"),
                        "Frequency": results.get("response", {}).get("frequency")
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Stop Forum Spam Email", e)


def stopforumspam_ip(indicator):
    try:
        response = requests.get(
            f"http://api.stopforumspam.org/api?ip={indicator.indicator}",
        )
        results = xmltodict.parse(response.text)

        if response.status_code != 200:
            return status_code_error(
                "Stop Forum Spam IP", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "Stop Forum Spam IP",
                    "results":{
                        "Appears": results.get("response", {}).get("appears"),
                        "Frequency": results.get("response", {}).get("frequency")
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Stop Forum Spam IP", e)


def abuse_ipdb(indicator):
    try:
        if config["AB_API_KEY"] == "":
            raise Exception("AB_API_KEY is not set in .env file.")

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
            return status_code_error("AbuseIPDB", response.status_code, response.reason)

        # fmt: off
        return (
            {
                "site": "AbuseIPDB",
                "results": {
                    "Reports": response.json().get("data", {}).get("totalReports"),
                    "Abuse Score": response.json().get("data", {}).get("abuseConfidenceScore"),
                    "Last Report": response.json().get("data", {}).get("lastReportedAt"),
                },
            },
        )
        # fmt: on

    except Exception as e:
        return failed_to_run("AbuseIPDB", e)


def emailrepio(indicator):
    try:
        if config["EMAILREP_API_KEY"] == "":
            raise Exception("EMAILREP_API_KEY is not set in .env file.")
        header = {"Key": config["EMAILREP_API_KEY"]}
        response = requests.get(
            f"https://emailrep.io/{indicator.indicator}",
            headers=header,
        )

        if response.status_code != 200:
            return status_code_error(
                "Emailrep.io", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "Emailrep.io",
                    "results": {
                        "Reputation": response.json().get("reputation"),
                        "Suspicious": response.json().get("suspicious"),
                        "References": response.json().get("references"),
                        "Blacklisted": response.json().get("details",{}).get("blacklisted"),
                        "Malicious Activity": response.json().get("details",{}).get("malicious_activity"),
                        "Malicious Activity Recent": response.json().get("details",{}).get("malicious_activity_recent"),
                        "Credential Leaked": response.json().get("details",{}).get("credentials_leaked"),
                        "Credentials Leaked Recent": response.json().get("details",{}).get("credentials_leaked_recent"),
                        "Data Breach": response.json().get("details",{}).get("data_breach"),
                        "First Seen": response.json().get("details",{}).get("first_seen"),
                        "Last Seen": response.json().get("details",{}).get("last_seen"),
                        "Domain Exists": response.json().get("details",{}).get("domain_exists"),
                        "Domain Reputation": response.json().get("details",{}).get("domain_reputation"),
                        "New Domain": response.json().get("details",{}).get("new_domain"),
                        "Days Since Domain Creation": response.json().get("details",{}).get("days_since_domain_creation"),
                        "Suspicious TLD": response.json().get("details",{}).get("suspicious_tld"),
                        "Spam": response.json().get("details",{}).get("spam"),
                        "Free Provider": response.json().get("details",{}).get("free_provider"),
                        "Disposable": response.json().get("details",{}).get("disposable"),
                        "Deliverable": response.json().get("details",{}).get("deliverable"),
                        "Accept All": response.json().get("details",{}).get("accept_all"),
                        "Valid MX": response.json().get("details",{}).get("valid_mx"),
                        "Primary MX": response.json().get("details",{}).get("primary_mx"),
                        "Spoofable": response.json().get("details",{}).get("spoofable"),
                        "SPF Strict": response.json().get("details",{}).get("spf_strict"),
                        "DMARC Enforced": response.json().get("details",{}).get("dmarc_enforced"),
                        "Profiles": response.json().get("details",{}).get("profiles",[]),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Emailrep.io", e)


def tweetfeed_live(indicator):
    def query_api(url):
        try:
            return requests.get(url)
        except Exception as e:
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
            return status_code_error(
                "Tweetfeed.live", response.status_code, response.reason
            )

        if response.json():
            for each in response.json():
                if indicator.indicator in each["value"]:
                    results.update(each)

        if not results:
            return no_results_found("Tweetfeed.live")

        return (
            {
                "site": "Tweetfeed.live",
                "results": results,
            },
        )
    except Exception as e:
        return failed_to_run("Tweetfeed.live", e)


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
            return status_code_error(
                "URLScan.io", response.status_code, response.reason
            )

        if not response.json().get("results"):
            return no_results_found("URLScan.io")

        last_scan_response = {}
        for scan in response.json().get("results"):
            if domain in scan.get("task").get("domain"):
                last_scan_response = requests.get(
                    f"https://urlscan.io/api/v1/result/{scan.get('task').get('uuid')}/",
                )
                break

        if not last_scan_response:
            return no_results_found("URLScan.io")

        return (
            # fmt: off
                {
                    "site": "URLScan.io",
                    "results": {
                        "Last Scan GUID": last_scan_response.json().get("task").get("uuid"),
                        "Last Scan URL": last_scan_response.json().get("task").get("reportURL"),
                        "Last Scan Time": last_scan_response.json().get("task").get("time"),
                        "Last Scan score": last_scan_response.json().get("verdicts").get("overall").get("score"),
                        "Categories": last_scan_response.json().get("verdicts").get("overall").get("categories"),
                        "Malicious": last_scan_response.json().get("verdicts").get("overall").get("malicious"),
                        "Tags": last_scan_response.json().get("verdicts").get("overall").get("tags"),
                        "Last Scan Screenshot": last_scan_response.json().get("task").get("screenshotURL"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("URLScan.io", e)


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
            return no_results_found("Circl.lu")

        if response.status_code != 200:
            return status_code_error("Circl.lu", response.status_code, response.reason)

        return (
            # fmt: off
                {
                    "site": "Circl.lu",
                    "results": {
                        "File Name": response.json().get("FileName"),
                        "File Size (KB)": response.json().get("FileSize"),
                        "Product Code": response.json().get("ProductCode"),
                        "Mimetype": response.json().get("mimetype"),
                        "Source": response.json().get("source"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Circl.lu", e)


def project_honeypot(indicator):
    # https://www.projecthoneypot.org/httpbl_api.php
    try:
        if config["PROJECT_HONEYPOT_API_KEY"] == "":
            raise Exception("PROJECT_HONEYPOT_API_KEY is not set in .env file.")

        bl = httpbl.HttpBL(config["PROJECT_HONEYPOT_API_KEY"])
        response = bl.query(indicator.indicator)

        if not (response.get("days_since_last_activity") and response.get("type")):
            return no_results_found("Project Honeypot")

        return (
            # fmt: off
                {
                    "site": "Project Honeypot",
                    "results": {
                        "Days Since Last Activity": response.get("days_since_last_activity"),
                        "Name": response.get("name"),
                        "Threat Score": response.get("threat_score"),
                        "Type": (", ".join([httpbl.DESCRIPTIONS[t] for t in response["type"]])) if response.get("type") else "",
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Project Honeypot", e)


def echo_trail(indicator):
    try:
        if config["ECHOTRAIL_API_KEY"] == "":
            raise Exception("ECHOTRAIL_API_KEY is not set in .env file.")

        response = requests.get(
            f"https://api.echotrail.io/v1/insights/{indicator.indicator}",
            headers={
                "X-Api-Key": str(config["ECHOTRAIL_API_KEY"]),
                "Content-Type": "application/json",
            },
        )

        if response.status_code != 200:
            return status_code_error(
                "Echo Trail", response.status_code, response.reason
            )

        if "EchoTrail has never observed" in response.json().get("message", ""):
            return no_results_found("Echo Trail")

        return (
            # fmt: off
                {
                    "site": "Echo Trail",
                    "results": {
                        "File Name": response.json().get("filenames"),
                        "Description": response.json().get("description"),
                        "Intel": response.json().get("intel"),
                        "Parents": response.json().get("parents"),
                        "Children": response.json().get("children"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Echo Trail", e)


def hybrid_analysis(indicator):
    # https://www.hybrid-analysis.com/docs/api/v2
    try:
        if config["HYBRID_ANALYSIS_API_KEY"] == "":
            raise Exception("HYBRID_ANALYSIS_API_KEY is not set in .env file.")

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
            return status_code_error(
                "Hybrid Analysis", response.status_code, response.reason
            )

        if not response.json():
            return no_results_found("Hybrid Analysis")

        response = response.json()[0]
        return (
            # fmt: off
                {
                    "site": "Hybrid Analysis",
                    "results": {
                        "File Name": response.get("submissions")[0].get("filename"),
                        "Type": response.get("type"),
                        "Job Environment": response.get("environment_description"),
                        "AV Detect": response.get("av_detect"),
                        "VX Family": response.get("vx_family"),
                        "Verdict": response.get("verdict"),
                        "Threat Score": response.get("threat_score"),
                        "SHA1": response.get("sha1"),
                        "SHA256": response.get("sha256"),
                        "SHA512": response.get("sha512"),
                        "Classification": response.get("classification_tags"),
                        "Tags": response.get("tags"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Hybrid Analysis", e)


def breach_directory(indicator):
    try:
        if config["BREACH_DIRECTORY_API_KEY"] == "":
            raise Exception("BREACH_DIRECTORY_API_KEY is not set in .env file.")

        response = requests.get(
            "https://breachdirectory.p.rapidapi.com/",
            headers={
                "X-RapidAPI-Key": config["BREACH_DIRECTORY_API_KEY"],
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            },
            params={"func": "auto", "term": indicator.indicator},
        )

        if response.status_code != 200:
            return status_code_error(
                "Breach Directory", response.status_code, response.reason
            )

        if not response.json().get("result", []):
            return no_results_found("Breach Directory")

        return (
            # fmt: off
                {
                    "site": "Breach Directory",
                    "results":{
                        "Found": response.json().get("found", {}),
                        "Frequency": response.json().get("result", [])
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Breach Directory", e)


def shodan(indicator):
    try:
        if config["SHODAN_API_KEY"] == "":
            raise Exception("SHODAN_API_KEY is not set in .env file.")

        try:
            api = Shodan(config["SHODAN_API_KEY"])
            host = api.host(indicator.indicator)
        except Exception:
            return no_results_found("Shodan")

        return (
            # fmt: off
                {
                    "site": "Shodan",
                    "results":{
                        "Hostnames": host.get("hostnames"),
                        "Domains": host.get("domains"),
                        "Tags": host.get("tags"),
                        "Last Update": host.get("last_update"),
                        "City": host.get("city"),
                        "ASN": host.get("asn"),
                        "ISP": host.get("isp"),
                        "Country": host.get("country_name"),
                        "Region": host.get("region_code"),
                        "OS": host.get("os"),
                        "Ports": host.get("ports"),
                        "Vulns": host.get("vulns"),
                        "URL": f"https://www.shodan.io/host/{indicator.indicator}",
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Shodan", e)


def checkphish(indicator):
    # https://checkphish.ai/checkphish-api/
    try:
        if config["CHECK_PHISH_API_KEY"] == "":
            raise Exception("CHECK_PHISH_API_KEY is not set in .env file.")

        if indicator.indicator_type == "fqdn":
            fqdn = convert_fqdn_to_url(indicator.indicator)
            start_job = requests.post(
                "https://developers.checkphish.ai/api/neo/scan",
                headers={"Content-Type": "application/json"},
                json={
                    "apiKey": config["CHECK_PHISH_API_KEY"],
                    "urlInfo": {"url": fqdn},
                },
            )
        elif indicator.indicator_type == "url":
            url = indicator.indicator
            start_job = requests.post(
                "https://developers.checkphish.ai/api/neo/scan",
                headers={"Content-Type": "application/json"},
                json={
                    "apiKey": config["CHECK_PHISH_API_KEY"],
                    "urlInfo": {"url": url},
                },
            )
        else:
            raise Exception("Invalid indicator type for CheckPhish")

        if start_job.status_code != 200:
            return status_code_error(
                "CheckPhish", start_job.status_code, start_job.reason
            )

        status = None
        retry_count = 0
        while status != "DONE":
            if retry_count > 5:
                return failed_to_run("CheckPhish", "Job took too long to complete.")
            time.sleep(5)
            response = requests.post(
                "https://developers.checkphish.ai/api/neo/scan/status",
                headers={"Content-Type": "application/json"},
                json={
                    "apiKey": config["CHECK_PHISH_API_KEY"],
                    "jobID": start_job.json().get("jobID"),
                    "insights": True,
                },
            )
            status = response.json().get("status")
            retry_count += 1

        if response.status_code != 200:
            return status_code_error(
                "CheckPhish", response.status_code, response.reason
            )

        if not response.json().get("error") == False:
            return no_results_found("CheckPhish")

        return (
            # fmt: off
                {
                    "site": "CheckPhish",
                    "results":{
                        "Disposition": response.json().get("disposition"),
                        "URL SHA256": response.json().get("url_sha256"),
                        "Insights": response.json().get("insights"),
                        "Screenshot": response.json().get("screenshot_path"),
                        "Scan Error": response.json().get("error"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("CheckPhish", e)


def malware_bazzar(indicator):
    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": indicator.indicator},
        )

        if response.status_code != 200:
            return status_code_error(
                "Malware Bazzar", response.status_code, response.reason
            )

        if not response.json().get("query_status") == "ok":
            return no_results_found("Malware Bazzar")

        return (
            # fmt: off
                {
                    "site": "Malware Bazzar",
                    "results":{
                        "File Type": response.json().get("data")[0].get("file_type"),
                        "Signature": response.json().get("data")[0].get("signature"),
                        "File Name": response.json().get("data")[0].get("file_name"),
                        "Delivery Method": response.json().get("delivery_method"),
                        "Tags": response.json().get("tags"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Malware Bazzar", e)


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
            raise Exception("Invalid indicator type for InQuestLabs")

        if response.status_code != 200:
            return status_code_error(
                "InQuestLabs", response.status_code, response.reason
            )

        if response.json().get("success") is False:
            return no_results_found("InQuestLabs")

        if not response.json().get("data"):
            return no_results_found("InQuestLabs")

        return (
            # fmt: off
                {
                    "site": "InQuestLabs",
                    "results": {
                        "Classification": response.json().get("data", [])[0].get("classification"),
                        "File Type": response.json().get("data", [])[0].get("file_type"),
                        "First Seen": response.json().get("data", [])[0].get("first_seen"),
                        "Inquest Alerts": response.json().get("data", [])[0].get("inquest_alerts"),
                        "Mime Type": response.json().get("data", [])[0].get("mime_type"),
                        "Subcategory": response.json().get("data", [])[0].get("subcategory"),
                        "Subcategory URL": response.json().get("data", [])[0].get("subcategory_url"),
                        "Tags": response.json().get("data", [])[0].get("tags"),
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("InQuestLabs", e)


def maltiverse(indicator):
    try:
        if config["MALTIVERSE_API_KEY"] == "":
            raise Exception("MALTIVERSE_API_KEY is not set in .env file.")

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
            raise Exception("Invalid indicator type for Maltiverse")

        if not result:
            raise Exception("No results found")

        return (
            # fmt: off
                {
                    "site": "Maltiverse",
                    "results": {
                        "Classification": result.get("classification", ""),
                        "Blacklist": result.get("blacklist", []),
                        "Tags": result.get("tag", []),

                        },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Maltiverse", e)
