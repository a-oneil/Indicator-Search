import requests
import xmltodict
import ipwhois
import httpbl
import base64
import json
from .. import config, notifications
from ..models import FeedLists, Indicators
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
            return status_code_error("ipinfo.io", response.status_code, response.reason)

        return (
            # fmt: off
            {
                "site": "ipinfo.io",
                "results": response.json()
            },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("ipinfo.io", e)


def search_ipwhois(indicator):
    try:
        obj = ipwhois.IPWhois(indicator.indicator)
        return (
            {
                "site": "ip_whois",
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
    except Exception as e:
        return failed_to_run("ip_whois", e)


def ipqualityscore(indicator):
    try:
        if config["IPQS_API_KEY"] == "":
            raise Exception("IPQS_API_KEY is not set in .env file.")

        response = requests.get(
            f"https://us.ipqualityscore.com/api/json/ip/{config['IPQS_API_KEY']}/{indicator.indicator}",
        )

        if response.status_code != 200:
            return status_code_error(
                "ip_quality_score", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "ip_quality_score",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("ip_quality_score", e)


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
            return no_results_found("virustotal_ip")

        if response.status_code != 200:
            return status_code_error(
                "virustotal_ip", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "virustotal_ip",
                    "results": response.json().get("data")
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("virustotal_ip", e)


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
            return no_results_found("virustotal_domain")

        if response.status_code != 200:
            return status_code_error(
                "virustotal_domain", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "virustotal_domain",
                    "results": response.json().get("data")
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("virustotal_domain", e)


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
            return no_results_found("virustotal_url")

        if response.status_code != 200:
            return status_code_error(
                "virustotal_url", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "virustotal_url",
                    "results": response.json().get("data")
                },
            # fmt: on
        )

    except Exception as e:
        return failed_to_run("virustotal_url", e)


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
            return no_results_found("virustotal_hash")

        if response.status_code != 200:
            return status_code_error(
                "virustotal_hash", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "virustotal_hash",
                    "results": response.json().get("data")
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("virustotal_hash", e)


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
            return no_results_found("greynoise_community")

        if response.status_code != 200:
            return status_code_error(
                "greynoise_community", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "greynoise_community",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("greynoise_community", e)


def hacked_ip_threatlist(indicator):
    try:
        response = requests.get(
            f"http://www.hackedip.com/api.php?ip={indicator.indicator}",
        )

        if response.status_code != 200:
            return status_code_error("hacked_ip", response.status_code, response.reason)

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
                    "site": "hacked_ip",
                    "results": {
                        "active_threatlists": results_list
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("hacked_ip", e)


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
            return status_code_error("url_void", response.status_code, response.reason)

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
                        "site": "url_void",
                        "results": {
                            "raw": response.json(),
                            "scanners_detected": blacklists_list,
                            "security_checks": security_checks_list,
                        },
                    },
                # fmt: on
            )
        else:
            return no_results_found("url_void")

    except Exception as e:
        return failed_to_run("url_void", e)


def macvendors(indicator):
    try:
        response = requests.get(f"https://api.macvendors.com/{indicator.indicator}")

        if response.status_code != 200:
            return status_code_error(
                "mac_vendors", response.status_code, response.reason
            )

        return (
            {
                "site": "mac_vendors",
                "results": {
                    "manufacturer": response.text,
                },
            },
        )
    except Exception as e:
        return failed_to_run("mac_vendors", e)


def stopforumspam_email(indicator):
    try:
        response = requests.get(
            f"http://api.stopforumspam.org/api?email={indicator.indicator}",
        )
        results = xmltodict.parse(response.text)

        if response.status_code != 200:
            return status_code_error(
                "stop_forum_spam_email", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "stop_forum_spam_email",
                    "results": {
                        "appears": results.get("response", {}).get("appears"),
                        "frequency": results.get("response", {}).get("frequency")
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("stop_forum_spam_email", e)


def stopforumspam_ip(indicator):
    try:
        response = requests.get(
            f"http://api.stopforumspam.org/api?ip={indicator.indicator}",
        )
        results = xmltodict.parse(response.text)

        if response.status_code != 200:
            return status_code_error(
                "stop_forum_spam_ip", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "stop_forum_spam_ip",
                    "results": {
                        "appears": results.get("response", {}).get("appears"),
                        "frequency": results.get("response", {}).get("frequency")
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("stop_forum_spam_ip", e)


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
            return status_code_error("abuseipdb", response.status_code, response.reason)

        # fmt: off
        return (
            {
                "site": "abuseipdb",
                "results": response.json()
            },
        )
        # fmt: on

    except Exception as e:
        return failed_to_run("abuseipdb", e)


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
                "emailrep.io", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "emailrep.io",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("emailrep.io", e)


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
                "tweetfeed.live", response.status_code, response.reason
            )

        if response.json():
            for each in response.json():
                if indicator.indicator in each["value"]:
                    results.update(each)

        if not results:
            return no_results_found("tweetfeed.live")

        return (
            {
                "site": "tweetfeed.live",
                "results": results,
            },
        )
    except Exception as e:
        return failed_to_run("tweetfeed.live", e)


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
                "urlscan.io", response.status_code, response.reason
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
                    "site": "urlscan.io",
                    "results": last_scan_response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("urlscan.io", e)


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
            return status_code_error("circl.lu", response.status_code, response.reason)

        return (
            # fmt: off
                {
                    "site": "circl.lu",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("circl.lu", e)


def project_honeypot(indicator):
    # https://www.projecthoneypot.org/httpbl_api.php
    try:
        if config["PROJECT_HONEYPOT_API_KEY"] == "":
            raise Exception("PROJECT_HONEYPOT_API_KEY is not set in .env file.")

        bl = httpbl.HttpBL(config["PROJECT_HONEYPOT_API_KEY"])
        response = bl.query(indicator.indicator)

        if not (response.get("days_since_last_activity") and response.get("type")):
            return no_results_found("project_honeypot")

        return (
            # fmt: off
                {
                    "site": "project_honeypot",
                    "results": {
                        "days_since_last_activity": response.get("days_since_last_activity"),
                        "name": response.get("name"),
                        "threat_score": response.get("threat_score"),
                        "type": (", ".join([httpbl.DESCRIPTIONS[t] for t in response["type"]])) if response.get("type") else "",
                    },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("project_honeypot", e)


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
                "echo_trail", response.status_code, response.reason
            )

        if "EchoTrail has never observed" in response.json().get("message", ""):
            return no_results_found("echo_trail")

        return (
            # fmt: off
                {
                    "site": "echo_trail",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("echo_trail", e)


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
                "hybrid_analysis", response.status_code, response.reason
            )

        if not response.json():
            return no_results_found("hybrid_analysis")

        response = response.json()[0]
        return (
            # fmt: off
                {
                    "site": "hybrid_analysis",
                    "results": response
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("hybrid_analysis", e)


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
                "breach_directory", response.status_code, response.reason
            )

        if not response.json().get("result", []):
            return no_results_found("breach_directory")

        return (
            # fmt: off
                {
                    "site": "breach_directory",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("breach_directory", e)


def shodan(indicator):
    try:
        if config["SHODAN_API_KEY"] == "":
            raise Exception("SHODAN_API_KEY is not set in .env file.")

        try:
            api = Shodan(config["SHODAN_API_KEY"])
            host = api.host(indicator.indicator)
        except Exception:
            return no_results_found("shodan")

        return (
            # fmt: off
                {
                    "site": "shodan",
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
    except Exception as e:
        return failed_to_run("shodan", e)


def malware_bazzar(indicator):
    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": indicator.indicator},
        )

        if response.status_code != 200:
            return status_code_error(
                "malware_bazzar", response.status_code, response.reason
            )

        if not response.json().get("query_status") == "ok":
            return no_results_found("malware_bazzar")

        return (
            # fmt: off
                {
                    "site": "malware_bazzar",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("malware_bazzar", e)


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
            return status_code_error(
                "inquest_labs", response.status_code, response.reason
            )

        if response.json().get("success") is False:
            return no_results_found("inquest_labs")

        if not response.json().get("data"):
            return no_results_found("inquest_labs")

        return (
            # fmt: off
                {
                    "site": "inquest_labs",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("inquest_labs", e)


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
                    "site": "maltiverse",
                    "results": {
                        "classification": result.get("classification", ""),
                        "blacklist": result.get("blacklist", []),
                        "tags": result.get("tag", []),

                        },
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("Maltiverse", e)


def numverify(indicator):
    try:
        if config["NUMVERIFY_API_KEY"] == "":
            raise Exception("NUMVERIFY_API_KEY is not set in .env file.")

        response = requests.get(
            f"http://apilayer.net/api/validate?access_key={config['NUMVERIFY_API_KEY']}&number={indicator.indicator}&format=1"
        )

        if response.status_code != 200:
            return status_code_error("numverify", response.status_code, response.reason)

        return (
            # fmt: off
                {
                    "site": "numverify",
                    "results": response.json()
                },
            # fmt: on
        )

    except Exception as e:
        return failed_to_run("Numverify", e)


def ipqualityscore_phone(indicator):
    try:
        if config["IPQS_API_KEY"] == "":
            raise Exception("IPQS_API_KEY is not set in .env file.")

        response = requests.get(
            f"https://us.ipqualityscore.com/api/json/phone/{config['IPQS_API_KEY']}/{indicator.indicator}",
        )

        if response.status_code != 200:
            return status_code_error(
                "ip_quality_score_phone", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "ip_quality_score_phone",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("ip_quality_score_phone", e)


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
            return status_code_error(
                "wayback_machine", response.status_code, response.reason
            )

        if not response.json().get("archived_snapshots"):
            return no_results_found("wayback_machine")

        return (
            # fmt: off
                {
                    "site": "wayback_machine",
                    "results": response.json().get("archived_snapshots", {}).get("closest")
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("wayback_machine", e)


def kickbox_disposible_email(indicator):
    try:
        response = requests.get(
            f"https://open.kickbox.com/v1/disposable/{indicator.indicator}",
        )

        if response.status_code != 200:
            return status_code_error(
                "kickbox_disposible_email", response.status_code, response.reason
            )

        if not response.json().get("disposable"):
            return no_results_found("kickbox_disposible_email")

        return (
            # fmt: off
                {
                    "site": "kickbox_disposible_email",
                    "results": response.json()
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("kickbox_disposible_email", e)


def whatsmybrowser_ua(indicator):
    try:
        if config["WHATSMYBROWSER_API_KEY"] == "":
            raise Exception("WHATSMYBROWSER_API_KEY is not set in .env file.")

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
            return status_code_error(
                "whatsmybrowser_ua", response.status_code, response.reason
            )

        return (
            # fmt: off
                {
                    "site": "whatsmybrowser_ua",
                    "results": response.json().get("parse", {})
                },
            # fmt: on
        )
    except Exception as e:
        return failed_to_run("whatsmybrowser_ua", e)