from ._search_feedlists import feedlists_handler
from ._ipinfoio import ipinfoio
from ._ipwhois import search_ipwhois as ipwhois
from ._ipqualityscore import ipqualityscore_ip, ipqualityscore_phone
from ._virustotal import (
    virustotal_ip,
    virustotal_domain,
    virustotal_url,
    virustotal_hash,
)
from ._greynoise import greynoise_community, greynoise_enterprise
from ._hackedip import hacked_ip
from ._tweetfeed import tweetfeed_live
from ._abuseipdb import abuseipdb
from ._project_honeypot import project_honeypot
from ._stopforumspam import stopforumspam_ip, stopforumspam_email
from ._shodan import shodan
from ._inquestlabs import inquestlabs
from ._urlvoid import urlvoid
from ._maltiverse import maltiverse
from ._urlscanio import urlscanio
from ._wayback_machine import wayback_machine
from ._kickbox import kickbox_disposible_email
from ._shimon import shimon
from ._emailrepio import emailrepio
from ._breach_directory import breach_directory
from ._hybrid_analysis import hybrid_analysis
from ._macvendors import macvendors
from ._numverify import numverify
from ._circl_lu import circl_lu
from ._echo_trail import echo_trail
from ._malware_bazzar import malware_bazzar
from ._whatsmybrowser import whatsmybrowser_ua


def run_tools(indicator):
    """Setup indicator json objects"""
    indicator.results = []

    # fmt: off
    if indicator.indicator_type == "ipv4":
        indicator.results += tweetfeed_live(indicator)
        indicator.results += ipwhois(indicator)
        indicator.results += ipinfoio(indicator)
        indicator.results += abuseipdb(indicator)
        indicator.results += ipqualityscore_ip(indicator)
        indicator.results += greynoise_community(indicator)
        indicator.results += greynoise_enterprise(indicator)
        indicator.results += virustotal_ip(indicator)
        indicator.results += project_honeypot(indicator)
        indicator.results += hacked_ip(indicator)
        indicator.results += stopforumspam_ip(indicator)
        indicator.results += shodan(indicator)
        indicator.results += inquestlabs(indicator)
        indicator.results += maltiverse(indicator)

    elif indicator.indicator_type == "ipv6":
        indicator.results += ipinfoio(indicator)
        indicator.results += abuseipdb(indicator)
        indicator.results += ipqualityscore_ip(indicator)
        indicator.results += virustotal_ip(indicator)
        indicator.results += stopforumspam_ip(indicator)

    elif indicator.indicator_type == "fqdn":
        indicator.results += tweetfeed_live(indicator)
        indicator.results += virustotal_domain(indicator)
        indicator.results += virustotal_url(indicator)
        indicator.results += urlvoid(indicator)
        indicator.results += urlscanio(indicator)
        indicator.results += inquestlabs(indicator)
        indicator.results += maltiverse(indicator)
        indicator.results += wayback_machine(indicator)
        indicator.results += kickbox_disposible_email(indicator)
        indicator.results += shimon(indicator)

    elif indicator.indicator_type == "url":
        indicator.results += tweetfeed_live(indicator)
        indicator.results += virustotal_domain(indicator)
        indicator.results += virustotal_url(indicator)
        indicator.results += urlvoid(indicator)
        indicator.results += urlscanio(indicator)
        indicator.results += inquestlabs(indicator)
        indicator.results += maltiverse(indicator)
        indicator.results += wayback_machine(indicator)
        indicator.results += shimon(indicator)

    elif indicator.indicator_type == "email":
        indicator.results += emailrepio(indicator)
        indicator.results += breach_directory(indicator)
        indicator.results += stopforumspam_email(indicator)
        indicator.results += virustotal_domain(indicator)
        indicator.results += urlvoid(indicator)
        indicator.results += inquestlabs(indicator)
        indicator.results += wayback_machine(indicator)
        indicator.results += kickbox_disposible_email(indicator)

    elif indicator.indicator_type == "hash.md5":
        indicator.results += circl_lu(indicator)
        indicator.results += echo_trail(indicator)
        indicator.results += tweetfeed_live(indicator)
        indicator.results += virustotal_hash(indicator)
        indicator.results += hybrid_analysis(indicator)
        indicator.results += malware_bazzar(indicator)
        indicator.results += inquestlabs(indicator)
        indicator.results += maltiverse(indicator)

    elif indicator.indicator_type == "hash.sha1":
        indicator.results += circl_lu(indicator)
        indicator.results += virustotal_hash(indicator)
        indicator.results += hybrid_analysis(indicator)
        indicator.results += malware_bazzar(indicator)
        indicator.results += inquestlabs(indicator)
        indicator.results += maltiverse(indicator)

    elif indicator.indicator_type == "hash.sha256":
        indicator.results += circl_lu(indicator)
        indicator.results += echo_trail(indicator)
        indicator.results += tweetfeed_live(indicator)
        indicator.results += virustotal_hash(indicator)
        indicator.results += hybrid_analysis(indicator)
        indicator.results += malware_bazzar(indicator)
        indicator.results += inquestlabs(indicator)
        indicator.results += maltiverse(indicator)

    elif indicator.indicator_type == "hash.sha512":
        indicator.results += virustotal_hash(indicator)
        indicator.results += inquestlabs(indicator)
        indicator.results += maltiverse(indicator)

    elif indicator.indicator_type == "mac":
        indicator.results += macvendors(indicator)

    elif indicator.indicator_type == "phone":
        indicator.results += numverify(indicator)
        indicator.results += ipqualityscore_phone(indicator)

    elif indicator.indicator_type == "useragent":
        indicator.results += whatsmybrowser_ua(indicator)
    # fmt: on

    return indicator.results
