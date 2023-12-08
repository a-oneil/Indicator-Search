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
    results = []

    # fmt: off
    if indicator.indicator_type == "ipv4":
        results += tweetfeed_live(indicator)
        results += ipwhois(indicator)
        results += ipinfoio(indicator)
        results += abuseipdb(indicator)
        results += ipqualityscore_ip(indicator)
        results += greynoise_community(indicator)
        results += greynoise_enterprise(indicator)
        results += virustotal_ip(indicator)
        results += project_honeypot(indicator)
        results += hacked_ip(indicator)
        results += stopforumspam_ip(indicator)
        results += shodan(indicator)
        results += inquestlabs(indicator)
        # results += maltiverse(indicator)

    elif indicator.indicator_type == "ipv6":
        results += ipinfoio(indicator)
        results += abuseipdb(indicator)
        results += ipqualityscore_ip(indicator)
        results += virustotal_ip(indicator)
        results += stopforumspam_ip(indicator)

    elif indicator.indicator_type == "fqdn":
        results += tweetfeed_live(indicator)
        results += virustotal_domain(indicator)
        results += virustotal_url(indicator)
        results += urlvoid(indicator)
        results += urlscanio(indicator)
        results += inquestlabs(indicator)
        # results += maltiverse(indicator)
        results += wayback_machine(indicator)
        results += kickbox_disposible_email(indicator)
        results += shimon(indicator)

    elif indicator.indicator_type == "url":
        results += tweetfeed_live(indicator)
        results += virustotal_domain(indicator)
        results += virustotal_url(indicator)
        results += urlvoid(indicator)
        results += urlscanio(indicator)
        results += inquestlabs(indicator)
        # results += maltiverse(indicator)
        results += wayback_machine(indicator)
        results += shimon(indicator)

    elif indicator.indicator_type == "email":
        results += emailrepio(indicator)
        results += breach_directory(indicator)
        results += stopforumspam_email(indicator)
        results += virustotal_domain(indicator)
        results += urlvoid(indicator)
        results += inquestlabs(indicator)
        results += wayback_machine(indicator)
        results += kickbox_disposible_email(indicator)

    elif indicator.indicator_type == "hash.md5":
        results += circl_lu(indicator)
        results += echo_trail(indicator)
        results += tweetfeed_live(indicator)
        results += virustotal_hash(indicator)
        results += hybrid_analysis(indicator)
        results += malware_bazzar(indicator)
        results += inquestlabs(indicator)
        # results += maltiverse(indicator)

    elif indicator.indicator_type == "hash.sha1":
        results += circl_lu(indicator)
        results += virustotal_hash(indicator)
        results += hybrid_analysis(indicator)
        results += malware_bazzar(indicator)
        results += inquestlabs(indicator)
        # results += maltiverse(indicator)

    elif indicator.indicator_type == "hash.sha256":
        results += circl_lu(indicator)
        results += echo_trail(indicator)
        results += tweetfeed_live(indicator)
        results += virustotal_hash(indicator)
        results += hybrid_analysis(indicator)
        results += malware_bazzar(indicator)
        results += inquestlabs(indicator)
        # results += maltiverse(indicator)

    elif indicator.indicator_type == "hash.sha512":
        results += virustotal_hash(indicator)
        results += inquestlabs(indicator)
        # results += maltiverse(indicator)

    elif indicator.indicator_type == "mac":
        results += macvendors(indicator)

    elif indicator.indicator_type == "phone":
        results += numverify(indicator)
        results += ipqualityscore_phone(indicator)

    elif indicator.indicator_type == "useragent":
        results += whatsmybrowser_ua(indicator)
    # fmt: on

    return results
