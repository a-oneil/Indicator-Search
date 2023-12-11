import asyncio
import httpx
from ..utils import sort_results, remove_missingapikey_results
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


async def tool_handler(indicator):
    """Setup indicator json objects"""
    results = []
    client = httpx.AsyncClient()

    if indicator.indicator_type == "ipv4":
        funcs = [
            tweetfeed_live,
            ipinfoio,
            abuseipdb,
            ipqualityscore_ip,
            greynoise_community,
            greynoise_enterprise,
            virustotal_ip,
            hacked_ip,
            stopforumspam_ip,
            # inquestlabs,
            maltiverse,
        ]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.append(shodan(indicator))
        results.append(project_honeypot(indicator))
        results.extend(await func_calls)

    elif indicator.indicator_type == "ipv6":
        funcs = [
            ipinfoio,
            abuseipdb,
            ipqualityscore_ip,
            virustotal_ip,
            stopforumspam_ip,
        ]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "fqdn":
        funcs = [
            tweetfeed_live,
            virustotal_domain,
            virustotal_url,
            urlvoid,
            urlscanio,
            # inquestlabs,
            maltiverse,
            wayback_machine,
            kickbox_disposible_email,
            shimon,
        ]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "url":
        funcs = [
            tweetfeed_live,
            virustotal_domain,
            virustotal_url,
            urlvoid,
            urlscanio,
            # inquestlabs,
            wayback_machine,
            shimon,
        ]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "email":
        funcs = [
            emailrepio,
            breach_directory,
            stopforumspam_email,
            virustotal_domain,
            urlvoid,
            # inquestlabs,
            wayback_machine,
            kickbox_disposible_email,
        ]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "hash.md5":
        funcs = [
            circl_lu,
            echo_trail,
            tweetfeed_live,
            virustotal_hash,
            hybrid_analysis,
            malware_bazzar,
            # inquestlabs,
            maltiverse,
        ]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "hash.sha1":
        funcs = [
            circl_lu,
            virustotal_hash,
            hybrid_analysis,
            malware_bazzar,
            # inquestlabs,
            maltiverse,
        ]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "hash.sha256":
        funcs = [
            circl_lu,
            echo_trail,
            tweetfeed_live,
            virustotal_hash,
            hybrid_analysis,
            malware_bazzar,
            # inquestlabs,
            maltiverse,
        ]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "hash.sha512":
        funcs = [
            virustotal_hash,
            # inquestlabs,
            maltiverse,
        ]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "mac":
        funcs = [macvendors]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "phone":
        funcs = [numverify, ipqualityscore_phone]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    elif indicator.indicator_type == "useragent":
        funcs = [whatsmybrowser_ua]
        func_calls = asyncio.gather(*[func(indicator, client) for func in funcs])
        results.extend(await func_calls)

    # Remove tools that did not have an API key set
    results = remove_missingapikey_results(results)

    # Sort results based on if the tool had results or not
    results = sorted(results, key=sort_results)

    await client.aclose()
    return results
