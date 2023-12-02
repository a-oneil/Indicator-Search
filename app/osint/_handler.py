import time
import traceback
import threading
from . import enrichments_handler, tagging_handler, links_handler
from .. import notifications
from ..models import Iocs
from sqlalchemy.orm import Session
from .utils import sort_results
from .tools import *


def new_indicator_handler(indicator, user, db: Session):
    try:
        t1_start = time.time()
        notifications.console_output(
            f"New indicator added by {user.username}, starting scan for {indicator.indicator_type}: {indicator.indicator}",
            indicator,
            "BLUE",
        )

        # Search feedlists for indicator in a new thread
        threads_to_wait_for = []
        if any(
            match in indicator.indicator_type
            for match in [
                "ipv4",
                "ipv6",
                "fqdn",
                "url",
                "email",
                "hash.md5",
                "hash.sha1",
                "hash.sha256",
                "hash.sha512",
            ]
        ):
            thread = threading.Thread(
                target=search_feedlists, daemon=False, args=(indicator, db)
            )
            threads_to_wait_for.append(thread)
            threads_to_wait_for[0].start()

        """ Setup indicator json objects """
        indicator.results = []

        # fmt: off
        if indicator.indicator_type == "ipv4":
            indicator.results += tweetfeed_live(indicator)
            indicator.results += ipwhois(indicator)
            indicator.results += ipinfoio(indicator)
            indicator.results += abuseipdb(indicator)
            indicator.results += ipqualityscore_ip(indicator)
            indicator.results += greynoise_community(indicator)
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

        # Wait for feedlist thread to finish
        if threads_to_wait_for:
            for thread in threads_to_wait_for:
                thread.join()

        # Remove tools that did not have an API key set
        indicator.results = [
            tool
            for tool in indicator.results
            if tool["outcome"]["status"] != "missing_apikey"
        ]

        # Sort results based on if the tool had results or not
        indicator.results = sorted(indicator.results, key=sort_results)

        notifications.console_output(
            "OSINT Scan complete",
            indicator,
            "BLUE",
        )

        if indicator.feedlist_results:
            notifications.console_output(
                f"Indicator found in {len(indicator.feedlist_results)} feeds",
                indicator,
                "BLUE",
            )

        """ Tagging and enriching using useful info from results """

        add_tags = tagging_handler(indicator, db)
        indicator.tags = add_tags if add_tags else None

        if indicator.tags:
            notifications.console_output(
                "Indicator has been tagged",
                indicator,
                "BLUE",
            )

        """ Add external enrichments to results """
        add_links = links_handler(indicator)
        indicator.external_links = add_links if add_links else None

        add_enrichments = enrichments_handler(indicator)
        indicator.enrichments = add_enrichments if add_enrichments else None

        if indicator.enrichments:
            notifications.console_output(
                "Indicator has enrichements",
                indicator,
                "BLUE",
            )

        """ Search if this indicator has been IOC'd before"""
        indicator = Iocs.search_for_ioc(indicator, db)

        """ Mark indicator as complete and commit to database"""
        t1_stop = time.time()
        processing_time = t1_stop - t1_start
        indicator.complete = True
        indicator.processing_time = processing_time
        db.add(indicator)
        db.commit()
        notifications.console_output(
            f"Indicator has been completed in {processing_time} seconds",
            indicator,
            "BLUE",
        )

        notifications.slack_indicator_complete(indicator, "success")

    except Exception as error_message:
        indicator.complete = True
        indicator.results = (
            {
                "tool": "Indicator Search",
                "outcome": {
                    "status": "failed_to_run",
                    "error_message": str(error_message),
                    "status_code": 500,
                    "reason": "Internal Server Error",
                },
                "results": {},
            },
        )
        indicator.tags = {"error": True}
        db.add(indicator)
        db.commit()
        notifications.console_output(
            f"Error: {traceback.format_exc()}", indicator, "RED"
        )
        notifications.slack_indicator_complete(indicator, "failure")
