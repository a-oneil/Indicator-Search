import traceback
from . import tools, enrichments_handler, tagging_handler, links_handler
from .. import notifications
from ..models import Iocs
from sqlalchemy.orm import Session
import time
import threading


def new_indicator_handler(indicator, user, db: Session):
    try:
        t1_start = time.time()
        notifications.console_output(
            f"New indicator added by {user.username}, starting scan for {indicator.indicator_type}: {indicator.indicator}",
            indicator,
            "BLUE",
        )

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
            threading.Thread(
                target=tools.search_feedlists, daemon=False, args=(indicator, db)
            ).start()

        """ Setup indicator json objects """
        indicator.results = []

        # fmt: off
        if indicator.indicator_type == "ipv4":
            indicator.results += tools.tweetfeed_live(indicator)
            indicator.results += tools.search_ipwhois(indicator)
            indicator.results += tools.ipinfoio(indicator)
            indicator.results += tools.abuse_ipdb(indicator)
            indicator.results += tools.ipqualityscore(indicator)
            indicator.results += tools.greynoise_community(indicator)
            indicator.results += tools.virustotal_ip(indicator)
            indicator.results += tools.project_honeypot(indicator)
            indicator.results += tools.hacked_ip_threatlist(indicator)
            indicator.results += tools.stopforumspam_ip(indicator)
            indicator.results += tools.shodan(indicator)
            indicator.results += tools.inquestlabs(indicator)
            indicator.results += tools.maltiverse(indicator)
        
        elif indicator.indicator_type == "ipv6":
            indicator.results += tools.ipinfoio(indicator)
            indicator.results += tools.abuse_ipdb(indicator)
            indicator.results += tools.ipqualityscore(indicator)
            indicator.results += tools.virustotal_ip(indicator)
            indicator.results += tools.stopforumspam_ip(indicator)

        elif indicator.indicator_type == "fqdn":
            indicator.results += tools.tweetfeed_live(indicator)
            indicator.results += tools.virustotal_domain(indicator)
            indicator.results += tools.virustotal_url(indicator)
            indicator.results += tools.urlvoid(indicator)
            indicator.results += tools.checkphish(indicator)
            indicator.results += tools.urlscanio(indicator)
            indicator.results += tools.inquestlabs(indicator)
            indicator.results += tools.maltiverse(indicator)
            indicator.results += tools.wayback_machine(indicator)
            indicator.results += tools.kickbox_disposible_email(indicator)

        elif indicator.indicator_type == "url":
            indicator.results += tools.tweetfeed_live(indicator)
            indicator.results += tools.virustotal_domain(indicator)
            indicator.results += tools.virustotal_url(indicator)
            indicator.results += tools.urlvoid(indicator)
            indicator.results += tools.checkphish(indicator)
            indicator.results += tools.urlscanio(indicator)
            indicator.results += tools.inquestlabs(indicator)
            indicator.results += tools.maltiverse(indicator)
            indicator.results += tools.wayback_machine(indicator)

        elif indicator.indicator_type == "email":
            indicator.results += tools.emailrepio(indicator)
            indicator.results += tools.breach_directory(indicator)
            indicator.results += tools.stopforumspam_email(indicator)
            indicator.results += tools.virustotal_domain(indicator)
            indicator.results += tools.urlvoid(indicator)
            indicator.results += tools.inquestlabs(indicator)
            indicator.results += tools.wayback_machine(indicator)
            indicator.results += tools.kickbox_disposible_email(indicator)

        elif indicator.indicator_type == "hash.md5":
            indicator.results += tools.circl_lu(indicator)
            indicator.results += tools.echo_trail(indicator)
            indicator.results += tools.tweetfeed_live(indicator)
            indicator.results += tools.virustotal_hash(indicator)
            indicator.results += tools.hybrid_analysis(indicator)
            indicator.results += tools.malware_bazzar(indicator)
            indicator.results += tools.inquestlabs(indicator)
            indicator.results += tools.maltiverse(indicator)

        elif indicator.indicator_type == "hash.sha1":
            indicator.results += tools.circl_lu(indicator)
            indicator.results += tools.virustotal_hash(indicator)
            indicator.results += tools.hybrid_analysis(indicator)
            indicator.results += tools.malware_bazzar(indicator)
            indicator.results += tools.inquestlabs(indicator)
            indicator.results += tools.maltiverse(indicator)

        elif indicator.indicator_type == "hash.sha256":
            indicator.results += tools.circl_lu(indicator)
            indicator.results += tools.echo_trail(indicator)
            indicator.results += tools.tweetfeed_live(indicator)
            indicator.results += tools.virustotal_hash(indicator)
            indicator.results += tools.hybrid_analysis(indicator)
            indicator.results += tools.malware_bazzar(indicator)
            indicator.results += tools.inquestlabs(indicator)
            indicator.results += tools.maltiverse(indicator)

        elif indicator.indicator_type == "hash.sha512":
            indicator.results += tools.virustotal_hash(indicator)
            indicator.results += tools.inquestlabs(indicator)
            indicator.results += tools.maltiverse(indicator)

        elif indicator.indicator_type == "mac":
            indicator.results += tools.macvendors(indicator)

        elif indicator.indicator_type == "phone":
            indicator.results += tools.numverify(indicator)
            indicator.results += tools.ipqualityscore_phone(indicator)

        elif indicator.indicator_type == "useragent":
            indicator.results += tools.whatsmybrowser_ua(indicator)

        # fmt: on
        for each in indicator.results:
            keys_to_remove = []
            for key, value in each["results"].items():
                if key == "error" and "is not set in .env file." in value:
                    indicator.results.remove(each)
                if not value:
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                del each["results"][key]

            if not each["results"]:
                each["results"] = {"error": "No results found"}

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
            f"Indicator has been completed in {processing_time}",
            indicator,
            "BLUE",
        )

        notifications.slack_indicator_complete(indicator, "success")

    except Exception as e:
        indicator.complete = True
        indicator.results = (
            {
                "site": "Error",
                "results": {"error": str(e)},
            },
        )
        indicator.tags = {"error": True}
        db.add(indicator)
        db.commit()
        notifications.console_output(
            f"Error: {traceback.format_exc()}", indicator, "RED"
        )
        notifications.slack_indicator_complete(indicator, "failure")
