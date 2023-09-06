import traceback
from . import tools, enrichments_handler, tagging_handler, links_handler
from .. import notifications
from ..models import Iocs
from sqlalchemy.orm import Session
from time import process_time


def new_indicator_handler(background_tasks, indicator, user, db: Session):
    try:
        t1_start = process_time()
        notifications.console_output(
            f"New indicator added by {user.username}, starting scan for {indicator.indicator_type}: {indicator.indicator}",
            indicator,
            "BLUE",
        )

        """ Setup indicator json objects """
        indicator.results = []

        """ Run Tools """
        notifications.console_output(f"Running tools", indicator, "BLUE")
        # fmt: off
        if indicator.indicator_type == "ipv4":
            indicator.results += background_tasks.add(tools.tweetfeed_live(indicator))
            indicator.results += background_tasks.add(tools.search_ipwhois(indicator))
            indicator.results += background_tasks.add(tools.ipinfoio(indicator))
            indicator.results += background_tasks.add(tools.abuse_ipdb(indicator))
            indicator.results += background_tasks.add(tools.ipqualityscore(indicator))
            indicator.results += background_tasks.add(tools.greynoise_community(indicator))
            indicator.results += background_tasks.add(tools.virustotal_ip(indicator))
            indicator.results += background_tasks.add(tools.project_honeypot(indicator))
            indicator.results += background_tasks.add(tools.hacked_ip_threatlist(indicator))
            indicator.results += background_tasks.add(tools.stopforumspam_ip(indicator))
            indicator.results += background_tasks.add(tools.shodan(indicator))
            indicator.results += background_tasks.add(tools.inquestlabs(indicator))
            indicator.results += background_tasks.add(tools.maltiverse(indicator))
        elif indicator.indicator_type == "ipv6":
            indicator.results += background_tasks.add(tools.ipinfoio(indicator))
            indicator.results += background_tasks.add(tools.abuse_ipdb(indicator))
            indicator.results += background_tasks.add(tools.ipqualityscore(indicator))
            indicator.results += background_tasks.add(tools.virustotal_ip(indicator))
            indicator.results += background_tasks.add(tools.stopforumspam_ip(indicator))

        elif indicator.indicator_type == "fqdn":
            indicator.results += background_tasks.add(tools.tweetfeed_live(indicator))
            indicator.results += background_tasks.add(tools.virustotal_domain(indicator))
            indicator.results += background_tasks.add(tools.virustotal_url(indicator))
            indicator.results += background_tasks.add(tools.urlvoid(indicator))
            indicator.results += background_tasks.add(tools.checkphish(indicator))
            indicator.results += background_tasks.add(tools.urlscanio(indicator))
            indicator.results += background_tasks.add(tools.inquestlabs(indicator))
            indicator.results += background_tasks.add(tools.maltiverse(indicator))

        elif indicator.indicator_type == "url":
            indicator.results += background_tasks.add(tools.tweetfeed_live(indicator))
            indicator.results += background_tasks.add(tools.virustotal_domain(indicator))
            indicator.results += background_tasks.add(tools.virustotal_url(indicator))
            indicator.results += background_tasks.add(tools.urlvoid(indicator))
            indicator.results += background_tasks.add(tools.checkphish(indicator))
            indicator.results += background_tasks.add(tools.urlscanio(indicator))
            indicator.results += background_tasks.add(tools.inquestlabs(indicator))
            indicator.results += background_tasks.add(tools.maltiverse(indicator))

        elif indicator.indicator_type == "email":
            indicator.results += background_tasks.add(tools.emailrepio(indicator))
            indicator.results += background_tasks.add(tools.breach_directory(indicator))
            indicator.results += background_tasks.add(tools.stopforumspam_email(indicator))
            indicator.results += background_tasks.add(tools.virustotal_domain(indicator))
            indicator.results += background_tasks.add(tools.urlvoid(indicator))
            indicator.results += background_tasks.add(tools.inquestlabs(indicator))

        elif indicator.indicator_type == "hash.md5":
            indicator.results += background_tasks.add(tools.circl_lu(indicator))
            indicator.results += background_tasks.add(tools.echo_trail(indicator))
            indicator.results += background_tasks.add(tools.tweetfeed_live(indicator))
            indicator.results += background_tasks.add(tools.virustotal_hash(indicator))
            indicator.results += background_tasks.add(tools.hybrid_analysis(indicator))
            indicator.results += background_tasks.add(tools.malware_bazzar(indicator))
            indicator.results += background_tasks.add(tools.inquestlabs(indicator))
            indicator.results += background_tasks.add(tools.maltiverse(indicator))

        elif indicator.indicator_type == "hash.sha1":
            indicator.results += background_tasks.add(tools.circl_lu(indicator))
            indicator.results += background_tasks.add(tools.virustotal_hash(indicator))
            indicator.results += background_tasks.add(tools.hybrid_analysis(indicator))
            indicator.results += background_tasks.add(tools.malware_bazzar(indicator))
            indicator.results += background_tasks.add(tools.inquestlabs(indicator))
            indicator.results += background_tasks.add(tools.maltiverse(indicator))

        elif indicator.indicator_type == "hash.sha256":
            indicator.results += background_tasks.add(tools.circl_lu(indicator))
            indicator.results += background_tasks.add(tools.echo_trail(indicator))
            indicator.results += background_tasks.add(tools.tweetfeed_live(indicator))
            indicator.results += background_tasks.add(tools.virustotal_hash(indicator))
            indicator.results += background_tasks.add(tools.hybrid_analysis(indicator))
            indicator.results += background_tasks.add(tools.malware_bazzar(indicator))
            indicator.results += background_tasks.add(tools.inquestlabs(indicator))
            indicator.results += background_tasks.add(tools.maltiverse(indicator))

        elif indicator.indicator_type == "hash.sha512":
            indicator.results += background_tasks.add(tools.virustotal_hash(indicator))
            indicator.results += background_tasks.add(tools.inquestlabs(indicator))
            indicator.results += background_tasks.add(tools.maltiverse(indicator))

        elif indicator.indicator_type == "mac":
            indicator.results += background_tasks.add(tools.macvendors(indicator))

        # fmt: on

        if indicator.results:
            notifications.console_output(
                "Indicator has tool results",
                indicator,
                "BLUE",
            )
            notifications.send_message_to_slack(
                indicator, notifications.successful_scan(indicator)
            )
        else:
            notifications.console_output("No results found", indicator, "RED")
            indicator.results += (
                {
                    "site": "No Results",
                    "results": {"Error": "No results found"},
                },
            )

        """ Check if the indicator is in any of the feedlists """

        search_feedlists = background_tasks.add(tools.search_feedlists(indicator, db))
        indicator.feedlist_results = search_feedlists if search_feedlists else None

        if indicator.feedlist_results:
            notifications.console_output(
                "Indicator found in feedlists",
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
        indicator.complete = True
        db.add(indicator)
        db.commit()
        t1_stop = process_time()
        notifications.console_output(
            f"Indicator has been completed in {t1_stop - t1_start}",
            indicator,
            "BLUE",
        )

    except Exception as e:
        notifications.console_output(
            f"Error: {traceback.format_exc()}", indicator, "RED"
        )
        indicator.complete = True
        indicator.results = (
            {
                "site": "Error",
                "results": {"Error": str(e)},
            },
        )
        indicator.tags = {"Error": True}
        db.add(indicator)
        db.commit()
