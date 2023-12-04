import time
import traceback
import threading
from . import enrichments_handler, tagging_handler, links_handler
from .. import notifications
from ..models import Iocs
from sqlalchemy.orm import Session
from .utils import sort_results, remove_missingapikey_results
from .tools import run_tools, search_feedlists


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

        # Run the tools based on the indicator type
        indicator.results = run_tools(indicator)
        # Remove tools that did not have an API key set
        indicator.results = remove_missingapikey_results(indicator.results)
        # Sort results based on if the tool had results or not
        indicator.results = sorted(indicator.results, key=sort_results)

        notifications.console_output(
            f"OSINT Scan complete - {len(indicator.results)} tools ran",
            indicator,
            "BLUE",
        )

        # Wait for feedlist thread to finish
        if threads_to_wait_for:
            for thread in threads_to_wait_for:
                thread.join()

        if indicator.feedlist_results:
            notifications.console_output(
                f"Indicator found in {len(indicator.feedlist_results)} feeds",
                indicator,
                "BLUE",
            )

        # Tagging and enriching using useful info from results
        add_tags = tagging_handler(indicator, db)
        indicator.tags = add_tags if add_tags else None
        if indicator.tags:
            notifications.console_output(
                "Indicator has been tagged",
                indicator,
                "BLUE",
            )

        # Add external links to indicattor
        add_links = links_handler(indicator)
        indicator.external_links = add_links if add_links else None

        # Add external enrichments to results
        add_enrichments = enrichments_handler(indicator)
        indicator.enrichments = add_enrichments if add_enrichments else None
        if indicator.enrichments:
            notifications.console_output(
                "Indicator has enrichements",
                indicator,
                "BLUE",
            )

        # Search if this indicator has been IOC'd before
        indicator = Iocs.search_for_ioc(indicator, db)

        # Mark indicator as complete and commit to database
        t1_stop = time.time()
        processing_time = t1_stop - t1_start
        indicator.complete = True
        indicator.processing_time = processing_time
        db.add(indicator)
        db.commit()
        notifications.console_output(
            f"Indicator has been processed in {processing_time} seconds",
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
