import time
import traceback
import threading
import queue
from . import enrichments_handler, tagging_handler, links_handler
from .. import notifications
from ..models import Iocs
from sqlalchemy.orm import Session
from .utils import sort_results, remove_missingapikey_results
from .tools import run_tools, feedlists_handler


def new_indicator_handler(indicator, user, db: Session):
    try:
        t1_start = time.time()
        notifications.console_output(
            f"New indicator added by {user.username}, starting scan for {indicator.indicator_type}: {indicator.indicator}",
            indicator,
            "BLUE",
        )

        # Search for indicator in active feedlists in a new thread
        threads_to_wait_for = []
        feedlist_result_queue = queue.Queue()
        thread = threading.Thread(
            target=feedlists_handler,
            daemon=False,
            args=(indicator, db, feedlist_result_queue),
        )
        threads_to_wait_for.append(thread)
        thread.start()

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
            indicator.feedlist_results = feedlist_result_queue.get()
            notifications.console_output(
                f"Indicator found in {len(indicator.feedlist_results)} feeds",
                indicator,
                "BLUE",
            )
        else:
            indicator.feedlist_results = None

        # Tagging and enriching using useful info from results
        add_tags = tagging_handler(indicator)
        if add_tags:
            indicator.tags = add_tags
            notifications.console_output(
                "Indicator has been tagged",
                indicator,
                "BLUE",
            )
        else:
            indicator.tags = None

        # Add external links to indicator
        add_links = links_handler(indicator)
        indicator.external_links = add_links if add_links else None

        # Add external enrichments to results
        add_enrichments = enrichments_handler(indicator)
        if add_enrichments:
            indicator.enrichments = add_enrichments
            notifications.console_output(
                "Indicator has enrichements",
                indicator,
                "BLUE",
            )
        else:
            indicator.enrichments = None

        # Search if this indicator has been IOC'd before
        previously_iocd = Iocs.get_ioc_by_indicator(indicator.indicator, db)
        if previously_iocd:
            indicator.ioc_id = previously_iocd.id
            tags_dict = indicator.tags if indicator.tags else {}
            tags_dict.update({"ioc": previously_iocd.id})
            indicator.tags = tags_dict
            notifications.console_output(
                f"Indicator has been IOC'd before (IOC ID: {previously_iocd.id})",
                indicator,
                "BLUE",
            )

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
