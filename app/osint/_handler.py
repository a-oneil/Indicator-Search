import time
import traceback
from . import enrichments_handler, tagging_handler, links_handler
from ._gpt import get_indicator_summary
from .. import notifications
from ..models import Iocs
from sqlalchemy.orm import Session
from .tools import tool_handler, feedlists_handler


async def new_indicator_handler(indicator, user, db: Session):
    try:
        t1_start = time.time()
        # fmt: off
        notifications.console_output(f"New indicator added by {user.username}, starting scan for {indicator.indicator_type}: {indicator.indicator}", indicator, "BLUE")

        # Run the tools based on the indicator type
        indicator.results = await tool_handler(indicator)

        # Search for indicator in active feedlists
        indicator.feedlist_results = await feedlists_handler(indicator, db)

        # Give the results to OpenAI to summarize the results in a paragraph
        indicator.summary = (await get_indicator_summary(indicator.results) if indicator.results else None)

        # Tagging  using useful info from results
        indicator.tags = (tagging_handler(indicator) if tagging_handler(indicator) else {})

        # Add external links to indicator
        indicator.external_links = (links_handler(indicator) if links_handler(indicator) else {})

        # Add external enrichments to results
        indicator.enrichments = (enrichments_handler(indicator) if enrichments_handler(indicator) else {})

        # Search if this indicator has been IOC'd before
        indicator.ioc_id = (Iocs.get_ioc_by_indicator(indicator.indicator, db).id if Iocs.get_ioc_by_indicator(indicator.indicator, db) else None)
        if indicator.ioc_id:
            tags_dict = indicator.tags if indicator.tags else {}
            tags_dict.update({"ioc": indicator.ioc_id})
            indicator.tags = tags_dict
        
        # Console notificiations on progress
        notifications.console_output(f"Indicator was queried against {len(indicator.results)} tools", indicator, "BLUE") if indicator.results else None

        notifications.console_output(f"Indicator found in {len(indicator.feedlist_results)} feeds", indicator, "BLUE") if indicator.feedlist_results else None

        notifications.console_output(f"Indicator has {len(indicator.tags)} tags", indicator, "BLUE") if indicator.tags else None

        notifications.console_output(f"Indicator has {len(indicator.enrichments)} enrichments", indicator, "BLUE") if indicator.enrichments else None

        notifications.console_output(f"Indicator has been IOC'd before (IOC ID: {indicator.ioc_id})", indicator, "BLUE") if indicator.ioc_id else None

        # Mark indicator as complete, commit to database, notifications of completion
        t1_stop = time.time()
        processing_time = t1_stop - t1_start
        indicator.complete = True
        indicator.processing_time = processing_time
        db.add(indicator)
        db.commit()
        notifications.console_output(f"Indicator has been processed in {processing_time} seconds", indicator, "BLUE")
        notifications.slack_indicator_complete(indicator, "success")
        # fmt: on

    except Exception as error_message:
        indicator.complete = True
        indicator.results = {
            "tool": "Indicator Search",
            "outcome": {
                "status": "failed_to_run",
                "error_message": str(error_message),
                "status_code": 500,
                "reason": "Internal Server Error",
            },
            "results": {},
        }
        indicator.tags = {"error": True}
        db.add(indicator)
        db.commit()
        notifications.console_output(
            f"Error: {traceback.format_exc()}", indicator, "RED"
        )
        notifications.slack_indicator_complete(indicator, "failure")
