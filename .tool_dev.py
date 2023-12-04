import json
import random
import app.osint.tools as tools
from datetime import datetime
from app.osint import tagging_handler, links_handler, enrichments_handler
from app.database import SessionManager
from app.osint.utils import (
    get_type,
    remove_missingapikey_results,
    sort_results,
    refang,
)


class TestIndicator:
    def __init__(self, indicator, db):
        """
        Initialize the TestIndicator object with an indicator to search for
        """
        self.db = db
        self.id = random.randint(1, 999)
        self.time_created = datetime.now()
        self.time_updated = None
        self.processing_time = None
        self.creator = "test_user"
        self.username = "test_user"
        self.indicator = refang(indicator).strip()
        self.indicator_type = get_type(self.indicator)
        self.feedlist_results = []
        self.results = []
        self.external_links = []
        self.tags = []
        self.notes = None
        self.enrichments = []
        self.complete = False
        self.ioc_id = None
        self.ioc = None

    def run_tools(self):
        """
        Run all tools on the indicator
        """
        self.results = tools.run_tools(self)
        self.results = sorted(self.results, key=sort_results)
        self.results = remove_missingapikey_results(self.results)
        return self.results

    def run_tagging(self):
        """
        Tag the indicator
        """
        self.run_tools()
        print(json.dumps(self.results, indent=4))
        self.tags = tagging_handler(self)
        return self.tags

    def get_links(self):
        """
        Add external links to the indicator
        """
        self.external_links = links_handler(self)
        return self.external_links

    def get_enrichments(self):
        """
        Add enrichments to the indicator
        """
        self.run_tools()
        self.enrichments = enrichments_handler(self)
        return self.enrichments

    def get_feedlist_results(self):
        """
        Add feedlist results to the indicator
        """

        self.feedlist_results = tools.search_feedlists(
            self,
            self.db,
        )
        return self.feedlist_results


def print_and_write_output(data):
    print(json.dumps(data, indent=4))
    with open("./.tool_dev.json", "w") as outfile:
        json.dump(data, outfile, indent=4)


with SessionManager() as db:
    indicator = TestIndicator(
        indicator="00sms.xyz",
        db=db,
    )

    # Run a specific tool
    # print_and_write_output(tools.malware_bazzar(indicator))

    # Run all tools
    # print_and_write_output(indicator.run_tools())

    # Run tagging
    # print_and_write_output(indicator.run_tagging())

    # Get external links
    # print_and_write_output(indicator.get_links())

    # Get enrichments
    # print_and_write_output(indicator.get_enrichments())

    # Get feedlist results
    print_and_write_output(indicator.get_feedlist_results())
