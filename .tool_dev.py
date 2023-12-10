import json
import random
import argparse
import traceback
import app.osint.tools as tools
from datetime import datetime
from app import color
from app.osint import (
    tagging_handler,
    links_handler,
    enrichments_handler,
    get_indicator_summary,
)
from app.database import SessionManager
from app.osint.utils import (
    get_type,
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
        self.results = tools.tool_handler(self)

        return self.results

    def run_tagging(self):
        """
        Tag the indicator
        """
        self.run_tools()
        print(json.dumps(self.results, indent=4))
        print(
            f"\n{color.BLUE}The JSON above are the indicator results for reference.{color.ENDCOLOR}"
        )
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
        print(json.dumps(self.results, indent=4))
        print(
            f"\n{color.BLUE}The JSON above are the indicator results for reference.{color.ENDCOLOR}"
        )
        self.enrichments = enrichments_handler(self)
        return self.enrichments

    def get_feedlist_results(self):
        """
        Add feedlist results to the indicator
        """
        self.feedlist_results = tools.feedlists_handler(
            self,
            self.db,
        )
        return self.feedlist_results


def print_and_write_output(data, args):
    def print_argument_names(args):
        for arg_name, arg_value in vars(args).items():
            if arg_value != parser.get_default(arg_name):
                print(f"{arg_name} = {arg_value}")

    if data:
        print(f"\n{color.BLUE}==== Testing output ===={color.ENDCOLOR}\n")
        print(json.dumps(data, indent=4))
        with open("./.tool_dev.json", "w") as outfile:
            json.dump(data, outfile, indent=4)
    else:
        print(f"\n{color.RED}No output using the following arguments:{color.ENDCOLOR}")
        print_argument_names(args)


def call_function_if_exists(function_name, indicator):
    if hasattr(tools, function_name) and callable(getattr(tools, function_name)):
        func = getattr(tools, function_name)
        return func(indicator)
    else:
        available_functions = [
            func for func in dir(tools) if callable(getattr(tools, func))
        ]
        print(f"{color.YELLOW}Available tools to run:{color.ENDCOLOR}")
        print("\n".join(available_functions))
        return None


try:
    parser = argparse.ArgumentParser(
        description="Indicator Search Tool Dev Framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--indicator",
        action="store",
        help="Pass an indicator to test with",
        required=True,
    )
    parser.add_argument(
        "--tool",
        action="store",
        help="Enter a specific tool name to run from the tools directory",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all tools against an indicator",
    )
    parser.add_argument(
        "--tags",
        action="store_true",
        help="Get tags for an indicator",
    )
    parser.add_argument(
        "--links",
        action="store_true",
        help="Get links for an indicator",
    )
    parser.add_argument(
        "--enrichments",
        action="store_true",
        help="Get enrichments for an indicator",
    )
    parser.add_argument(
        "--feedlists",
        action="store_true",
        help="Get feedlist results for an indicator",
    )

    parser.add_argument(
        "--openai",
        action="store_true",
        help="Get a short description of the indicator using OpenAI's API",
    )

    if parser.parse_args().indicator:
        indicator = parser.parse_args().indicator
    else:
        indicator = input("Enter an indicator to search for: ")

    with SessionManager() as db:
        # fmt: off
        indicator = TestIndicator(indicator=indicator, db=db)

        if parser.parse_args().tool:
            print_and_write_output(
                call_function_if_exists(parser.parse_args().tool.strip(), indicator), parser.parse_args(),
            )

        elif parser.parse_args().all:
            print_and_write_output(indicator.run_tools(), parser.parse_args())

        elif parser.parse_args().tags:
            print_and_write_output(indicator.run_tagging(), parser.parse_args())

        elif parser.parse_args().links:
            print_and_write_output(indicator.get_links(), parser.parse_args())

        elif parser.parse_args().enrichments:
            print_and_write_output(indicator.get_enrichments(), parser.parse_args())
        
        elif parser.parse_args().feedlists:
            print_and_write_output(indicator.get_feedlist_results(), parser.parse_args())
        
        elif parser.parse_args().openai:
            results = indicator.run_tools()
            print(get_indicator_summary(results).choices[0].message.content)
        
        else:
            print_and_write_output(indicator.run_tools(), parser.parse_args())
        # fmt: on

except Exception:
    traceback.print_exc()
