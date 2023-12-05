import requests
from ... import notifications
from ...models import FeedLists
from thefuzz import fuzz
from ..utils import (
    get_feedlist_type,
    convert_email_to_fqdn,
    convert_url_to_fqdn,
)


def feedlists_handler(indicator, db, feedlist_result_queue=None):
    def update_queue(results, feedlist_result_queue=None):
        if feedlist_result_queue:
            feedlist_result_queue.put(results)

    def load_top_domains_list():
        with open("./config/top_domains_list.txt", "r") as f:
            return f.read().splitlines()

    results = []
    feedlists_to_search = []

    list_type = get_feedlist_type(indicator.indicator_type)
    if not list_type:
        update_queue(results, feedlist_result_queue)
        return None

    type_feedlists = FeedLists.get_active_feedlists_by_type(list_type, db)
    any_feedlists = FeedLists.get_active_any_type_feedlist(db)

    if type_feedlists:
        for x in type_feedlists:
            feedlists_to_search.append(x)

    if any_feedlists:
        for x in any_feedlists:
            feedlists_to_search.append(x)

    if not feedlists_to_search:
        update_queue(results, feedlist_result_queue)
        return None

    notifications.console_output(
        f"Searching for indicator in {len(feedlists_to_search)} feedlists",
        indicator,
        "BLUE",
    )

    top_domains_list = load_top_domains_list()
    for feedlist in feedlists_to_search:
        try:
            search_results = perform_search(indicator, feedlist, top_domains_list)
            if search_results:
                results.append(search_results)

        except Exception as e:
            notifications.console_output(str(e), indicator, "RED")
            continue

    update_queue(results, feedlist_result_queue)
    return results if results else None


def perform_search(indicator, feedlist, top_domains_list):
    def set_searchstring(indicator):
        output = indicator.indicator

        if indicator.indicator_type == "url":
            output = convert_url_to_fqdn(indicator.indicator)
        elif indicator.indicator_type == "email":
            output = convert_email_to_fqdn(indicator.indicator)

        for domain in top_domains_list:
            if output in domain:
                return None

        return output

    try:
        search_string = set_searchstring(indicator)
        if not search_string:
            return None

        req = requests.get(feedlist.url)
        if req.status_code != 200:
            raise Exception("Did not get a 200 OK response from the feedlist.")

        results = {}
        lines = req.text.splitlines()

        for line in lines:
            if not line:
                continue

            match = False
            match_types = []
            if fuzz.ratio(search_string, line) > 85:
                match = True
                match_types.append("fuzzy")

            if search_string in line:
                match = True
                match_types.append("substring")

            if search_string == line:
                match = True
                match_types.append("exact")

            if match and not ("feedlist", feedlist.name) in results.items():
                results.update(
                    {
                        "feedlist_id": feedlist.id,
                        "match": line,
                        "match_type": match_types,
                        "feedlist": feedlist.name,
                        "description": feedlist.description,
                        "category": feedlist.category,
                        "list_period": feedlist.list_period,
                        "list_type": feedlist.list_type,
                        "url": feedlist.url,
                    }
                )

        return results if results else None

    except Exception as e:
        raise Exception(
            f"Error during searching through {feedlist.name}(ID-{feedlist.id}) {str(e)} "
        )
