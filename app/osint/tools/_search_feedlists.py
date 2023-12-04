import requests
from ... import notifications
from ...models import FeedLists
from ..utils import (
    get_feedlist_type,
    remove_ip_address,
    convert_email_to_fqdn,
    convert_url_to_fqdn,
)


def feedlists_handler(indicator, db, feedlist_result_queue=None):
    def update_queue(results, feedlist_result_queue=None):
        if feedlist_result_queue:
            feedlist_result_queue.put(results)

    results = []
    feedlists_to_search = []

    list_type = get_feedlist_type(indicator)
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

    for feedlist in feedlists_to_search:
        try:
            search_results = perform_search(indicator, feedlist, list_type)
            if search_results:
                results.append(search_results)

        except Exception as e:
            notifications.console_output(str(e), indicator, "RED")
            continue

    update_queue(results, feedlist_result_queue)
    return results if results else None


def perform_search(indicator, feedlist, list_type):
    def set_searchstring(indicator):
        if indicator.indicator_type == "url":
            return convert_url_to_fqdn(indicator.indicator)
        elif indicator.indicator_type == "email":
            return convert_email_to_fqdn(indicator.indicator)
        return indicator.indicator

    try:
        search_string = set_searchstring(indicator)
        req = requests.get(feedlist.url)
        if req.status_code != 200:
            raise Exception("Did not get a 200 OK response from the feedlist.")

        results = {}
        lines = req.text.splitlines()

        for line in lines:
            line = remove_ip_address(line) if list_type == "fqdn" else line

            if search_string in line:
                print(f"{search_string} found in {line}")
            if search_string == line:
                print(f"{search_string} == {line}")

            # results.update(
            #     {
            #         "feedlist_id": feedlist.id,
            #         "match": line,
            #         "feedlist": feedlist.name,
            #         "description": feedlist.description,
            #         "category": feedlist.category,
            #         "list_period": feedlist.list_period,
            #         "list_type": feedlist.list_type,
            #         "url": feedlist.url,
            #     }
            # )

        return results if results else None

    except Exception as e:
        raise Exception(
            f"Error during searching through {feedlist.name}(ID-{feedlist.id}) {str(e)} "
        )
