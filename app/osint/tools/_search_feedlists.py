import requests
from ... import notifications
from ...models import FeedLists, Indicators
from ..utils import (
    get_feedlist_type,
    remove_ip_address,
    convert_email_to_fqdn,
    convert_url_to_fqdn,
)


def search_feedlists(indicator, db):
    def perform_search(indicator, feedlist, list_type):
        try:
            if indicator.indicator_type == "url":
                search_string = convert_url_to_fqdn(indicator.indicator)
            elif indicator.indicator_type == "email":
                search_string = convert_email_to_fqdn(indicator.indicator)
            else:
                search_string = indicator.indicator

            req = requests.get(feedlist.url)
            if req.status_code == 200:
                results = {}
                lines = req.text.splitlines()
                for line in lines:
                    line = remove_ip_address(line) if list_type == "fqdn" else line
                    if (
                        search_string in line
                        and not ("feedlist", feedlist.name) in results.items()
                    ):
                        results.update(
                            {
                                "feedlist_id": feedlist.id,
                                "match": line,
                                "feedlist": feedlist.name,
                                "description": feedlist.description,
                                "category": feedlist.category,
                                "list_period": feedlist.list_period,
                                "list_type": feedlist.list_type,
                                "url": feedlist.url,
                            }
                        )
            else:
                raise Exception("Did not get a 200 OK response from the feedlist.")

            if results:
                return results
            else:
                return None

        except Exception as e:
            raise Exception(
                f"Error during searching through {feedlist.name}(ID-{feedlist.id}) {str(e)} "
            )

    results = []

    list_type = get_feedlist_type(indicator)

    if list_type:
        feedlists_to_search = []

        list_type_match = FeedLists.get_active_feedlists_by_type(list_type, db)
        if list_type_match:
            for x in list_type_match:
                feedlists_to_search.append(x)

        any_type_lists = FeedLists.any_list_type_feedlists(db)
        if any_type_lists:
            for x in any_type_lists:
                feedlists_to_search.append(x)

        if not feedlists_to_search:
            return None

        notifications.console_output(
            f"{len(feedlists_to_search)} {list_type} feedlists enabled. Searching feedlists now",
            indicator,
            "BLUE",
        )

        for feedlist in feedlists_to_search:
            try:
                notifications.console_output(
                    f"Searching for indicator in {feedlist.name} - {feedlist.list_type}",
                    indicator,
                    "BLUE",
                )
                search_results = perform_search(indicator, feedlist, list_type)
                if search_results:
                    results.append(search_results)

            except Exception as e:
                notifications.console_output(str(e), indicator, "RED")
                continue

    if results:
        return Indicators.save_feedlist_results(indicator.id, results, db)
    else:
        return None
