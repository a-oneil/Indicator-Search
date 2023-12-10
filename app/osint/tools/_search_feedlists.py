import asyncio
import httpx
from ... import notifications
from ...models import FeedLists
from thefuzz import fuzz
from ..utils import (
    get_feedlist_type,
    convert_email_to_fqdn,
    convert_url_to_fqdn,
)


def load_top_domains_list():
    with open("./config/top_domains_list.txt", "r") as f:
        return f.read().splitlines()


def set_searchstring(indicator):
    output = indicator.indicator
    if indicator.indicator_type == "url":
        output = convert_url_to_fqdn(indicator.indicator)
    elif indicator.indicator_type == "email":
        output = convert_email_to_fqdn(indicator.indicator)
    for domain in top_domains_list:
        if output in domain:
            raise Exception("Indicator is a top domain.")
    return output


top_domains_list = load_top_domains_list()


async def feedlists_handler(indicator, db):
    results = []
    feedlists_to_search = []
    client = httpx.AsyncClient()

    list_type = get_feedlist_type(indicator.indicator_type)

    feedlists_to_search.extend(
        FeedLists.get_active_feedlists_by_type(list_type, db) or []
    )

    feedlists_to_search.extend(FeedLists.get_active_any_type_feedlist(db) or [])

    if not feedlists_to_search:
        return None

    notifications.console_output(
        f"Searching for indicator in {len(feedlists_to_search)} feedlists",
        indicator,
        "BLUE",
    )

    for feedlist in feedlists_to_search:
        try:
            search_results = asyncio.gather(perform_search(indicator, feedlist, client))

            search_results = await search_results
            if search_results:
                results.extend(search_results)

        except Exception:
            continue

    client.aclose()
    return results if results else None


async def perform_search(indicator, feedlist, client):
    try:
        search_string = set_searchstring(indicator)

        response = await client.get(feedlist.url)
        if response.status_code != 200:
            raise Exception("Did not get a 200 OK response from the feedlist.")

        lines = response.text.splitlines()
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

            if match:
                return {
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
        raise Exception("Indicator not found in feedlist.")

    except Exception as e:
        raise Exception(e)
