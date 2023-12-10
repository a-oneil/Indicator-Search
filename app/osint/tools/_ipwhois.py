import ipwhois
from ..utils import failed_to_run


def search_ipwhois(indicator):
    try:
        obj = ipwhois.IPWhois(indicator.indicator)
        return {
            "tool": "ip_whois",
            "outcome": {
                "status": "results_found",
                "error_message": None,
                "status_code": None,
                "reason": None,
            },
            "results": {
                "asn_number": obj.lookup_rws().get("asn"),
                "asn_registry": obj.lookup_rws().get("asn_registry"),
                "asn_date": obj.lookup_rws().get("asn_date"),
                "cidr": obj.lookup_rws().get("nets")[0].get("cidr"),
                "description": obj.lookup_rws().get("nets")[0].get("description"),
                "country": obj.lookup_rws().get("nets")[0].get("country"),
                "state": obj.lookup_rws().get("nets")[0].get("state"),
                "city": obj.lookup_rws().get("nets")[0].get("city"),
                "address": obj.lookup_rws().get("nets")[0].get("address"),
                "postal_code": obj.lookup_rws().get("nets")[0].get("postal_code"),
                "abuse_emails": obj.lookup_rws().get("nets")[0].get("emails"),
                "tech_emails": obj.lookup_rws().get("nets")[0].get("tech_emails"),
            },
        }

    except Exception as error_message:
        return failed_to_run(tool_name="ip_whois", error_message=error_message)
