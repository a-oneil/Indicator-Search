from .. import config


def links_handler(indicator):
    if indicator.indicator_type == "ipv4":
        return {
            "virustotal": f"https://www.virustotal.com/gui/ip-address/{indicator.indicator}",
            "abuseipdb": f"https://www.abuseipdb.com/check/{indicator.indicator}",
            "greynoise": f"https://viz.greynoise.io/ip/{indicator.indicator}",
            "google": f"https://www.google.com/search?q={indicator.indicator}",
            "twitter": f"https://twitter.com/search?q={indicator.indicator}&src=typed_query",
            "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
        }

    if indicator.indicator_type == "ipv6":
        return {
            "abuseipdb": f"https://www.abuseipdb.com/check/{indicator.indicator}",
            "google": f"https://www.google.com/search?q={indicator.indicator}",
            "twitter": f"https://twitter.com/search?q={indicator.indicator}&src=typed_query",
            "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
        }

    elif indicator.indicator_type in [
        "hash.md5",
        "hash.sha1",
        "hash.sha256",
        "hash.sha512",
    ]:
        return {
            "virustotal": f"https://www.virustotal.com/gui/file/{indicator.indicator}",
            "hybrid_analysis": f"https://www.hybrid-analysis.com/search?query={indicator.indicator}",
            "joes_sandbox": f"https://www.joesandbotwitter/search?q={indicator.indicator}",
            "google": f"https://www.google.com/search?q={indicator.indicator}",
            "twitter": f"https://twitter.com/search?q={indicator.indicator}&src=typed_query",
            "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
        }

    elif indicator.indicator_type == "fqdn":
        return {
            "virustotal": f"https://www.virustotal.com/gui/domain/{indicator.indicator}",
            "mx_toolbox": f"https://mxtoolbotwitter/SuperTool.aspx?action=mx%3a{indicator.indicator}&run=toolpage",
            "urlscan.io": f"https://urlscan.io/search/#{indicator.indicator.replace('https://', '').replace('http://', '')}",
            "google": f"https://www.google.com/search?q={indicator.indicator}",
            "twitter": f"https://twitter.com/search?q={indicator.indicator}&src=typed_query",
            "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
        }

    elif indicator.indicator_type == "url":
        return {
            "virustotal": f"https://www.virustotal.com/gui/domain/{indicator.indicator}",
            "mx_toolbox": f"https://mxtoolbotwitter/SuperTool.aspx?action=mx%3a{indicator.indicator}&run=toolpage",
            "urlscan.io": f"https://urlscan.io/search/#{indicator.indicator.replace('https://', '').replace('http://', '')}",
            "google": f"https://www.google.com/search?q={indicator.indicator}",
            "twitter": f"https://twitter.com/search?q={indicator.indicator}&src=typed_query",
            "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
        }

    elif indicator.indicator_type == "email":
        return {
            "emailrep.io": f"https://emailrep.io/{indicator.indicator}",
            "mx_toolbox": f"https://mxtoolbotwitter/SuperTool.aspx?action=mx%3a{indicator.indicator.split('@')[1]}&run=toolpage",
            "google": f"https://www.google.com/search?q={indicator.indicator}",
            "twitter": f"https://twitter.com/search?q={indicator.indicator}&src=typed_query",
            "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
        }

    elif indicator.indicator_type == "mac":
        return {
            "mac_vendor_lookup": f"https://api.macvendors.com/{indicator.indicator}",
            "google": f"https://www.google.com/search?q={indicator.indicator}",
            "twitter": f"https://twitter.com/search?q={indicator.indicator}&src=typed_query",
            "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
        }

    elif indicator.indicator_type == "phone":
        return {
            "ip_quality_score": "https://www.ipqualityscore.com/free-phone-number-lookup",
            "google": f"https://www.google.com/search?q={indicator.indicator}",
            "twitter": f"https://twitter.com/search?q={indicator.indicator}&src=typed_query",
            "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
        }

    return {}
