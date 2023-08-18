from .. import config


def links_handler(indicator):
    links = {}
    if indicator.indicator_type == "ipv4":
        links.update(
            {
                "VirusTotal": f"https://www.virustotal.com/gui/ip-address/{indicator.indicator}",
                "AbuseIP DB": f"https://www.abuseipdb.com/check/{indicator.indicator}",
                "Greynoise": f"https://viz.greynoise.io/ip/{indicator.indicator}",
                "JSON": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    if indicator.indicator_type == "ipv6":
        links.update(
            {
                "AbuseIP DB": f"https://www.abuseipdb.com/check/{indicator.indicator}",
                "JSON": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    elif indicator.indicator_type in [
        "hash.md5",
        "hash.sha1",
        "hash.sha256",
        "hash.sha512",
    ]:
        links.update(
            {
                "VirusTotal": f"https://www.virustotal.com/gui/file/{indicator.indicator}",
                "Hybrid Analysis": f"https://www.hybrid-analysis.com/search?query={indicator.indicator}",
                "Joes Sandbox": f"https://www.joesandbox.com/search?q={indicator.indicator}",
                "JSON": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    elif indicator.indicator_type == "fqdn":
        links.update(
            {
                "VirusTotal": f"https://www.virustotal.com/gui/domain/{indicator.indicator}",
                "MX Toolbox": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{indicator.indicator}&run=toolpage",
                "Urlscan.io": f"https://urlscan.io/search/#{indicator.indicator.replace('https://', '').replace('http://', '')}",
                "JSON": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    elif indicator.indicator_type == "url":
        links.update(
            {
                "VirusTotal": f"https://www.virustotal.com/gui/domain/{indicator.indicator}",
                "MX Toolbox": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{indicator.indicator}&run=toolpage",
                "Urlscan.io": f"https://urlscan.io/search/#{indicator.indicator.replace('https://', '').replace('http://', '')}",
                "JSON": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    elif indicator.indicator_type == "email":
        links.update(
            {
                "Emailrep.io": f"https://emailrep.io/{indicator.indicator}",
                "MX Toolbox": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{indicator.indicator.split('@')[1]}&run=toolpage",
                "JSON": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    elif indicator.indicator_type == "mac":
        links.update(
            {
                "MAC Vendor Lookup": f"https://api.macvendors.com/{indicator.indicator}",
                "JSON": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )

    return links
