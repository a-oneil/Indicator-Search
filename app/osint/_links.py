from .. import config


def links_handler(indicator):
    links = {}
    if indicator.indicator_type == "ipv4":
        links.update(
            {
                "virustotal": f"https://www.virustotal.com/gui/ip-address/{indicator.indicator}",
                "abuseipdb": f"https://www.abuseipdb.com/check/{indicator.indicator}",
                "greynoise": f"https://viz.greynoise.io/ip/{indicator.indicator}",
                "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    if indicator.indicator_type == "ipv6":
        links.update(
            {
                "abuseipdb": f"https://www.abuseipdb.com/check/{indicator.indicator}",
                "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
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
                "virustotal": f"https://www.virustotal.com/gui/file/{indicator.indicator}",
                "hybrid_analysis": f"https://www.hybrid-analysis.com/search?query={indicator.indicator}",
                "joes_sandbox": f"https://www.joesandbox.com/search?q={indicator.indicator}",
                "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    elif indicator.indicator_type == "fqdn":
        links.update(
            {
                "virustotal": f"https://www.virustotal.com/gui/domain/{indicator.indicator}",
                "mx_toolbox": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{indicator.indicator}&run=toolpage",
                "urlscan.io": f"https://urlscan.io/search/#{indicator.indicator.replace('https://', '').replace('http://', '')}",
                "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    elif indicator.indicator_type == "url":
        links.update(
            {
                "virustotal": f"https://www.virustotal.com/gui/domain/{indicator.indicator}",
                "mx_toolbox": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{indicator.indicator}&run=toolpage",
                "urlscan.io": f"https://urlscan.io/search/#{indicator.indicator.replace('https://', '').replace('http://', '')}",
                "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    elif indicator.indicator_type == "email":
        links.update(
            {
                "emailrep.io": f"https://emailrep.io/{indicator.indicator}",
                "mx_toolbox": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{indicator.indicator.split('@')[1]}&run=toolpage",
                "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )
    elif indicator.indicator_type == "mac":
        links.update(
            {
                "mac_vendor_lookup": f"https://api.macvendors.com/{indicator.indicator}",
                "json": f"{config['SERVER_ADDRESS']}/api/indicator/{indicator.id}",
            },
        )

    return links
