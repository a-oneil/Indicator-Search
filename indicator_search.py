import subprocess
import os
import time
from threading import Thread
import argparse


class terminalColors:
    BLUE = "\033[36m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ENDCOLOR = "\033[0m"


def load_config():
    try:
        import json

        f = open("./config/.env", "r")
        config = json.load(f)
        f.close()
        print(f"{color.BLUE}Config file loaded successfully!{color.ENDCOLOR}")
        return config
    except Exception as e:
        print(
            f"{color.RED}Error occurred while loading the file: {str(e)}{color.ENDCOLOR}"
        )
        exit(1)


def toggle_env_value(new_env=None):
    import json

    try:
        with open("./config/.env", "r") as f:
            config = json.load(f)
        current_env = config.get("ENV", "DEV")
        if new_env is None:
            new_env = "PROD" if current_env == "DEV" else "DEV"
        config["ENV"] = new_env

        with open("./config/.env", "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(
            f"{color.RED}Error occurred while updating the file:{color.ENDCOLOR} {str(e)}"
        )


def check_env_status():
    import json

    try:
        with open("./config/.env", "r") as f:
            config = json.load(f)
        current_env = config.get("ENV", "DEV")
        print(f"{color.BLUE}Current ENV status:{color.ENDCOLOR} {current_env}")
    except Exception as e:
        print(
            f"{color.RED}Error occurred while reading the file:{color.ENDCOLOR} {str(e)}"
        )


def menu():
    print("")
    print(f"{color.RED}===== Indicator Search ====={color.ENDCOLOR}")
    check_env_status()
    print(f"{color.BLUE}1.{color.ENDCOLOR} Re-setup enviroment")
    print(f"{color.BLUE}2.{color.ENDCOLOR} Toggle environment")
    print(f"{color.BLUE}3.{color.ENDCOLOR} Run local instance (127.0.0.1:8000)")
    print(f"{color.BLUE}4.{color.ENDCOLOR} Run local instance (0.0.0.0:8000)")
    print(f"{color.BLUE}5.{color.ENDCOLOR} Build docker image")
    print(f"{color.BLUE}6.{color.ENDCOLOR} Seed feedlists database")
    print(f"{color.BLUE}7.{color.ENDCOLOR} Seed indicators")
    print(f"{color.BLUE}8.{color.ENDCOLOR} Delete local sqlite database")
    print(f"{color.BLUE}9.{color.ENDCOLOR} Exit")
    menu_switch(input(f"{color.YELLOW}~> {color.ENDCOLOR}"))


def menu_switch(choice):
    if choice == "1":
        reinstall_packages()
        reconfig()
        menu()
    elif choice == "2":
        toggle_env_value()
        menu()
    elif choice == "3":
        run_local()
    elif choice == "4":
        run_local_global()
    elif choice == "5":
        build_docker_image()
        menu()
    elif choice == "6":
        seed_feedlists()
        menu()
    elif choice == "7":
        seed_indicators()
        menu()
    elif choice == "8":
        delete_sqlite()
    elif choice == "9":
        exit(0)
    else:
        menu()


def ioc_ageout_automation():
    import requests

    first_run = True
    while True:
        if not first_run:
            print("running")
            response = requests.post(
                f"{config['SERVER_ADDRESS']}/api/iocs/ageout",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            for value in response.json().values():
                print(f"{color.YELLOW}IOC Automation: {color.ENDCOLOR}{value}")
            time.sleep(21600)
        else:
            first_run = False
            time.sleep(21600)


def reinstall_packages():
    from sys import platform

    if platform == "linux" or platform == "linux2":
        subprocess.run(
            ["sudo", "apt", "install", "libpq-dev", "python3-dev", "python3-venv"],
            check=True,
        )

    elif platform == "darwin":
        subprocess.run(
            ["brew", "install", "libpq", "virtualenv"],
            check=True,
        )

    else:
        print(f"{color.RED}Unsupported OS{color.ENDCOLOR}")
        exit(1)


def reconfig():
    import shutil

    if not os.path.exists("./config/.env"):
        shutil.copyfile("./config/.env.example", "./config/.env")
        print(
            f"{color.YELLOW}Creating a new .env file from the example{color.ENDCOLOR}"
        )
    else:
        print(f"{color.BLUE}Existing .env file found{color.ENDCOLOR}")

    if os.path.exists("./venv/"):
        print(f"{color.YELLOW}Removing existing environment{color.ENDCOLOR}")
        shutil.rmtree("./venv")
    print(f"{color.YELLOW}Installing dependencies{color.ENDCOLOR}")

    # Setup environment
    subprocess.run(["python3", "-m", "venv", "venv"], check=True)
    subprocess.run(
        [
            "./venv/bin/python3",
            "-m",
            "pip",
            "install",
            "-r",
            "./config/requirements.txt",
        ],
        check=True,
    )


def run_local():
    t = Thread(target=ioc_ageout_automation)
    t.start()
    subprocess.run(
        [
            "./venv/bin/uvicorn",
            "app.main:app",
            "--reload",
            f"--host=127.0.0.1",
            f"--port=8000",
        ],
        check=True,
    )


def run_local_global():
    t = Thread(target=ioc_ageout_automation)
    t.start()
    subprocess.run(
        [
            "./venv/bin/uvicorn",
            "app.main:app",
            f"--host=0.0.0.0",
            f"--port=8000",
        ],
        check=True,
    )


def build_docker_image():
    print("Building docker image")
    subprocess.run(
        [
            "docker",
            "build",
            "-t",
            "indicator-search:latest",
            "-f",
            "Dockerfile",
            ".",
        ],
        check=True,
    )
    print(f"{color.BLUE}Docker image built successfully!{color.ENDCOLOR}")


def seed_feedlists():
    def seed(json_input, list_type):
        from app.database import SessionManager
        from app.models import FeedLists

        with SessionManager() as db:
            for entry in json_input:
                url_already_in_feedlists = FeedLists.get_feedlist_by_url(
                    entry.get("listURL"), db
                )

                if not url_already_in_feedlists:
                    new_feedlist = FeedLists(
                        name=entry.get("name"),
                        category=entry.get("category"),
                        description=entry.get("desc"),
                        url=entry.get("listURL"),
                        list_period=entry.get("period"),
                        list_type=list_type,
                    )

                    db.add(new_feedlist)
                    db.commit()
                    print(
                        f"{color.BLUE}Adding:{color.ENDCOLOR} {entry.get('name')} from {list_type.capitalize()} list."
                    )
                else:
                    print(
                        f"{color.BLUE}Skipping:{color.ENDCOLOR} {entry.get('name')} from {list_type.capitalize()} list. Entry already exists in database."
                    )
                    continue

            db.close()
            print(
                f"{color.BLUE}{list_type.capitalize()} DB Seeding complete{color.ENDCOLOR}"
            )

    domainslists = [
        {
            "name": "Referrer-spam-blacklist",
            "category": "Suspicious",
            "listURL": "https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt",
        },
        {
            "name": "KADhosts",
            "category": "Suspicious",
            "listURL": "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
        },
        {
            "name": "FadeMind-AddSpam",
            "category": "Suspicious",
            "listURL": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
        },
        {
            "name": "Firebog-W3KBL",
            "category": "Suspicious",
            "listURL": "https://v.firebog.net/hosts/static/w3kbl.txt",
        },
        {
            "name": "Easyprivacy",
            "category": "Tracking & Telemetry Lists",
            "listURL": "https://v.firebog.net/hosts/Easyprivacy.txt",
        },
        {
            "name": "Prigent-Ads",
            "category": "Tracking & Telemetry Lists",
            "listURL": "https://v.firebog.net/hosts/Prigent-Ads.txt",
        },
        {
            "name": "FadeMind-2o7Net",
            "category": "Tracking & Telemetry Lists",
            "listURL": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
        },
        {
            "name": "WindowsSpyBlocker-spy",
            "category": "Tracking & Telemetry Lists",
            "listURL": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
        },
        {
            "name": "Frogeye-firstparty-trackers",
            "category": "Tracking & Telemetry Lists",
            "listURL": "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
        },
        {
            "name": "DandelionSprout Anti-Malware List",
            "category": "Malicious Lists",
            "listURL": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
        },
        {
            "name": "DigitalSide Threat Intel",
            "category": "Malicious Lists",
            "listURL": "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
        },
        {
            "name": "Disconnect.me Simple Malvertising",
            "category": "Malicious Lists",
            "listURL": "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
        },
        {
            "name": "Prigent-Crypto",
            "category": "Malicious Lists",
            "listURL": "https://v.firebog.net/hosts/Prigent-Crypto.txt",
        },
        {
            "name": "FadeMind Risk List",
            "category": "Malicious Lists",
            "listURL": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
        },
        {
            "name": "Mandiant APT1 Report",
            "category": "Malicious Lists",
            "listURL": "https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt",
        },
        {
            "name": "Phishing Army Extended Blocklist",
            "category": "Malicious Lists",
            "listURL": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        },
        {
            "name": "notrack-malware",
            "category": "Malicious Lists",
            "listURL": "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
        },
        {
            "name": "RPiList-Malware",
            "category": "Malicious Lists",
            "listURL": "https://v.firebog.net/hosts/RPiList-Malware.txt",
        },
        {
            "name": "RPiList-Phishing",
            "category": "Malicious Lists",
            "listURL": "https://v.firebog.net/hosts/RPiList-Phishing.txt",
        },
        {
            "name": "Spam404 Main Blacklist",
            "category": "Malicious Lists",
            "listURL": "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
        },
        {
            "name": "Stalkerware Indicators",
            "category": "Malicious Lists",
            "listURL": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts",
        },
        {
            "name": "URLhaus Hostfile",
            "category": "Malicious Lists",
            "listURL": "https://urlhaus.abuse.ch/downloads/hostfile/",
        },
    ]

    iplists = [
        {
            "name": "Blocklist.de",
            "category": "abuse",
            "desc": "All IP addresses that have attacked one of our customers/servers in the last 48 hours.",
            "listURL": "https://lists.blocklist.de/lists/all.txt",
            "period": "48 hours",
        },
        {
            "name": "botvrij.eu",
            "desc": "Indicators of Compromise (IOCS) about malicious destination IPs, gathered via open source information feeds",
            "category": "attacks",
            "listURL": "http://www.botvrij.eu/data/ioclist.ip-dst.raw",
            "period": "6 months",
        },
        {
            "name": "myip.ms",
            "desc": "IPs identified as web bots in the last 15 minutes, using several sites that require human action",
            "category": "abuse",
            "listURL": "http://www.myip.ms/files/blacklist/csf/latest_blacklist.txt",
            "period": "10 days",
        },
        {
            "name": "NiX Spam",
            "desc": "IP addresses that have sent spam in the last twelve hours.",
            "category": "spam",
            "listURL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/nixspam.ipset",
            "period": "12 hours",
        },
        {
            "name": "Tor Exit Nodes",
            "desc": "Tor Exit Nodes in the last 30 days",
            "category": "anonymizers",
            "listURL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits_30d.ipset",
            "period": "30 days",
        },
        {
            "name": "Malc0de",
            "desc": "Malcode malicious IPs of the last 30 days",
            "category": "malware",
            "listURL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malc0de.ipset",
            "period": "30 days",
        },
        {
            "name": "Malware Domain List",
            "desc": "List of malware active ip addresses in the last twelve hours.",
            "category": "malware",
            "listURL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malwaredomainlist.ipset",
            "period": "12 hours",
        },
        {
            "name": "Threat Crowd",
            "desc": "Crowd-sourcing list of malicious IPs in the last hour.",
            "category": "abuse",
            "listURL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/threatcrowd.ipset",
            "period": "1 hour",
        },
        {
            "name": "Alien Vault",
            "desc": "Alien Vault list of malicious IPs in the last six hours.",
            "category": "abuse",
            "listURL": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset",
            "period": "6 hours",
        },
        {
            "name": "Binary Defense",
            "desc": "Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed",
            "category": "abuse",
            "listURL": "https://www.binarydefense.com/banlist.txt",
            "period": "6 hours",
        },
        {
            "name": "Montysecurity Brute Ratel C2",
            "desc": "Montysecurity C2-Tracker IP Threat Intelligence Feed",
            "category": "C2",
            "listURL": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Brute%20Ratel%20C4%20IPs.txt",
            "period": "Nightly",
        },
        {
            "name": "Montysecurity Cobalt Strike",
            "desc": "Montysecurity C2-Tracker IP Threat Intelligence Feed",
            "category": "C2",
            "listURL": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Cobalt%20Strike%20C2%20IPs.txt",
            "period": "Nightly",
        },
        {
            "name": "Montysecurity Sliver C2",
            "desc": "Montysecurity C2-Tracker IP Threat Intelligence Feed",
            "category": "C2",
            "listURL": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver%20C2%20IPs.txt",
            "period": "Nightly",
        },
        {
            "name": "Montysecurity Posh C2",
            "desc": "Montysecurity C2-Tracker IP Threat Intelligence Feed",
            "category": "C2",
            "listURL": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Posh%20C2%20IPs.txt",
            "period": "Nightly",
        },
        {
            "name": "Montysecurity Metasploit",
            "desc": "Montysecurity C2-Tracker IP Threat Intelligence Feed",
            "category": "C2",
            "listURL": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Metasploit%20Framework%20C2%20IPs.txt",
            "period": "Nightly",
        },
        {
            "name": "Montysecurity Havoc C2",
            "desc": "Montysecurity C2-Tracker IP Threat Intelligence Feed",
            "category": "C2",
            "listURL": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Havoc%20C2%20IPs.txt",
            "period": "Nightly",
        },
        {
            "name": "Montysecurity GoPhish C2",
            "desc": "Montysecurity C2-Tracker IP Threat Intelligence Feed",
            "category": "C2",
            "listURL": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/GoPhish%20IPs.txt",
            "period": "Nightly",
        },
        {
            "name": "Montysecurity Mythic C2",
            "desc": "Montysecurity C2-Tracker IP Threat Intelligence Feed",
            "category": "C2",
            "listURL": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Mythic%20C2%20IPs.txt",
            "period": "Nightly",
        },
    ]

    hashlists = [
        {
            "name": "Bazaar Abuse.ch MD5",
            "category": "MD5 Recent additions",
            "listURL": "https://bazaar.abuse.ch/export/txt/md5/recent/",
        },
        {
            "name": "Threatfox Abuse.ch MD5",
            "category": "MD5 Recently found malicious files on C2",
            "listURL": "https://threatfox.abuse.ch/export/txt/md5/recent/",
        },
        {
            "name": "Bazaar Abuse.ch SHA1",
            "category": "SHA1 Recent additions",
            "listURL": "https://bazaar.abuse.ch/export/txt/sha1/recent/",
        },
        {
            "name": "Bazaar Abuse.ch SHA256",
            "category": "SHA256 Recent additions",
            "listURL": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        },
        {
            "name": "Threatfox Abuse.ch SHA256",
            "category": "SHA256 Recently found malicious files on C2",
            "listURL": "https://threatfox.abuse.ch/export/txt/sha256/recent/",
        },
    ]

    if os.path.exists("./db.sqlite"):
        # fmt: off
        seed(iplists, list_type="ip")
        seed(hashlists, list_type="hash")
        seed(domainslists, list_type="fqdn")
        # fmt: on
    else:
        print(
            "Local database does not exit, please start the dev instance first then retry"
        )


def seed_indicators():
    import requests

    indicator_list = [
        "ahash.com",
        "78.71.29.183",
        "193.151.24.186",
        "1c1760ed4d19cdbecb2398216922628b",
        "7df848031f95ec2061e83e519e0fae57c0506cacafd2f0e3b1970640d1188304",
        "fb028dd937a8378bc76a35c805a76cb367b4ccccf64b942807522325bae81621",
        "7490cb2192170167731093ed47a4c256532c5f28dacb1c264d5ffb9be9e6f909",
        "loginnjbehgqwege.click",
    ]
    api_key = str(input(f"{color.YELLOW}Enter API Key: {color.ENDCOLOR}")).strip()
    for indicator in indicator_list:
        response = requests.post(
            f"{config['SERVER_ADDRESS']}/api/indicator",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={"indicator": indicator, "api_key": api_key},
        )
        if response.status_code != 200:
            print(color.RED + response.text + color.ENDCOLOR)
        else:
            print(
                f"{color.BLUE}Successfully seeded {response.json().get('indicator_type')} indicator: {color.ENDCOLOR}{response.json().get('indicator')}"
            )


def delete_sqlite():
    if os.path.exists("./db.sqlite"):
        os.remove("./db.sqlite")
        print(f"{color.BLUE}Successfully deleted local database{color.ENDCOLOR}")
    else:
        print(f"{color.RED}Local database does not exist{color.ENDCOLOR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Indicator Search",
    )
    parser.add_argument(
        "-r",
        "--run",
        action="store_true",
        help="You know what you're doing, start the server",
    )

    if parser.parse_args().run:
        color = terminalColors()
        config = load_config()
        run_local_global()

    else:
        color = terminalColors()
        if not os.path.exists("./venv"):
            reinstall_packages()
            reconfig()
            print(
                f"{color.YELLOW}Setup complete, please configure your env file located at ./config/.env{color.ENDCOLOR}"
            )
        else:
            config = load_config()
            menu()
