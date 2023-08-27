import subprocess
import os
import time
import argparse
import json
import platform
import shutil
from threading import Thread


class terminalColors:
    BLUE = "\033[36m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ENDCOLOR = "\033[0m"


def load_config():
    try:
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
    try:
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
    print(f"{color.BLUE}6.{color.ENDCOLOR} Seed feedlists database (API)")
    print(f"{color.BLUE}7.{color.ENDCOLOR} Seed indicators (API)")
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
            time.sleep(3600)
        else:
            print(
                f"{color.YELLOW}IOC Automation: {color.ENDCOLOR} Automation started, waiting 1 hour before first run"
            )
            first_run = False
            time.sleep(3600)


def reinstall_packages():
    print(
        f"{color.YELLOW}Installing required OS packages (see Readme), requesting password. {color.ENDCOLOR}"
    )
    system = platform.system()
    if system.lower() == "linux":
        distro = platform.uname().release.lower()
        if "debian" in distro or "ubuntu" in distro:
            subprocess.run(
                ["sudo", "apt", "install", "libpq-dev", "python3-dev", "python3-venv"],
                check=True,
            )

        elif "manjaro" in distro or "arch" in distro:
            subprocess.run(
                ["sudo", "pacman", "-S", "postgresql-libs", "python3"],
                check=True,
            )
        else:
            print(f"{color.RED}Unsupported Linux Distro{color.ENDCOLOR}")
            exit(1)

    elif system.lower() == "darwin":
        subprocess.run(
            ["brew", "install", "libpq", "virtualenv"],
            check=True,
        )

    else:
        print(f"{color.RED}Unsupported OS{color.ENDCOLOR}")
        exit(1)


def reconfig():
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
    import requests

    def seed(json_file_path, api_key, list_type):
        with open(json_file_path, "r") as json_file:
            json_input = json.load(json_file)
        json_file.close()

        for feedlist in json_input:
            response = requests.post(
                f"{config['SERVER_ADDRESS']}/api/feeds",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={
                    "api_key": api_key,
                    "name": feedlist.get("name"),
                    "url": feedlist.get("listURL"),
                    "description": feedlist.get("description"),
                    "category": feedlist.get("category"),
                    "list_type": list_type,
                    "list_period": feedlist.get("list_period"),
                },
            )

            if response.status_code != 200:
                print(color.RED + response.text + color.ENDCOLOR)
            else:
                if response.json().get("Error"):
                    for value in response.json().values():
                        print(f"{color.RED}{value}{color.ENDCOLOR}")
                else:
                    print(
                        f"{color.BLUE}Successfully seeded {response.json().get('list_type')} feedlist: {color.ENDCOLOR}{response.json().get('name')}"
                    )

    api_key = str(input(f"{color.YELLOW}Enter API Key: {color.ENDCOLOR}")).strip()
    seed("./config/feedlist_examples/iplists.json", api_key, list_type="ip")
    seed("./config/feedlist_examples/hashlists.json", api_key, list_type="hash")
    seed("./config/feedlist_examples/domainlists.json", api_key, list_type="fqdn")


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
