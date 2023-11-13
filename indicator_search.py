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


def menu():
    print("")
    print(f"{color.RED}{'='*16} Indicator Search {'='*16}{color.ENDCOLOR}")
    print(f"{color.BLUE}1.{color.ENDCOLOR}  Setup enviroment")
    print(f"{color.BLUE}2.{color.ENDCOLOR}  Build docker-compose and run")
    print(f"{color.YELLOW} 2a.{color.ENDCOLOR}  Docker compose up")
    print(f"{color.YELLOW} 2b.{color.ENDCOLOR}  Docker compose down")
    print(f"{color.YELLOW}{'='*22} Dev {'='*23}{color.ENDCOLOR}")
    print(f"{color.BLUE}3.{color.ENDCOLOR}  Run local instance (127.0.0.1:8000)")
    print(f"{color.BLUE}4.{color.ENDCOLOR}  Run local instance (0.0.0.0:80)")
    print(f"{color.BLUE}5.{color.ENDCOLOR}  Build docker image")
    print(f"{color.BLUE}6.{color.ENDCOLOR}  Delete local sqlite database")
    print(f"{color.YELLOW}{'='*22} API {'='*23}{color.ENDCOLOR}")
    print(f"{color.BLUE}7.{color.ENDCOLOR}  Seed feedlists database")
    print(f"{color.BLUE}8.{color.ENDCOLOR}  Seed indicators")
    print(f"{color.BLUE}9.{color.ENDCOLOR}  Create user")
    print(f"{color.YELLOW}  9a.{color.ENDCOLOR} Create admin user")
    print(f"\n{color.YELLOW}Ctrl + c to exit{color.ENDCOLOR}")
    menu_switch(input(f"{color.YELLOW}~> {color.ENDCOLOR}"))


def menu_switch(choice):
    if choice == "1":
        reinstall_packages()
        reconfig()
        menu()
    elif choice == "2":
        create_self_signed_cert()
        docker_compose_build()
        docker_compose_up()
        menu()
    elif choice == "2a":
        docker_compose_up()
        menu()
    elif choice == "2b":
        docker_compose_down()
        menu()
    elif choice == "3":
        run_local()
    elif choice == "4":
        run_local_global()
    elif choice == "5":
        build_docker_image()
        menu()
    elif choice == "6":
        delete_sqlite()
        menu()
    elif choice == "7":
        seed_feedlists()
        menu()
    elif choice == "8":
        seed_indicators()
        menu()
    elif choice == "9":
        create_user()
        menu()
    elif choice == "9a":
        create_admin_user()
        menu()
    else:
        menu()


def ioc_ageout_automation():
    import requests

    api_key = config["ADMIN_API_KEY"]
    if not api_key:
        print(
            f"{color.RED}IOC Ageout automation failed to run due to no ADMIN_API_KEY being set in the env file.\nPlease either create a user from the menu or use an existing user's api key.{color.ENDCOLOR}"
        )
        return False

    first_run = True
    while True:
        if not first_run:
            response = requests.post(
                f"{config['SERVER_ADDRESS']}/api/iocs/ageout",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={"api_key": api_key},
            )
            detail = response.json().get("detail")

            if detail != "No IOCs to age out":
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
        distro = platform.uname()

        if any(match in distro for match in ["debian", "ubuntu", "kali"]):
            subprocess.run(
                ["sudo", "apt", "install", "python3-dev", "python3-venv"],
                check=True,
            )

        elif any(match in distro for match in ["arch", "manjaro"]):
            subprocess.run(
                ["sudo", "pacman", "-S", "python3"],
                check=True,
            )
        else:
            print(f"{color.RED}Unsupported Linux Distro{color.ENDCOLOR} - {distro}")
            exit(1)

    elif system.lower() == "darwin":
        subprocess.run(
            ["brew", "install", "virtualenv"],
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
            "--host=127.0.0.1",
            "--port=8000",
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
            "--host=0.0.0.0",
            "--port=80",
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
        "a3cb3b02a683275f7e0a0f8a9a5c9e07",
        "124.89.118.9",
        "193.151.24.186",
        "https://injective.claims",
        "projectdept@kanzalshamsprojectmgt.com",
        "e8ac867e5f51bdcf5ab7b06a8bced131",
        "fb028dd937a8378bc76a35c805a76cb367b4ccccf64b942807522325bae81621",
        "7490cb2192170167731093ed47a4c256532c5f28dacb1c264d5ffb9be9e6f909",
        "00sms.xyz",
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


def create_user():
    import requests

    user = str(input(f"{color.YELLOW}Enter username: {color.ENDCOLOR}")).strip()
    password = str(input(f"{color.YELLOW}Enter password: {color.ENDCOLOR}")).strip()

    response = requests.post(
        f"{config['SERVER_ADDRESS']}/api/user",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={
            "username": user,
            "password": password,
            "invite_key": config["USER_INVITE_KEY"],
        },
    )
    if response.status_code != 200:
        print(color.RED + response.text + color.ENDCOLOR)
    else:
        print(
            f"{color.BLUE}Successfully created user, log into the user on the webapp to view the API Key{color.ENDCOLOR}"
        )


def create_admin_user():
    import requests

    password = str(input(f"{color.YELLOW}Enter password: {color.ENDCOLOR}")).strip()

    response = requests.post(
        f"{config['SERVER_ADDRESS']}/api/user",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={
            "username": "Admin",
            "password": password,
            "invite_key": config["USER_INVITE_KEY"],
        },
    )
    if response.status_code != 200:
        print(color.RED + response.text + color.ENDCOLOR)
    else:
        print(
            f"{color.BLUE}Successfully created admin user.{color.ENDCOLOR}\nUsername: Admin\nPassword: {password}\nAPI Key: {response.json().get('api_key')}"
        )


def delete_sqlite():
    if os.path.exists("./db.sqlite"):
        os.remove("./db.sqlite")
        os.close(os.open("./db.sqlite", os.O_CREAT))
        print(f"{color.BLUE}Successfully deleted local database{color.ENDCOLOR}")
    else:
        print(f"{color.RED}Local database does not exist{color.ENDCOLOR}")


def create_self_signed_cert():
    if not os.path.exists("./config/traefik.key") or not os.path.exists(
        "./config/traefik.crt"
    ):
        print(f"{color.YELLOW}Creating self-signed certificate{color.ENDCOLOR}")
        subprocess.run(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "./config/traefik.key",
                "-x509",
                "-days",
                "365",
                "-out",
                "./config/traefik.crt",
            ],
            check=True,
        )
    else:
        print(f"{color.BLUE}Existing certificate found{color.ENDCOLOR}")


def docker_compose_build():
    if not os.path.exists("./db.sqlite"):
        os.close(os.open("./db.sqlite", os.O_CREAT))

    env = {
        **os.environ,
        "HOSTNAME": config["HOSTNAME"],
    }

    subprocess.run(
        [
            "docker-compose",
            "build",
        ],
        env=env,
        check=True,
    )


def docker_compose_up():
    env = {
        **os.environ,
        "HOSTNAME": config["HOSTNAME"],
    }
    subprocess.run(
        [
            "docker-compose",
            "up",
            "-d",
        ],
        env=env,
        check=True,
    )


def docker_compose_down():
    env = {
        **os.environ,
        "HOSTNAME": config["HOSTNAME"],
    }
    subprocess.run(
        [
            "docker-compose",
            "down",
        ],
        env=env,
        check=True,
    )


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
            try:
                config = load_config()
                menu()
            except KeyboardInterrupt:
                print(f"{color.RED}\nExiting...{color.ENDCOLOR}")
                menu()
