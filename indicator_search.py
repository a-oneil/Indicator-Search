import subprocess
import os
import time
import argparse
import json
import shutil
from threading import Thread


class terminalColors:
    BLUE = "\033[36m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ENDCOLOR = "\033[0m"


def load_config():
    try:
        if not os.path.exists("./config/.env"):
            shutil.copyfile("./config/.env.example", "./config/.env")
            print(
                f"{color.YELLOW}Creating a new .env file located at ./config/.env. Please configure it before proceeding.{color.ENDCOLOR}"
            )
            exit(1)
        else:
            print(f"{color.BLUE}Existing .env file found{color.ENDCOLOR}")

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
    try:
        # fmt: off
        print(f"{color.YELLOW}Ctrl + c to exit{color.ENDCOLOR}")
        print(f"{color.BLUE}To configure API tokens, modify the ./config/.env file\nThen, restart the app or rebuild the container{color.ENDCOLOR}")
        print("")
        print(f"{color.RED}{'='*16} Indicator Search {'='*16}{color.ENDCOLOR}")
        print(f"{color.BLUE}1.{color.ENDCOLOR}  Setup enviroment")
        print(f"{color.BLUE}2.{color.ENDCOLOR}  Build docker-compose and run locally with SSL proxy")
        print(f"{color.YELLOW} 2a.{color.ENDCOLOR}  Docker compose up")
        print(f"{color.YELLOW} 2b.{color.ENDCOLOR}  Docker compose down")
        print(f"{color.YELLOW}{'='*22} Dev {'='*23}{color.ENDCOLOR}")
        print(f"{color.BLUE}3.{color.ENDCOLOR}  Run local instance reachable at 127.0.0.1:8000 - Change reload enabled")
        print(f"{color.BLUE}4.{color.ENDCOLOR}  Run local instance reachable at 0.0.0.0:80 - Change reload disabled")
        print(f"{color.BLUE}5.{color.ENDCOLOR}  Build a docker image and push to a container registry")
        print(f"{color.BLUE}6.{color.ENDCOLOR}  Delete local sqlite database, will require restart of the app to rebuild")
        print(f"{color.YELLOW}{'='*22} API {'='*23}{color.ENDCOLOR}")
        print(f"{color.BLUE}7.{color.ENDCOLOR}  Seed feedlists database")
        print(f"{color.BLUE}8.{color.ENDCOLOR}  Seed indicators")
        print(f"{color.BLUE}9.{color.ENDCOLOR}  Create user")
        print(f"{color.YELLOW}  9a.{color.ENDCOLOR} Create admin user")
        # fmt: on
        menu_switch(input(f"{color.YELLOW}~> {color.ENDCOLOR}"))
    except KeyboardInterrupt:
        print(f"{color.RED}Exiting...{color.ENDCOLOR}")
        current_system_pid = os.getpid()
        ThisSystem = psutil.Process(current_system_pid)
        ThisSystem.terminate()


def menu_switch(choice):
    try:
        if choice == "1":
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
            run_dev()
        elif choice == "4":
            run_global()
        elif choice == "5":
            push_docker_to_registry()
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
    except KeyboardInterrupt:
        print(f"{color.RED}Exiting...{color.ENDCOLOR}")
        menu()


def ioc_ageout_automation():
    import requests
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    if not api_key:
        print(
            f"{color.RED}IOC Ageout automation failed to run due to no ADMIN_API_KEY being set in the env file.\nPlease either create a user from the menu or use an existing user's api key.{color.ENDCOLOR}"
        )
        return

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
                verify=False,
            )
            detail = response.json().get("detail")
            for value in (
                response.json().values() if detail != "No IOCs to age out" else False
            ):
                print(f"{color.YELLOW}IOC Automation: {color.ENDCOLOR}{value}")
        else:
            print(
                f"{color.YELLOW}IOC Automation: {color.ENDCOLOR} Automation started, waiting 1 hour before first run"
            )
            first_run = False
        time.sleep(3600)


def reconfig():
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


def run_dev():
    Thread(target=ioc_ageout_automation).start()
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


def run_global():
    Thread(target=ioc_ageout_automation).start()
    subprocess.run(
        [
            "./venv/bin/uvicorn",
            "app.main:app",
            "--host=0.0.0.0",
            "--port=80",
        ],
        check=True,
    )


def push_docker_to_registry():
    try:
        tag = (
            config["DOCKER_IMAGE_TAG"]
            if config["DOCKER_IMAGE_TAG"]
            else input("Enter a image:tag ~> ")
        )

        registry = (
            config["DOCKER_REGISTRY"]
            if config["DOCKER_REGISTRY"]
            else input("Enter a repository. Example: registry.docker.com/user/repo ~> ")
        )

        print("Building docker image")
        subprocess.run(
            [
                "docker",
                "build",
                "-t",
                f"{registry}/{tag}",
                "-f",
                "Dockerfile",
                ".",
            ],
            check=True,
        )
        print(f"{color.BLUE}Docker image built successfully!{color.ENDCOLOR}")
        print("Pushing to registry")
        subprocess.run(
            [
                "docker",
                "push",
                f"{registry}/{tag}",
            ],
            check=True,
        )
        print(
            f"{color.BLUE}Docker image pushed to registry successfully!{color.ENDCOLOR}"
        )
    except Exception as e:
        print(
            f"{color.RED}Error occurred while pushing to registry: {str(e)}{color.ENDCOLOR}"
        )


def seed_feedlists():
    def seed(json_file_path, list_type):
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
                    "url": feedlist.get("url"),
                    "description": feedlist.get("description"),
                    "category": feedlist.get("category"),
                    "list_type": list_type,
                    "list_period": feedlist.get("list_period"),
                },
                verify=False,
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

    seed("./config/feedlist_examples/iplists.json", list_type="ip")
    seed("./config/feedlist_examples/hashlists.json", list_type="hash")
    seed("./config/feedlist_examples/domainlists.json", list_type="fqdn")
    seed("./config/feedlist_examples/anylists.json", list_type="any")


def seed_indicators():
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
    for indicator in indicator_list:
        response = requests.post(
            f"{config['SERVER_ADDRESS']}/api/indicator",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={"indicator": indicator, "api_key": api_key},
            verify=False,
        )
        if response.status_code != 200:
            print(color.RED + response.text + color.ENDCOLOR)
        else:
            print(
                f"{color.BLUE}Successfully seeded {response.json().get('indicator_type')} indicator: {color.ENDCOLOR}{response.json().get('indicator')}"
            )


def create_user():
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
        verify=False,
    )
    if response.status_code != 200:
        print(color.RED + response.text + color.ENDCOLOR)
    else:
        print(
            f"{color.BLUE}Successfully created the user {response.json().get('username')}{color.ENDCOLOR}\nPassword: {password}\nAPI Key: {response.json().get('api_key')}"
        )


def create_admin_user():
    password = str(input(f"{color.YELLOW}Enter password: {color.ENDCOLOR}")).strip()

    response = requests.post(
        f"{config['SERVER_ADDRESS']}/api/user",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={
            "username": "Admin",
            "password": password,
            "invite_key": config["USER_INVITE_KEY"],
        },
        verify=False,
    )
    if response.status_code != 200:
        print(color.RED + response.text + color.ENDCOLOR)
    else:
        print(
            f"{color.BLUE}Successfully created admin user.{color.ENDCOLOR}\nUsername: Admin\nPassword: {password}\nAPI Key: {response.json().get('api_key')}"
        )


def delete_sqlite():
    confirm = input(
        f"{color.RED}Are you sure you want to delete the local database? (y/n) ~> {color.ENDCOLOR}"
    )
    if confirm.lower() != "y":
        menu()

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
        ["docker-compose", "build", "--no-cache", "--progress", "plain"],
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
        help="Run instance reachable at 0.0.0.0:80",
    )

    parser.add_argument(
        "-d",
        "--dev",
        action="store_true",
        help="Run dev instance reachable at 127.0.0.1:8000",
    )

    color = terminalColors()
    config = load_config()
    api_key = config["ADMIN_API_KEY"]

    if parser.parse_args().run:
        run_global()

    if parser.parse_args().dev:
        run_dev()

    if not os.path.exists("./venv"):
        reconfig()

    import requests
    import psutil
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    menu()
