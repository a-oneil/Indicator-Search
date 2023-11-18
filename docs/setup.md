# Setup
[Indicator Search menu](menu.md) | [Go back to readme](../README.md)

This project operates on FastAPI with Python 3.10.

Necessary OS packages include:
- Python 3.10
- Docker and Docker-compose

Follow these steps:

1. Clone the repository and navigate to it.
2. Execute `python3 indicator_search.py`. This will duplicate the example environment file and prompt you to complete it.
3. Adjust the settings in the `./config/.env` file.
4. Re-run `python3 indicator_search.py` to set up the environment and access the indicator search menu.
5. Choose your preferred method for running indicator search from the menu.
6. Create an admin user and save the API to the .env file for the api menu options to work. This API key is also used for the IOC ageout automation that runs every hour.

## Env File
The env file located at `./config/.env` is used to configure the applications api keys and tweakable settings. 

On inital run of the app, it will clone the `.env.example` file also located in the config folder and then print a message asking you to configure it.

* `SERVER_ADDRESS`: Used for seeding API calls and slack notifications
* `HOSTNAME`: Required for docker https proxy
* `ADMIN_API_KEY`: A user's api key for the ageout ioc automation that is ran every hour
* `USER_INVITE_KEY`: Required for user signup
* `ENABLE_SLACK`: True/False
* `SLACK_BOT_TOKEN`: Slack bot token with message permissions
* `SLACK_CHANNEL`: Channel to post slack updates to
* `DOCKER_IMAGE_TAG`: indicator_search:latest
* `DOCKER_REGISTRY`: Dockerregistry.com/user/repo
* `IS_POSTGRES_USER`: 
* `IS_POSTGRES_PASSWORD`:
* `IS_POSTGRES_DB`:

## Tool API Keys
If you don't have an api key, leave the value as `"API_KEY": ""`

The tool will be omitted from the indicators results.

## Slack Notifications
![Slack Notifications](../app/routers/web/static/images/slack_notifications.png)