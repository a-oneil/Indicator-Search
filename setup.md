# Setup
[Go back to readme](./README.md)

There are a couple of ways to get started with Indicator Search. Choose the best option that works out for you. 

- The [Docker-compose](./setup.md#docker-compose) option will setup a reverse HTTPs (self-signed) proxy for you.
- The [Docker image](./setup.md#docker-image) is a little more modular and requires you to put Indicator Search behind a reverse proxy yourself if you'd like encryption. You'll also need to setup a postgres database.
- The [Locally accessible only](./setup.md#locally-accessible-only) option is used for devlopement. You can use [VSCode](https://code.visualstudio.com/) to portforward from a remote host to your local machine.


## Docker-compose

To get started, you will need [Docker](https://docs.docker.com/get-docker/), [Docker-compose](https://docs.docker.com/compose/), and [Python 3.11](https://www.python.org/downloads/release/python-3117/) installed.

1. From the terminal, navigate to where you would like to save Indicator Search.
2. Run the command `git clone git@github.com:rc-austinoneil/Indicator-Search.git`. Once finished, `cd Indicator-Search`.
3. Execute `python3 indicator_search.py`. This will duplicate the example config file and prompt you to complete it. (`./config/.env`)
4. Re-run `python3 indicator_search.py` to set up the environment and access the Indicator Search menu.
5. Choose `option 2` from the menu. 
    - This will attempt to create a new self-signed ssl certificate, be sure to fill out all of the details.
    - New docker containers for Postgres, Traefik Reverse Proxy, and Indicator Search will be built.
6. Access Indicator Search from the url `https://<hostname>`


## Docker image
With GitHub actions, the Indicator Search image gets pushed to Dockerhub on each merge to the master branch. https://hub.docker.com/r/aoneil/indicator-search

To get started, you need [Docker](https://docs.docker.com/get-docker/) installed. You will also need a running postgres 16 database. The postgres database could be a container or a standalone install on a server or workstation.

```
docker run -d \
  --name indicator-search-postgres \
  -e POSTGRES_DB=${POSTGRES_DB} \
  -e POSTGRES_USER=${POSTGRES_USER} \
  -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
  -p 5432:5432 \
  -v path/to/db/storage:/var/lib/postgresql/data \
  --restart always \
  postgres:16
```

Once installed, copy the [config/.env.example](./config/.env.example) file to a safe location and modify the config file to enter your all of your tool API keys and postgres configuration.

Finally, you can spin up an Indicator Search instance using the following command. Be sure to change the path to your .env file.

```
docker run -d \
    --name "indicator-search \ 
    -v ~/home/user/.env:/code/config.env \
    -p 80:8000 \
    --restart always \
    aoneil/indicator-search:latest
```

## Locally accessible only
To get started, you will need [Docker](https://docs.docker.com/get-docker/), [Docker-compose](https://docs.docker.com/compose/), and [Python 3.11](https://www.python.org/downloads/release/python-3117/) installed.

1. From the terminal, navigate to where you would like to save Indicator Search.
2. Run the command `git clone git@github.com:rc-austinoneil/Indicator-Search.git`. Once finished, `cd Indicator-Search`.
3. Execute `python3 indicator_search.py`. This will duplicate the example config file and prompt you to complete it. (`./config/.env`)
4. Re-run `python3 indicator_search.py` to set up the environment and access the Indicator Search menu.
5. Choose `option 3` from the menu. 
    - A new docker container for Postgres will be built and the web application will execute locally without docker.
6. Access Indicator Search from the url `http://127.0.0.1:8000`


## Env File
The env file located at `./config/.env` is used to configure the application's API keys and customizable settings. To help get you started, here is a short description of the application settings that you can configure.

* `SERVER_ADDRESS`: Required, Used for seeding API calls, slack notifications, and result links.
* `HOSTNAME`: Required, Docker https proxy, this must be the same as the hostname on the SSL cert. 
* `USER_INVITE_KEY`: Required, string to hand out to for user registration. This limits the installation of Indicator Search to your team members/people you know.
* `POSTGRES_HOST`: Required, If running on the same host, this is handled for you. If you want to build an image and push to a container, make sure to set the correct postgres IP and port.
* `POSTGRES_PORT`: Required, Default is 5432. 
* `POSTGRES_USER`: Required, User for postgres.
* `POSTGRES_PASSWORD`: Required, Password for the postgres user.
* `POSTGRES_DB`: Required, Database name for Indicator Search data.
* `DOCKER_IMAGE_TAG`: indicator_search:latest
* `ENABLE_SLACK`: true/false
* `DOCKER_REGISTRY`: Dockerregistry.com/user/repo
* `SLACK_BOT_TOKEN`: Slack bot token with message permissions.
* `SLACK_CHANNEL`: Channel to post slack updates to.
* `OPENAI_ENABLED`: Experimental feature to add GPT-4 summaries of results as an enrichment. Adds additional processing time to every indicator searched.
* `OPENAI_MODEL`: Choose the model you would like to create summaries with. [See OpenAI's documentation for available models.](https://platform.openai.com/docs/models)

## Tool API Keys
If you don't have an api key, leave the value as `"API_KEY": ""`
The tool will be omitted from the indicators results.

To see the list of tools that Indicator Search can run, visit the [README.md](./README.md#tools). Use the link column to navigate to the tool and signup for an API key.

## Slack Notifications
If you would like Indicator Search to notify a Slack channel on every successful or failure search, be sure to fill out the `SLACK_BOT_TOKEN` and `SLACK_CHANNEL` key in the config file.

![Slack Notifications](./app/routers/web/static/images/slack_notifications.png)