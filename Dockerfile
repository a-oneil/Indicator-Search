FROM ubuntu:22.04

# Make code directory where the code will live
WORKDIR /code

# Copy script to docker image
COPY ./ ./

ARG DEBIAN_FRONTEND=noninteractive

# Install all required dependencies
RUN apt-get update && apt-get install -y python3 python3-pip cron tzdata ntp python3-venv git libpq-dev

# Set timezone
ENV TZ=America/New_York

RUN ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && dpkg-reconfigure -f noninteractive tzdata && service ntp start && date && python3 -m venv ./venv && ./venv/bin/pip3 install --no-cache-dir -r ./config/requirements.txt

CMD /bin/bash -c "venv/bin/python3 ./indicator_search.py --run"
