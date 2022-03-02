FROM ubuntu:18.04

RUN apt-get update -y && apt install -y git cmake gnupg libffi-dev libssl-dev libcurl4-openssl-dev python3-pip python3-dev 

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1
# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

# Creates a non-root user with an explicit UID and adds permission to access the /app folder
# For more info, please refer to https://aka.ms/vscode-docker-python-configure-containers
RUN adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

# Install pip requirements
WORKDIR /app
RUN git clone https://github.com/APImetrics/Agent .
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install -r requirements.txt

# This is what we could call from docker-compose:
# CMD ["python3", "-m", "apimetrics_agent"]
