# APImetrics Agent deployment guide

## Required Resources

### Docker container:
Details can be found on docker hub: https://hub.docker.com/r/apimetrics/agent.

Alternatively on Google’s Docker Container Registry: `gcr.io/apimetrics/agent`.
Note you may need to run:
`gcloud auth configure-docker us-docker.pkg.dev`

### Agent source
The source code is available in our GitHub: https://github.com/APImetrics/Agent.
The docker container pulls the sources as part of the install, you do not need to clone this repository.

## Configuration needed

### Configuration file
The configuration files is provided by APImetrics – usually named `apimetrics_agent.ini`.
Set a local environment variable `APIM_CONFIG_FILE` to the path to this file on your system.

### Google Cloud credentials
The credentials file is provide by APImetrics – usually named `google_creds.json`.
Set a local environment variable `GOOGLE_APPLICATION_CREDENTIALS` to the path to this file on your system.

## How to run the agent

1. To use docker-compose, get file from GitHub - https://github.com/APImetrics/Agent/blob/main/docker-compose.yml (direct URL is https://github.com/APImetrics/Agent/raw/main/docker-compose.yml).
2. Ensure that the `APIM_CONFIG_FILE` and `GOOGLE_APPLICATION_CREDENTIALS` environment variables are set.
3. In folder with `docker-compose.yml` file:
`docker-compose up`

### Example output:
```
➜ docker-compose up                                                    
[+] Running 1/1
 ⠿ Container agent-apimagent-1  Recreated                                                                                                                                                                              0.1s
Attaching to agent-apimagent-1
agent-apimagent-1  | 2022-08-16 21:53:05,411:apimetrics_agent.config:131: INFO: APImetrics Agent: Demo Agent [qcmetrics_demoagent]
agent-apimagent-1  | 2022-08-16 21:53:05,411:apimetrics_agent.register:13: INFO: Registering Agent qcmetrics_demoagent - Demo Agent to owner 
agent-apimagent-1  | 2022-08-16 21:53:05,411:apimetrics_agent.register:25: INFO: Calling POST https://qc-client.apimetrics.io/remote-api/1/agent/register {'name': 'qcmetrics_demoagent', 'display_name': 'Demo Agent', 'owner': '', 'access_token': 'GXw2y6CdektT9aDGQAcdCja0U12Dufxd', 'version': '0.12.3'} proxy: None
agent-apimagent-1  | /home/appuser/.local/lib/python3.6/site-packages/urllib3/connectionpool.py:1004: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
agent-apimagent-1  |   InsecureRequestWarning,
agent-apimagent-1  | 2022-08-16 21:53:07,756:apimetrics_agent.register:45: INFO: Register returned 200 OK:
...
```
