import os
import json
import logging
import argparse

from dependabot.vulnerability import Vulnerability
from dependabot.kenna import Kenna
from dependabot.event import processEventFile


if os.environ.get("GITHUB_SERVER_URL"):
    default_application = "{}/{}".format(
        os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY")
    )
else:
    default_application = ""


parser = argparse.ArgumentParser("dependabot-action")
parser.add_argument(
    "--debug", action="store_true", default=bool(os.environ.get("DEBUG"))
)
parser.add_argument(
    "-k", "--kenna-token", default=os.environ.get("KENNA_TOKEN"), help="Kenna Token"
)
parser.add_argument("-e", "--endpoint", default=os.environ.get("KENNA_ENDPOINT"))
parser.add_argument(
    "-a", "--application", default=default_application, help="Kenna Application ID/Name"
)
parser.add_argument(
    "-c",
    "--connector",
    type=int,
    default=os.environ.get("KENNA_CONNECTOR_ID"),
    help="Kenna Connection ID",
)
parser.add_argument(
    "-i",
    "--input",
    default=os.path.join(os.getcwd(), "event.json"),
    help="Result file(s)",
)
parser.add_argument(
    "--vulnerability-format",
    default="[{name}] {path}",
    help="Vulnerability Unique Identifier String",
)


arguments = parser.parse_args()

# Logging
logging.basicConfig(
    level=logging.DEBUG if arguments.debug else logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)

# Kenna Client
kenna_client = Kenna(
    endpoint=arguments.endpoint,
    token=arguments.kenna_token,
    connector=arguments.connector,
    application=arguments.application,
)

# TODO: Check if we can authenticate to instance
if not arguments.debug and not kenna_client.checkLogin():
    logging.error("Failed to authentication")
    raise Exception("Failed to authentication, please check access token and endpoint")
else:
    logging.info("Kenna authenticated")

dependabot_issue = processEventFile(arguments.input)
dependabot_issue.name = arguments.application

vulnerabilities = []
vulnerabilities.append(dependabot_issue)

logging.info("Application Name :: " + arguments.application)

logging.info("Vulnerabilities found :: " + str(len(vulnerabilities)))

# Generate data for Kenna
data = kenna_client.generateData(vulnerabilities, application_name="Dependabot")

# Write to file
with open("kenna-data.json", "w") as handle:
    json.dump(data, handle, indent=2)

# Upload file
kenna_client.uploadFile("kenna-data.json")

logging.info("Upload successful!")
