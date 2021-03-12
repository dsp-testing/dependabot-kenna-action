import json

from dependabot.vulnerability import Vulnerability


def processEventFile(file: str) -> Vulnerability:
    with open(file, "r") as handle:
        data = json.load(handle)

    issue = Vulnerability(
        name=data.get("repository", {}).get("full_name"),
        package_name=data.get("alert", {}).get("affected_package_name"),
        package_range=data.get("alert", {}).get("affected_range"),
        creation=data.get("alert", {}).get("created_at"),
        id=data.get("alert", {}).get("id"),
        ghsa_id=data.get("alert", {}).get("ghsa_id"),
        cve=data.get("alert", {}).get("external_identifier"),
        rating="Medium"
    )

    return issue
