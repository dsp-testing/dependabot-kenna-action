#!/usr/bin/env python3
import time
import pycurl
import urllib
import logging
import datetime
import requests


class Kenna:
    def __init__(self, endpoint, token, connector=None, application=None):
        """"""
        self.endpoint = endpoint
        self.token = token

        self.connector = connector
        self.application = application

        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-Risk-Token": self.token
                # 'Content-Type': 'application/json'
            }
        )

        if not self.endpoint:
            raise Exception("Kenna required options not set: endpoint")
        elif not self.token:
            raise Exception("Kenna required options not set: token")

        logging.info("Kenna Endpoint :: " + endpoint)
        logging.debug("Kenna Token :: " + token)

    def getEndpoint(self, path: str = ""):
        return self.endpoint + path

    def checkLogin(self) -> bool:
        # https://apidocs.kennasecurity.com/reference#list-applications
        try:
            url = self.getEndpoint("/applications")
            res = self.session.get(url)
        except Exception as err:
            return False
        
        if res.status_code != 200:
            return False

        return True


    def uploadFile(self, kenna_file: str) -> dict:
        url = self.getEndpoint(
            "/connectors/{}".format(self.connector)
        )
        logging.info("Connecting to Kenna Endpoint :: " + url)

        # with open(kenna_file, 'rb') as handle:
        c = pycurl.Curl()
        c.setopt(c.URL, url + "/data_file?run=true")
        c.setopt(c.POST, 1)
        c.setopt(c.HTTPPOST, [("file", (c.FORM_FILE, kenna_file))])
        c.setopt(pycurl.HTTPHEADER, ["content-type: application/json"])
        c.setopt(pycurl.HTTPHEADER, ["X-Risk-Token: " + self.token])
        c.setopt(c.VERBOSE, 0)
        c.perform()
        c.close()

        running = True
        response = {}

        while running:
            time.sleep(3)
            vuln_post = requests.get(url, headers={'content-type': 'application/json', 'X-Risk-Token': self.token})
            response = vuln_post.json()
            if response.get('success', None) == "false":
                raise Exception("Connected Failed :: " + response.get('message'))

            running = response['connector']['running']

        return response

    def generateData(self, vulnerabilities, application_name="GHAS"):
        now = datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d-%X")

        findings = []
        vuln_defs = []

        for vulnerability in vulnerabilities:
            findings.append(
                {
                    "scanner_type": "codescanning",
                    "scanner_identifier": vulnerability.identifier,
                    "scanner_score": int(vulnerability.criticality[1]),
                    "created_at": now,
                    # TODO: get value from GitHub API
                    "last_seen_at": vulnerability.creation,
                    "triage_status": "open"
                }
            )

            vuln_defs.append(
                {
                    "scanner_identifier": vulnerability.identifier,
                    "scanner_type": "codescanning",
                    "cve_identifiers": vulnerability.cve,
                    "name": vulnerability.name,
                    "description": vulnerability.description,
                }
            )

        data = {
            "skip_autoclose": False,
            "assets": [
                {
                    "url": "https://github.com/" + self.application,
                    "tags": ["AppID:" + application_name],
                    "vulns": [],
                    "findings": findings,
                }
            ],
            "vuln_defs": vuln_defs,
        }

        return data
