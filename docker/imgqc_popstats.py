"""
IMGQC_POPSTATS: Generate population statistics from imgqc data

This script can be run on a project to calculate population mean/std for 
tests run by the imgqc container. They can then be added to the configuration
file so that individual scan results can be RAG rated.

Note that this involves a re-run of IMGQC on all sessions each time the stats
are updated. This is obviously not ideal, if it proves a problem the container
could be revised so it can be run in 'update RAG only' mode.
"""
import argparse
import csv
import getpass
import io
import logging
import requests
import sys
import traceback
import urllib3, urllib
import csv
from io import StringIO

import numpy as np
import xmltodict

from imgqc import get_test_config, test_is_relevant

LOG = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_sessions(options):
    """
    Get session details for all sessions in specified project
    """
    url = f"{options.host}/data/projects/{options.project_id}/experiments/"
    params = {"xsiType": "xnat:mrSessionData", "format" : "csv"}
    LOG.debug(f"Getting sessions {url} {params}")
    r = requests.get(url, verify=False, auth=(options.user, options.password), params=params)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to download sessions for project {options.project_id}: {r.text}")
    return list(csv.DictReader(io.StringIO(r.text)))

def login(options):
    url = f"{options.host}/data/services/auth"
    auth_params={"username" : options.user, "password" : options.password}
    LOG.info(f"Logging in: {url}")
    r = requests.put(url, verify=False, data=urllib.parse.urlencode(auth_params))
    if r.status_code == 200:
        LOG.info("Logged in using auth service")
        options.cookies = {"JSESSIONID" : r.text}
        options.auth = None
    else:
        LOG.info(f"Failed to log in using auth service - will use basic auth instead")
        options.cookies = {}
        options.auth = (options.user, options.password)

def get_project(options):
    """
    Get project ID from specified project name/ID
    """
    url = f"{options.host}/data/projects/"
    params={"format" : "csv"}
    LOG.debug(f"Getting projects {url} {params}")
    tries = 0
    while tries < 10:
        tries += 1
        r = requests.get(url, verify=False, cookies=options.cookies, auth=options.auth, params=params)
        if r.status_code == 200:
            break
    if r.status_code != 200:
        raise RuntimeError(f"Failed to download projects after 10 tries: {r.status_code} {r.text}")

    projects = list(csv.DictReader(io.StringIO(r.text)))
    for project in projects:
        if project["ID"] == options.project or project["name"] == options.project:
            return project["ID"]
    
    projects = [p["name"] for p in projects]
    raise RuntimeError("Project not found: {options.project} - known project: {projects}")

def add_results_from_session(options, session):
    """
    Get the results from the ImgQC assessor and add them to matching results list

    This assumes that each result from the assessor matches exactly one row in the config.
    The same assumption is made when the QC is run.
    """
    url = "%s/data/experiments/%s/assessors/" % (options.host, session["ID"])
    LOG.info(f"Getting imgqc assessors from URL: {url}")
    r = requests.get(url, auth=options.auth, cookies=options.cookies, params={"format" : "csv", "xsiType" : "xnat_imgqc:ImgQCData", "columns" : "ID"}, verify=False)
    r.raise_for_status()
    f = StringIO(r.text)
    scans = []
    for row in csv.DictReader(f, skipinitialspace=True):
        url = "%s/data/experiments/%s/assessors/%s" % (options.host, session["ID"], row['ID'])
        LOG.info(f"Getting ImqQC results from URL: {url}")
        r = requests.get(url, auth=options.auth, cookies=options.cookies, params={"format" : "xml"}, verify=False)
        r.raise_for_status()
        d = xmltodict.parse(r.text)["xnat_imgqc:ImgQCData"]
        scans = d.get("xnat_imgqc:scan", [])

    if isinstance(scans, dict):
        scans = [scans]
    for scan in scans:
        tests = scan.get("xnat_imgqc:test", [])
        if isinstance(tests, dict):
            tests = [tests]
        for test in tests:
            img_name = test["xnat_imgqc:img"]
            result = test["xnat_imgqc:result"]
            try:
                # For each test found, loop through test definition and find the relevant entries
                # FIXME vendors is not being used
                for test_def, test_results in zip(options.tests, options.test_results):
                    matchers, exclusions, vendors, test_name, mean, std, amber, red = test_def
                    if test["xnat_imgqc:name"] == test_name and test_is_relevant(img_name, matchers, exclusions, vendors):
                        LOG.info(f"Adding {test_name} result {result} for {img_name} to matcher: {matchers}, exclusions {exclusions}")
                        test_results.append(float(result))
            except:
                LOG.exception(f"Failed to process test result: {test} - ignoring")

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        argparse.ArgumentParser.__init__(self, prog="imgqc", add_help=False, **kwargs)
        self.add_argument("--host", help="XNAT host", required=True)
        self.add_argument("--project", help="XNAT project", required=True)
        self.add_argument("--user", help="XNAT username")
        self.add_argument("--config", help="Config file name - if not given will download from XNAT")

def main():
    """
    Main script entry point
    """
    options = ArgumentParser().parse_args()
    version = "0.0.1" # FIXME

    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    LOG.info(f"IMGQC_POPSTATS v{version}")

    try:
        if not options.user:
            options.user = input("XNAT username: ")
        options.password = getpass.getpass()
        LOG.info(f"Using XNAT: {options.host} with user: {options.user}")

        login(options)
        options.project_id = get_project(options)
        LOG.info(f"Found project: {options.project} with ID {options.project_id}")
        sessions = get_sessions(options)
        LOG.info(f"Found {len(sessions)} sessions")

        options.tests = get_test_config(options)
        options.test_results = [[] for t in options.tests]

        for idx, session in enumerate(sessions):
            LOG.info(f"Processing session {idx}: {session['label']}")
            add_results_from_session(options, session)
        
        writer = None
        with open("imgqc_popstats.csv", "w") as f:
            for test_def, test_results in zip(options.tests, options.test_results):
                matchers, exclusions, vendors, test_name, mean, std, amber, red = test_def
                outdata = {
                    "matchers" : ",".join(matchers),
                    "exclusions" : ",".join(exclusions),
                    "vendors" : ",".join(vendors),
                    "test_name" : test_name,
                    "mean" : np.mean(test_results),
                    "std" : np.std(test_results),
                    "amber" : amber,
                    "red" : red,
                }
                if writer is None:
                    writer = csv.DictWriter(f, outdata.keys())
                    writer.writeheader()
                writer.writerow(outdata)
    except Exception as exc:
        LOG.error(exc)
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
