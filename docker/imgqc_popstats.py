"""
IMGQC_POPSTATS: Generate population statistics from imgqc data

This script can be run in two modes: 'stats' calculates population mean/std for 
tests run by the imgqc container in a project. They can then be added to the configuration
file so that individual scan results can be RAG rated.

'rag' goes through existing ImgQC assessors and updates the pass/warn/fail status
based on the mean/std defined on the project.

This whole script is pretty messy and in need of rationalizing
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

from imgqc import get_test_config, test_is_relevant, create_xml

LOG = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_sessions(options):
    """
    Get session details for all sessions in specified project
    """
    url = f"{options.host}/data/projects/{options.project_id}/subjects/"
    params = {"xsiType": "xnat:mrSessionData", "format" : "csv"}
    LOG.debug(f"Getting subjects {url} {params}")
    r = requests.get(url, verify=False, auth=(options.user, options.password), params=params)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to download subjects for project {options.project_id}: {r.text}")
    subjects = list(csv.DictReader(io.StringIO(r.text)))
    sessions = []

    for subject in subjects:
        url = f"{options.host}/data/projects/{options.project_id}/subjects/{subject['ID']}/experiments/"
        LOG.debug(f"Getting sessions {url} {params}")
        r = requests.get(url, verify=False, auth=(options.user, options.password), params=params)
        if r.status_code != 200:
            raise RuntimeError(f"Failed to download sessions for project {options.project_id}: {r.text}")
        for session in list(csv.DictReader(io.StringIO(r.text))):
            session["subject"] = subject['ID']
            session["subject_label"] = subject['label']
            sessions.append(session)

    return sessions

def login(options):
    if options.auth_method == "service":
        LOG.info(f"Using XNAT authorization service")
        url = f"{options.host}/data/services/auth"
        auth_params={"username" : options.user, "password" : options.password}
        LOG.info(f"Logging in: {url}")
        r = requests.put(url, verify=False, data=urllib.parse.urlencode(auth_params))
        r.raise_for_status()
        LOG.info("Logged in using auth service")
        options.cookies = {"JSESSIONID" : r.text}
        options.auth = None
    else:
        LOG.info(f"Using HTTP basic auth")
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

def get_assessor(options, session):
    """
    Get the results from the ImgQC assessor for a session

    Assumes only one such assessor exists - which should be the case!

    :return: List of scan dictionaries
    """
    url = "%s/data/experiments/%s/assessors/" % (options.host, session["ID"])
    LOG.info(f"Getting imgqc assessors from URL: {url}")
    r = requests.get(url, auth=options.auth, cookies=options.cookies, params={"format" : "csv", "xsiType" : "xnat_imgqc:ImgQCData", "columns" : "ID"}, verify=False)
    r.raise_for_status()
    f = StringIO(r.text)
    assessor_id, scans = None, []
    for row in csv.DictReader(f, skipinitialspace=True):
        assessor_id = row['ID']
        url = "%s/data/experiments/%s/assessors/%s" % (options.host, session["ID"], assessor_id)
        LOG.info(f"Getting ImqQC results from URL: {url}")
        r = requests.get(url, auth=options.auth, cookies=options.cookies, params={"format" : "xml"}, verify=False)
        r.raise_for_status()
        d = xmltodict.parse(r.text)["xnat_imgqc:ImgQCData"]
        scans = d.get("xnat_imgqc:scan", [])
    return assessor_id, scans
 
def update_xml(options, assessor_id, xml):
    """
    Update assessor on XNAT
    """
    with open("temp.xml", "w") as f:
        f.write(xml)
    LOG.info(f"Uploading XML to {options.host}")

    LOG.info("Deleting existing assessor")
    delete_url = "%s/data/projects/%s/subjects/%s/experiments/%s/assessors/%s" % (options.host, options.project, options.subject, options.session, assessor_id)
    LOG.info(f"Delete URL: {delete_url}")
    r = requests.delete(delete_url, auth=options.auth, cookies=options.cookies, verify=False)
    if r.status_code != 200:
        LOG.warning("Failed to delete existing assessor")
        LOG.warning(f"{r.status_code}: {r.text}")
    else:
        LOG.info("Delete successful - posting update")

    with open("temp.xml", "r") as f:
        files = {'file': f}
        while True:
            url = "%s/data/projects/%s/subjects/%s/experiments/%s/assessors/" % (options.host, options.project, options.subject, options.session)
            LOG.info(f"Post URL: {url}")
            r = requests.post(url, files=files, auth=options.auth, cookies=options.cookies, verify=False, allow_redirects=False)
            if r.status_code in (301, 302):
                LOG.info("Redirect: {r.headers['Location']}")
                f.seek(0)
                url = r.headers["Location"]
                continue

            if r.status_code != 200:
                sys.stderr.write(xml)
                raise RuntimeError(f"Failed to create assessor: {r.status_code} {r.text}")
            break

def get_matching_test_def(options, img_name, test_name):
    """
    Loop through test definitions in config file and find the relevant entry
    for a given test result. 

    FIXME vendors is not being used
    FIXME assumes a given entry will match at most one row - this same assumption is made
    when running tests
    """
    try:
        for matchers, exclusions, vendors, config_test_name, mean, std, amber, red in options.tests:
            if config_test_name == test_name and test_is_relevant(img_name, matchers, exclusions, vendors):
                return matchers, exclusions, vendors, config_test_name, mean, std, amber, red
    except:
        LOG.exception(f"Failed to find matching configuration entry for test: {test_name} on image {img_name} - ignoring")
        return None

def report_session(options, session):
    """
    Output subject-level reports for session
    """
    assessor_id, scans = get_assessor(options, session)
    if not scans:
        return []

    results = []
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        scanid = scan["xnat_imgqc:scan_id"]
        tests = scan.get("xnat_imgqc:test", [])
        if isinstance(tests, dict):
            tests = [tests]
        for test in tests:
            test_name = test["xnat_imgqc:name"]
            img_name = test["xnat_imgqc:img"]
            test_def =  get_matching_test_def(options, img_name, test_name)
            if test_def:
                row = {
                    "subject" : session["subject_label"],
                    "session" : session["label"],
                    "scanid" : scanid,
                    "matcher" : ":".join(test_def[0]),
                    "test_name" : test_name,
                    "img_name" : img_name,
                    "result" : float(test["xnat_imgqc:result"]),
                }
                results.append(row)

    return results

def rag_session(options, session):
    """
    Collect results from the ImgQC assessor for a session, add RAG categorization
    and re-upload XML assessor
    """
    assessor_id, scans = get_assessor(options, session)
    if not scans:
        return

    session_results = {}
    for scan in scans:
        print(scan)
        if not isinstance(scan, dict):
            continue
        scanid = scan["xnat_imgqc:scan_id"]
        images = {}
        tests = scan.get("xnat_imgqc:test", [])
        if isinstance(tests, dict):
            tests = [tests]
        for test in tests:
            test_name = test["xnat_imgqc:name"]
            img_name = test["xnat_imgqc:img"]
            result = float(test["xnat_imgqc:result"])
            status = None
            test_def =  get_matching_test_def(options, img_name, test_name)
            if test_def:
                _matchers, _exclusions, _vendors, _config_test_name, mean, std, amber, red = test_def
                LOG.info(f"Adding RAG status for {test_name} result {result} for {img_name}")
                sigma = abs(result - mean) / std
                if sigma > red:
                    status = "FAIL"
                elif sigma > amber:
                    status = "WARN"
                else:
                    status = "PASS"
                break

            if img_name not in images:
                images[img_name] = {}

            if status is not None:
                images[img_name][test_name] = {
                    "result" : result,
                    "status" : status,
                    "mean" : mean,
                    "std" : std,
                }
            
        session_results[scanid] = {
            "id" : scanid,
            "type" : scan.get("xnat_imgqc:scan_type", scanid),
            "images" : images
        }

    # FIXME hack
    options.session = session["ID"]
    options.subject = session["subject"]
    new_xml = create_xml(options, session_results)
    print(new_xml)
    update_xml(options, assessor_id, new_xml)

def add_results_from_session(options, session):
    """
    Collect results from the ImgQC assessor on a session and add them to matching results list

    This assumes that each result from the assessor matches exactly one row in the config.
    The same assumption is made when the QC is run.
    """
    _assessor_id, scans = get_assessor(options, session)

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
        self.add_argument("--auth-method", help="Authorization method: basic or service", choices=["basic", "service"], default="basic")
        self.add_argument("--mode", help="Run mode - generate stat, RAG existing results or generate report", choices=["stats", "rag", "report"], default="stats")

def main():
    """
    Main script entry point
    """
    options = ArgumentParser().parse_args()
    
    try:
        with open("version.txt") as f:
            options.version = f.read().strip()
    except IOError:
        options.version = "(unknown)"

    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    LOG.info(f"IMGQC_POPSTATS v{options.version}")

    try:
        if not options.user:
            options.user = input("XNAT username: ")
        options.password = getpass.getpass()
        options.host = options.host.rstrip("/") # Double slashes confuses XNAT
        LOG.info(f"Using XNAT: {options.host} with user: {options.user}")

        login(options)
        options.project_id = get_project(options)
        LOG.info(f"Found project: {options.project} with ID {options.project_id}")
        sessions = get_sessions(options)
        LOG.info(f"Found {len(sessions)} sessions")

        options.tests = get_test_config(options)
        options.test_results = [[] for t in options.tests]
        options.report_rows = []

        for idx, session in enumerate(sessions):
            LOG.info(f"Processing session {idx}: {session['label']}")
            if options.mode == "stats":
                add_results_from_session(options, session)
            elif options.mode == "rag":
                rag_session(options, session)
            else:
                options.report_rows += report_session(options, session)

        if options.mode == "stats":
            writer = None
            with open(f"imgqc_popstats_{options.project}.csv", "w") as f:
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

        if options.mode == "report":
            writer = None
            with open(f"imgqc_stats_report_{options.project}.csv", "w") as f:
                for row in options.report_rows:
                    if writer is None:
                        writer = csv.DictWriter(f, row.keys())
                        writer.writeheader()
                    writer.writerow(row)

    except Exception as exc:
        LOG.error(exc)
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
