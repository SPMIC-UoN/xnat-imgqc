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
import logging
import requests
import sys
import traceback
import csv

import numpy as np

from imgqc import get_test_config, test_is_relevant, create_xml
from xnat_nott import get_project, get_all_sessions, get_assessors, get_version, setup_logging, get_credentials, xnat_upload, xnat_download, xnat_login
 
LOG = logging.getLogger(__name__)

def get_assessor(options, session):
    """
    Get the results from the ImgQC assessor for a session

    Assumes only one such assessor exists - which should be the case!

    :return: Tuple of assessor ID, List of scan dictionaries
    """
    assessors = get_assessors(options, session, "xnat_imgqc:ImgQCData")
    if not assessors:
        LOG.warn(f"Could not find ImgQCData for session {session}")
        return None, []
    if len(assessors) > 1:
        LOG.warn(f"Multiple ImgQCData for session {session} - using first")
    assessor = assessors[0]
    scans = assessor.get("xnat_imgqc:scan", [])
    if not scans:
        LOG.warn(f"No tests in ImgQCData for session {session}")
    return assessor["ID"], scans

def update_xml(options, assessor_id, xml):
    """
    Update assessor on XNAT
    """
    with open("temp.xml", "w") as f:
        f.write(xml)

    url = f"data/projects/{options.project}/subjects/{options.subject}/experiments/{options.session}/assessors/"
    xnat_upload(options, url, "temp.xml", assessor_id)

def get_matching_test_def(options, img_name, test_name):
    """
    Loop through test definitions in config file and find the relevant entry
    for a given test result. 

    FIXME vendors is not being used
    FIXME assumes a given entry will match at most one row - this same assumption is made
    when running tests
    """
    try:
        for matchers, exclusions, vendors, config_test_name, masks, mean, std, amber, red in options.tests:
            if config_test_name == test_name and test_is_relevant(img_name, matchers, exclusions, vendors):
                return matchers, exclusions, vendors, config_test_name, masks, mean, std, amber, red
    except:
        LOG.exception(f"Failed to find matching configuration entry for test: {test_name} on image {img_name} - ignoring")
        return None

def report_session(options, session):
    """
    Output subject-level reports for session
    """
    _assessor_id, scans = get_assessors(options, session, "xnat_imgqc:ImgQCData")

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
                _matchers, _exclusions, _vendors, _config_test_name, _masks, mean, std, amber, red = test_def
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
                    matchers, exclusions, vendors, test_name, masks, mean, std, amber, red = test_def
                    if test["xnat_imgqc:name"] == test_name and test_is_relevant(img_name, matchers, exclusions, vendors):
                        LOG.info(f"Adding {test_name} result {result} for {img_name} to matcher: {matchers}, exclusions {exclusions}")
                        test_results.append(float(result))
            except:
                LOG.exception(f"Failed to process test result: {test} - ignoring")

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        argparse.ArgumentParser.__init__(self, prog="imgqc", add_help=False, **kwargs)
        self.add_argument("--host", help="XNAT host", required=True)
        self.add_argument("--user", help="XNAT username")
        self.add_argument("--project", help="XNAT project", required=True)
        self.add_argument("--config", help="Config file name - if not given will download from XNAT")
        self.add_argument("--mode", help="Run mode - generate stat, RAG existing results or generate report", choices=["stats", "rag", "report"], default="stats")
        self.add_argument("--debug", help="Use debug logging")

def main():
    """
    Main script entry point
    """
    options = ArgumentParser().parse_args()
    setup_logging(options)
    try:
        get_version(options)
        LOG.info(f"IMGQC_POPSTATS QC v{options.version}")
        get_credentials(options)
        xnat_login(options)

        options.project = get_project(options, options.project)
        options.project_id = options.project["ID"]
        LOG.info(f"Found project: {options.project} with ID {options.project_id}")
        sessions = get_all_sessions(options, options.project)
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
                    matchers, exclusions, vendors, test_name, masks, mean, std, amber, red = test_def
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
