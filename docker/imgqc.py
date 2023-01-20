"""
ImgQC: Simple image based quality control for XNAT MR sessions

Currently only a single test - image SNR - is defined. However the
system is designed to feature multiple tests. A configuration file
defines which tests apply to which scans/vendors and what the 'normal'
range for the results should be.
"""
import argparse
import getpass
import os
import sys
import requests
import io
import csv
import logging
import datetime
import traceback
import urllib3

LOG = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import nibabel as nib
import numpy as np
import pandas as pd

from ukat.qa import snr

def convert_dicoms(dicomdir, scanid):
    niftidir = os.path.join("/tmp", str(scanid), "nifti")
    os.makedirs(niftidir, exist_ok=True, mode=0o777)
    cmd = "dcm2niix -o %s %s %s" % (niftidir, "-m n -f %n_%p_%q -z y", dicomdir)
    LOG.info(cmd)
    retval = os.system(cmd)
    if retval != 0:
        LOG.warning("DICOM->NIFTI conversion failed - skipping scan")
        return None
    return niftidir

def calc_isnr(nii):
    isnr = snr.Isnr(nii.get_fdata(), nii.header.get_best_affine()).isnr
    return isnr
     
def get_test_stats(options, test_name, img_name):
    test_stats = options.pop_stats.get(test_name.split()[0].lower(), None)
    if test_stats:
        for matcher, mean, std in test_stats:
            if matcher == "*" or matcher.lower() in img_name.lower():
                return mean, std

KNOWN_TESTS = {
    "isnr" : calc_isnr,
}

def test_is_relevant(img_name, matchers, exclusions, vendors):
    matched = False
    for m in matchers:
        LOG.debug(f"Checking matcher: {m.lower()}, {img_name.lower()}")
        if m.lower() in img_name.lower():
            LOG.debug("match")
            matched = True
            break

    if matched:
        for e in exclusions:
            LOG.debug(f"Checking exclusion: {e.lower()}, {img_name.lower()}")
            if e.lower() in img_name.lower():
                LOG.debug("excluded")
                matched = False
                break

    # FIXME vendor check requires json metadata
    return matched

def run_scan(options, scan, scandir, scanid):
    scan_results = {"id" : scanid, "type" : scan, "images" : {}}
    if os.path.isdir(os.path.join(scandir, "resources")):
        niftidir = os.path.join(scandir, "resources", "NIFTI")
        dicomdir = os.path.join(scandir, "resources", "DICOM")
    else:
        niftidir = os.path.join(scandir, "NIFTI")
        dicomdir = os.path.join(scandir, "DICOM")

    LOG.info(f"This version of IMGQC uses DICOMs in preference to NIFTI")
    niftidir = convert_dicoms(dicomdir, scanid)

    for fname in os.listdir(niftidir):
        if not (fname.endswith(".nii") or fname.endswith(".nii.gz")):
            continue

        fpath = os.path.join(niftidir, fname)
        if not os.path.isfile(fpath):
            LOG.warning(f"{fpath} for scan {scan} is not a file - ignoring")
            continue

        try:
            nii = nib.load(fpath)
        except:
            traceback.print_exc()
            LOG.warning(f"{fname} for scan {scan} was not a valid NIFTI file - ignoring")
            continue

        img_name = fname[:fname.index(".nii")]
        scan_results["images"][img_name] = {}
        LOG.info(f"Looking for tests for scan {img_name}")
        for matchers, exclusions, vendors, test_name, mean, std, amber, red in options.tests:
            test_impl = KNOWN_TESTS.get(test_name, None)
            if test_impl is None:
                LOG.warning(f"Unknown test: {test_name} - skipping")
                continue
            
            if test_is_relevant(img_name, matchers, exclusions, vendors):
                LOG.info(f"Applying test {test_name} to scan {img_name}")
                result = test_impl(nii)
                scan_results["images"][img_name][test_name] = {"result" : result}

                if mean and std and amber and red:
                    LOG.info(f"Population stats for {test_name} / {img_name}: {mean} {std}")
                    sigma = np.abs(result - mean) / std
                    status = "PASS" if sigma < amber else "WARN" if sigma < red else "FAIL"
                    scan_results["images"][img_name][test_name]["mean"] = mean
                    scan_results["images"][img_name][test_name]["std"] = std
                    scan_results["images"][img_name][test_name]["status"] = status
                else:
                    LOG.info(f"No population stats for {test_name} / {img_name}")

    return scan_results

def get_scan(scandname, options):
    """
    Try to identify a scan from the name of the DICOM directory

    FIXME this is messy because we aren't quite sure how XNAT names scan dirs
    """
    # First look for exact ID match
    for scanmd in options.scan_metadata:
        id = scanmd["ID"]
        if id  == scandname:
            return id

    # Now look for longest startswith match
    match_len, ret = -1, None
    for scanmd in options.scan_metadata:
        id = scanmd["ID"]
        if scandname.startswith(id) and len(id) > match_len:
            ret = id
            match_len = len(id)

    # May be None if we found nothing matching
    return ret

def run_session(options, sessiondir):
    """
    Run image QC on all scans in a session
    """
    LOG.info(f"Checking session from {sessiondir}")
    session_results = {}

    scansdir = [d for d in os.listdir(sessiondir) if d.lower() == "scans"]
    if len(scansdir) != 1:
        raise RuntimeError(f"Expected single scan dir, got {scansdir}")
    scansdir = os.path.join(sessiondir, scansdir[0])

    for scan in os.listdir(scansdir):
        scandir = os.path.join(scansdir, scan)
        LOG.info(f"Checking {scan}")
        scanid = get_scan(scan, options)
        if not scanid:
            LOG.warning(f"Could not get scan ID for {scan}: metadata was {options.scan_metadata} - skipping")
            continue
        session_results[scan] = run_scan(options, scan, scandir, scanid[0])
    return session_results

XML_HEADER = """<?xml version="1.0" encoding="UTF-8"?>
<ImgQCData xmlns="http://github.com/spmic-uon/xnat-imgqc" 
           xmlns:xnat="http://nrg.wustl.edu/xnat" 
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
"""

XML_FOOTER = """
</ImgQCData>
"""

def create_xml(options, session_results):
    """
    Create XML assessor document
    """
    timestamp = datetime.datetime.today().strftime('%Y-%m-%d') 
    xml = XML_HEADER
    xml += f"  <imgqcVersion>{options.version}</imgqcVersion>\n"
    xml += f"  <xnat:label>IMGQC_{options.session}</xnat:label>\n"
    xml += f"  <xnat:date>{timestamp}</xnat:date>\n"

    for scan in session_results.values():
        xml += "  <scan>\n"
        xml += f"    <scan_id>{scan['id']}</scan_id>\n"
        if scan['type'] != scan['id']:
            xml += f"    <scan_type>{scan['type']}</scan_type>\n"
        for img_name, tests in scan["images"].items():
            for test_name, test_data in tests.items():
                result = test_data["result"]
                xml += f"    <test>\n"
                test_name = test_name.replace("<", "[").replace(">", "]")[:200]
                xml += f"      <name>{test_name}</name>\n"
                xml += f"      <img>{img_name}</img>\n"
                xml += f"      <result>{result:.3f}</result>\n"
                if "status" in test_data:
                    mean, std, status = test_data["mean"], test_data["std"], test_data["status"]
                    xml += f"      <pop_mean>{mean:.3f}</pop_mean>\n"
                    xml += f"      <pop_std>{std:.3f}</pop_std>\n"
                    xml += f"      <status>{status}</status>\n"
                xml += f"    </test>\n"
        xml += "  </scan>\n"
    xml += XML_FOOTER
    LOG.info(f"Generated XML:\n{xml}")
    return xml

def upload_xml(options, xml):
    """
    Upload new assessor to XNAT
    """
    with open("temp.xml", "w") as f:
        f.write(xml)
    LOG.info(f"Uploading XML to {options.host}")

    with open("temp.xml", "r") as f:
        files = {'file': f}
        url = "%s/data/projects/%s/subjects/%s/experiments/%s/assessors/" % (options.host, options.project, options.subject, options.session)
        while True:
            LOG.info(f"Post URL: {url}")
            r = requests.post(url, files=files, auth=(options.user, options.password), verify=False, allow_redirects=False)
            if r.status_code in (301, 302):
                LOG.info("Redirect: {r.headers['Location']}")
                f.seek(0)
                url = r.headers["Location"]
                continue

            elif r.status_code == 409:
                LOG.info("ImgQC assessor already exists - will delete and replace")
                delete_url = url + f"IMGQC_{options.session}"
                LOG.info(f"Delete URL: {delete_url}")
                r = requests.delete(delete_url, auth=(options.user, options.password), verify=False)
                if r.status_code == 200:
                    LOG.info("Delete successful - re-posting")
                    f.seek(0)
                    continue

            if r.status_code != 200:
                sys.stderr.write(xml)
                raise RuntimeError(f"Failed to create assessor: {r.status_code} {r.text}")
            break

def get_test_config(options):
    """
    Read test configuration which is stored in an Excel spreadsheet with coloumns:
    
    matchers, exclusions, vendors, test, mean, std, amber, red

    'matchers' are comma-separated case-insensitive substrings, one of which must be present in the 
    filename of an input for the test to be used

    'exclusions' are comma separated case-insensitive substrings. If any are present in the filename
    of an input, the test will not be used

    'vendors' is a comma separated case insensitive list of vendors which the test will apply to.
    If blank, the test applies to any vendor

    'test' is a case-insensitive test name which must be known to imgqc

    'mean' and 'std' describe the comparison distribution for this test

    'amber' and 'red' are the number of standard deviations from the mean for a result to be categorized
    as amber or red
    """
    fname = options.config
    if not fname:
        LOG.info("Downloading config from XNAT")
        fname = "downloaded_config.xlsx"
        with requests.get(f"{options.host}/data/projects/{options.project}/resources/imgqc/files/imgqc_conf.xlsx",
                          auth=(options.user, options.password), verify=False, stream=True) as r:
            r.raise_for_status()
            with open(fname, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192): 
                    f.write(chunk)

    sheet = pd.read_excel(fname, dtype=str)
    test_config = sheet.fillna('')
    tests = []
    for index, row in test_config.iterrows():
        LOG.info(row)
        if len(row) < 8:
            LOG.warning(f"Invalid row - at least 8 columns required. Skipping")
            continue

        matchers, exclusions, vendors, test, mean, std, amber, red = row[:8]
        matchers = [m.strip().upper() for m in matchers.split(",")]
        exclusions = [e.strip().upper() for e in exclusions.split(",") if e.strip() != ""]
        vendors = [v.strip().upper() for v in vendors.split(",") if v.strip() != ""]
        test = test.strip().lower()
        if not test:
            LOG.warning(f"Test name missing - skipping")
            continue

        try:
            if mean: mean = float(mean)
            if std: std = float(std)
            if amber: amber = float(amber)
            if red: red = float(red)
        except ValueError:
            LOG.warning(f"Invalid numeric data in row {row} - skipping")
            continue

        tests.append((matchers, exclusions, vendors, test, mean, std, amber, red))

    return tests

def get_scan_metadata(options):
    """
    Get information on scan IDs and names

    We need to download scan metadata to identify the ID of the scan more reliably from the directory name
    The scan ID is required in order to set scan properties correctly via REST - the scan label does not always work
    """
    url = f"{options.host}/data/projects/{options.project}/subjects/{options.subject}/experiments/{options.session}/scans?format=csv"
    LOG.info(f"Getting session scan metadata from {url}")
    r = requests.get(url, verify=False, auth=(options.user, options.password))
    if r.status_code != 200:
        raise RuntimeError(f"Failed to download session scan data: {r.text}")
    return list(csv.DictReader(io.StringIO(r.text)))

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        argparse.ArgumentParser.__init__(self, prog="imgqc", add_help=False, **kwargs)
        self.add_argument("--input", help="Input directory", required=True)
        self.add_argument("--project", help="XNAT project")
        self.add_argument("--subject", help="XNAT subject")
        self.add_argument("--session", help="XNAT session")
        self.add_argument("--config", help="Config file name")

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
    LOG.info(f"Image QC v{options.version}")

    try:
        if not os.path.isdir(options.input):
            raise RuntimeError(f"Input directory {options.input} does not exist")

        options.host, options.user, options.password = os.environ["XNAT_HOST"], os.environ.get("XNAT_USER", None), os.environ.get("XNAT_PASS", None)
        if not options.user:
            options.user = getpass.getuser()
        if not options.password:
            options.password = getpass.getpass()
        LOG.info(f"XNAT server: {options.host} {options.user}")

        options.tests = get_test_config(options)
        options.scan_metadata = get_scan_metadata(options)

        found_session = False
        for path, dirs, files in os.walk(options.input):
            if "scans" in [d.lower() for d in dirs]:
                if not found_session:
                    found_session = True
                    session_results = run_session(options, path)
                else:
                    LOG.warning(f"Found another session: {path} - ignoring")

        if not found_session:
            LOG.warning(f"No sessions found")

        xml = create_xml(options, session_results)
        upload_xml(options, xml)

    except Exception as exc:
        LOG.error(exc)
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
