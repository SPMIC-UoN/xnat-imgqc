"""
ImgQC: Simple image based quality control for XNAT MR sessions

Currently only a single test - image SNR - is defined. However the
system is designed to feature multiple tests. A configuration file
defines which tests apply to which scans/vendors and what the 'normal'
range for the results should be.
"""
import argparse
import os
import sys
import requests
import io
import csv
import logging
import datetime
import traceback

import nibabel as nib
import numpy as np
import pandas as pd

from ukat.qa import snr

from xnat_nott import convert_dicoms, get_version, setup_logging, get_credentials, xnat_upload, xnat_download, xnat_login

LOG = logging.getLogger(__name__)

def calc_isnr(nii):
    isnr = snr.Isnr(nii.get_fdata(), nii.header.get_best_affine()).isnr
    return isnr
    
KNOWN_TESTS = {
    "isnr" : calc_isnr,
}
 
def convert_dicoms(dicomdir, scanid):
    niftidir = os.path.join("/tmp", str(scanid), "nifti")
    os.makedirs(niftidir, exist_ok=True, mode=0o777)
    cmd = "dcm2niix -o %s %s %s" % (niftidir, "-m n -f %d_%q -z y", dicomdir)
    LOG.info(cmd)
    retval = os.system(cmd)
    if retval != 0:
        LOG.warning("DICOM->NIFTI conversion failed - skipping scan")
        return None
    return niftidir

def test_is_relevant(img_name, test_config):
    """
    :return: True if test is relevant to this image
    
    FIXME vendor check requires json metadata
    """
    matched = False
    for m in test_config["matchers"]:
        LOG.debug(f" - Checking matcher: {m.lower()}, {img_name.lower()}")
        if m.lower() in img_name.lower():
            LOG.debug(" - Match")
            matched = True
            break

    if matched:
        for e in test_config["exclusions"]:
            LOG.debug(f" - Checking exclusion: {e.lower()}, {img_name.lower()}")
            if e.lower() in img_name.lower():
                LOG.debug(" - Excluded")
                matched = False
                break

    return matched

def run_scan(options, scan, scandir, scanid):
    """
    Run tests on a scan
    """
    LOG.info(f"Running scan ID {scanid}")
    scan_results = {"id" : scanid, "type" : scan, "images" : {}}
    if os.path.isdir(os.path.join(scandir, "resources")):
        niftidir = os.path.join(scandir, "resources", "NIFTI")
        dicomdir = os.path.join(scandir, "resources", "DICOM")
    else:
        niftidir = os.path.join(scandir, "NIFTI")
        dicomdir = os.path.join(scandir, "DICOM")

    LOG.info(f" - This version of IMGQC uses DICOMs in preference to NIFTI")
    niftidir = convert_dicoms(dicomdir, os.path.join("/tmp", str(scanid), "nifti"))
    if not niftidir:
        LOG.warning(f" - DICOM conversion failed - skipping scan")
        return scan_results

    for fname in os.listdir(niftidir):
        if not (fname.endswith(".nii") or fname.endswith(".nii.gz")):
            continue

        fpath = os.path.join(niftidir, fname)
        if not os.path.isfile(fpath):
            LOG.warning(f" - {fpath} for scan {scan} is not a file - ignoring")
            continue

        try:
            nii = nib.load(fpath)
        except:
            traceback.print_exc()
            LOG.warning(f" - {fname} for scan {scan} was not a valid NIFTI file - ignoring")
            continue

        LOG.info(f" - Found Nifti file: {fname} for scan {scan}")
        img_name = fname[:fname.index(".nii")]
        scan_results["images"][img_name] = {}
        LOG.info(f" - Looking for tests for scan {img_name}")
        for test_config in options.tests:
            test_name = test_config["name"]
            test_impl = KNOWN_TESTS.get(test_name, None)
            if test_impl is None:
                LOG.warning(f" - Unknown test: {test_name} - skipping")
                continue
            
            if test_config.get('masks', None):
                LOG.warning(f" - Masks defined - not currently supported and will be ignored")

            if test_is_relevant(img_name, test_config):
                LOG.info(f" - Applying test {test_name} to scan {img_name}")
                result = test_impl(nii)
                scan_results["images"][img_name][test_name] = {"result" : result}

                mean, std = test_config.get("mean", None), test_config.get("std", None)
                amber, red = test_config.get("amber", None), test_config.get("red", None)
                if mean and std and amber and red:
                    LOG.info(f" - Population stats for {test_name} / {img_name}: {mean} {std}")
                    sigma = np.abs(result - mean) / std
                    status = "PASS" if sigma < amber else "WARN" if sigma < red else "FAIL"
                    scan_results["images"][img_name][test_name]["mean"] = mean
                    scan_results["images"][img_name][test_name]["std"] = std
                    scan_results["images"][img_name][test_name]["status"] = status
                else:
                    LOG.info(f" - No population stats / flagging criteria found for {test_name} / {img_name}")

    LOG.info(f"DONE running scan ID {scanid}")
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
            continues
        session_results[scan] = run_scan(options, scan, scandir, scanid)
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
    url = f"data/projects/{options.project}/subjects/{options.subject}/experiments/{options.session}/assessors/"
    xnat_upload(options, url, "temp.xml", f"IMGQC_{options.session}")

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

    'masks' is an optional comma-separated list of masks to apply to the image before testing. Masks are identified
    from Nifti files in the session

    'mean' and 'std' describe the comparison distribution for this test

    'amber' and 'red' are the number of standard deviations from the mean for a result to be categorized
    as amber or red
    """
    fname = options.config
    if not fname:
        LOG.info("Downloading config from XNAT")
        fname = "downloaded_config.xlsx"
        xnat_download(options, f"/data/projects/{options.project}/resources/imgqc/files/imgqc_conf.xlsx", local_fname=fname)

    sheet = pd.read_excel(fname, dtype=str)
    test_config = sheet.fillna('')
    tests = []
    for _index, row in test_config.iterrows():
        LOG.info(row)
        if len(row) < 8:
            LOG.warning(f"Invalid row - at least 8 columns required. Skipping")
            continue

        if len(row) == 8:
            matchers, exclusions, vendors, test_name, mean, std, amber, red = row[:9]
            masks = ""
        else:
            matchers, exclusions, vendors, test_name, masks, mean, std, amber, red = row[:9]
        test_config = {}
        test_config["matchers"] = [m.strip().upper() for m in matchers.split(",")]
        test_config["exclusions"] = [e.strip().upper() for e in exclusions.split(",") if e.strip() != ""]
        test_config["vendors"] = [v.strip().upper() for v in vendors.split(",") if v.strip() != ""]
        test_config["masks"] = [m.strip().upper() for m in masks.split(",") if m.strip() != ""]
        test_config["name"] = test_name.strip().lower()
        if not test_config["name"]:
            LOG.warning(f"Test name missing in {row} - skipping")
            continue

        try:
            if mean: test_config["mean"] = float(mean)
            if std: test_config["std"] = float(std)
            if amber: test_config["amber"] = float(amber)
            if red: test_config["red"] = float(red)
        except ValueError:
            LOG.warning(f"Invalid numeric data in row {row} - skipping")
            continue

        tests.append(test_config)

    return tests

def get_scan_metadata(options):
    """
    Get information on scan IDs and names

    We need to download scan metadata to identify the ID of the scan more reliably from the directory name
    The scan ID is required in order to set scan properties correctly via REST - the scan label does not always work
    """
    url = f"{options.host}/data/projects/{options.project}/subjects/{options.subject}/experiments/{options.session}/scans?format=csv"
    LOG.info(f"Getting session scan metadata from {url}")
    r = requests.get(url, verify=False, auth=options.auth, cookies=options.cookies)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to download session scan data: {r.text}")
    return list(csv.DictReader(io.StringIO(r.text)))

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        argparse.ArgumentParser.__init__(self, prog="imgqc", add_help=False, **kwargs)
        self.add_argument("--input", help="Input directory", required=True)
        self.add_argument("--host", help="XNAT host")
        self.add_argument("--user", help="XNAT user")
        self.add_argument("--project", help="XNAT project", required=True)
        self.add_argument("--subject", help="XNAT subject", required=True)
        self.add_argument("--session", help="XNAT session", required=True)
        self.add_argument("--config", help="Config file name")
        self.add_argument("--debug", help="Use debug logging")

def main():
    """
    Main script entry point
    """
    options = ArgumentParser().parse_args()
    setup_logging(options)
    try:
        get_version(options)
        LOG.info(f"Image QC v{options.version}")
        get_credentials(options)
        xnat_login(options)

        if not os.path.isdir(options.input):
            raise RuntimeError(f"Input directory {options.input} does not exist")

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
        #upload_xml(options, xml)

    except Exception as exc:
        LOG.exception("Unexpected error")
        sys.exit(1)

if __name__ == "__main__":
    main()
