"""
ImgQC: Simple image based quality control for XNAT MR sessions
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

LOG = logging.getLogger(__name__)

import nibabel as nib

from ukat.data import fetch
from ukat.qa import snr

def convert_dicoms(dicomdir):
    niftidir = os.path.join(dicomdir, "nifti")
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
    
KNOWN_TESTS = {
    "iSNR" : calc_isnr,
}

def run_scan(options, scan, scandir, scanid):
    scan_results = {"id" : scanid, "type" : scan, "images" : {}}
    if os.path.isdir(os.path.join(scandir, "resources")):
        niftidir = os.path.join(scandir, "resources", "NIFTI")
        dicomdir = os.path.join(scandir, "resources", "DICOM")
    else:
        niftidir = os.path.join(scandir, "NIFTI")
        dicomdir = os.path.join(scandir, "DICOM")

    if not os.path.isdir(niftidir) or not os.listdir(niftidir):
        if not os.path.isdir(dicomdir) or not os.listdir(dicomdir):
            LOG.warning(f"No NIFTIs or DICOMs found, skipping scan")
            return
        else:
            LOG.info(f"No NIFTIs found, will use DICOMs instead")
            niftidir = convert_dicoms(dicomdir)

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
            LOG.warning(f"{fname} for scan {scan} was not a valid NIFTI file - ignoring")
            continue

        img_name = fname[:fname.index(".nii")]
        scan_results["images"][img_name] = {}
        for test_name, test_impl in KNOWN_TESTS.items():
            result = test_impl(nii)
            scan_results["images"][img_name][test_name] = result

            if options.set_imgprops:
                # Set image result as a property on the scan
                try:
                    full_test_name = f"{test_name} ({img_name})"
                    url = f"{options.host}/data/projects/cmore/subjects/XNAT_S00017/experiments/XNAT_E00116/scans/{scanid}"
                    params = {
                        "xsiType" : "xnat:mrScanData",
                        f"xnat:mrScanData/parameters/addParam[name={full_test_name}]/addField" : str(result),
                    }
                    r = requests.put(url, params=params, auth=(options.user, options.password), verify=False)
                    LOG.info(f"Set QC result: {full_test_name}={result}")
                    if r.status_code != 200:
                        LOG.warning(f"Failed to set test result {full_test_name} for scan {scan}: {r.text}")
                except Exception as exc:
                    LOG.exception(f"Failed to set test result {full_test_name} for scan {scan}: {str(exc)}")

    return scan_results

def run_session(options, sessiondir, scandata):
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
        # FIXME very hacky, relies on consistent XNAT naming convention for dir.
        scanid = [scanmd["ID"] for scanmd in scandata if scan.startswith(scanmd["ID"])]
        if len(scanid) != 1:
            LOG.warning(f"Could not reliably get scan ID for {scan}: metadata was {scandata} - skipping")
            continue
        session_results[scan] = run_scan(options, scan, scandir, scanid[0])
    return session_results

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        argparse.ArgumentParser.__init__(self, prog="imgqc", add_help=False, **kwargs)
        self.add_argument("--input", help="Input directory", required=True)
        self.add_argument("--project", help="XNAT project")
        self.add_argument("--subject", help="XNAT subject")
        self.add_argument("--session", help="XNAT session")
        self.add_argument("--set-imgprops", action="store_true", default=False, help="Set test result properties directly on images")

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
        xml += f"    <scan_type>{scan['type']}</scan_type>\n"
        multi_img = True if len(scan["images"]) > 1 else False
        for img_name, tests in scan["images"].items():
            for test_name, result in tests.items():
                xml += f"    <test>\n"
                test_name = test_name.replace("<", "[").replace(">", "]")[:200]
                if multi_img:
                    test_name += f" ({img_name})"
                xml += f"      <name>{test_name}</name>\n"
                xml += f"      <result>{result}</result>\n"
                # FIXME This will be added when we have a means of calculating and storing population results
                #xml += f"      <pop_mean>{pop_mean}</pop_mean>\n"
                #xml += f"      <pop_std>{pop_std}</pop_std>\n"
                #xml += f"      <status>{status}</status>\n"
                xml += f"    </test>\n"
        xml += "  </scan>\n"
    xml += XML_FOOTER
    LOG.info(f"Generated XML:\n{xml}")
    return xml

def upload_xml(options, xml):
    """
    Upload new assessor to XNAT

    FIXME delete if already exists?
    """
    with open("temp.xml", "w") as f:
        f.write(xml)
    print(f"Uploading XML to {options.host}")
    print(xml)

    with open("temp.xml", "r") as f:
        files = {'file': f}
        url = "%s/data/projects/%s/subjects/%s/experiments/%s/assessors/" % (options.host, options.project, options.subject, options.session)
        print(f"Post URL: {url}")
        r = requests.post(url, files=files, auth=(options.user, options.password), verify=False)
        if r.status_code != 200:
            sys.stderr.write(xml)
            raise RuntimeError(f"Failed to create assessor: {r.text}")

def main():
    """
    Main script entry poin
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

        # Hack to disable certificate validation for HTTPS connections. This is required
        # becuase the certificate used for UoN servers are not always signed by a CA that
        # is recognized by the fixed set of CA certificates built in to python requests.
        #os.environ["CURL_CA_BUNDLE"] = ""

        # We need to download scan metadata to identify the ID of the scan more reliably from the directory name
        # The scan ID is required in order to set scan properties correctly via REST - the scan label does not always work
        options.host, options.user, options.password = os.environ["XNAT_HOST"], os.environ.get("XNAT_USER", None), os.environ.get("XNAT_PASS", None)
        if not options.user:
            options.user = getpass.getuser()
        if not options.password:
            options.password = getpass.getpass()

        r = requests.get(f"{options.host}/data/projects/{options.project}/subjects/{options.subject}/experiments/{options.session}/scans?format=csv", verify=False, auth=(options.user, options.password))
        if r.status_code != 200:
            raise RuntimeError(f"Failed to download session scan data: {r.text}")
        scandata = list(csv.DictReader(io.StringIO(r.text)))

        found_session = False
        for path, dirs, files in os.walk(options.input):
            if "scans" in [d.lower() for d in dirs]:
                if not found_session:
                    found_session = True
                    session_results = run_session(options, path, scandata)
                else:
                    LOG.warning(f"Found another session: {path} - ignoring")

        if not found_session:
            LOG.warning(f"No sessions found")

        xml = create_xml(options, session_results)
        upload_xml(options, xml)

    except Exception as exc:
        LOG.error(exc)
        sys.exit(1)

if __name__ == "__main__":
    main()
