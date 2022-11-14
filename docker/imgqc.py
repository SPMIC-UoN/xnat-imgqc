"""
ImgQC: Simple image based quality control for XNAT MR sessions
"""
import argparse
import os
import sys
import requests
import traceback
import io
import csv

import nibabel as nib

from ukat.data import fetch
from ukat.qa import snr

def convert_dicoms(dicomdir):
    niftidir = os.path.join(dicomdir, "nifti")
    os.makedirs(niftidir, exist_ok=True, mode=0o777)
    cmd = "dcm2niix -o %s %s %s" % (niftidir, "-m n -f %n_%p_%q -z y", dicomdir)
    print(cmd)
    retval = os.system(cmd)
    if retval != 0:
        print(" - WARNING: DICOM->NIFTI conversion failed - skipping")
        return None
    return niftidir

def calc_isnr(nii):
    isnr = snr.Isnr(nii.get_fdata(), nii.header.get_best_affine()).isnr
    return isnr
    
KNOWN_TESTS = {
    "iSNR" : calc_isnr,
}

def check_scan(options, scan, scandir, scanid):
    if os.path.isdir(os.path.join(scandir, "resources")):
        niftidir = os.path.join(scandir, "resources", "NIFTI")
        dicomdir = os.path.join(scandir, "resources", "DICOM")
    else:
        niftidir = os.path.join(scandir, "NIFTI")
        dicomdir = os.path.join(scandir, "DICOM")

    if not os.path.isdir(niftidir) or not os.listdir(niftidir):
        if not os.path.isdir(dicomdir) or not os.listdir(dicomdir):
            print(f"   - No NIFTIs or DICOMs found, skipping scan")
            return None
        else:
            print(f"   - No NIFTIs found, will use DICOMs instead")
            niftidir = convert_dicoms(dicomdir)

    for fname in os.listdir(niftidir):
        # FIXME what if more than one NIFTI?
        if not (fname.endswith(".nii") or fname.endswith(".nii.gz")):
            continue
        fpath = os.path.join(niftidir, fname)
        print(fpath)
        if not os.path.isfile(fpath):
            print(f"   - WARNING: {fpath} is not a file - ignoring")
            return None

        try:
            nii = nib.load(fpath)
        except:
            print(f"   - {fname} for scan {scan} was not a valid NIFTI file - ignoring")
            return None

        for test_name, test_impl in KNOWN_TESTS.items():
            result = test_impl(nii)
            try:
                host, user, password = os.environ["XNAT_HOST"], os.environ["XNAT_USER"], os.environ["XNAT_PASS"]
                os.environ["CURL_CA_BUNDLE"] = "" # Hack to disable CA verification
                url = f"{host}/data/projects/cmore/subjects/XNAT_S00017/experiments/XNAT_E00116/scans/{scanid}"
                params = {
                    "xsiType" : "xnat:mrScanData",
                    f"xnat:mrScanData/parameters/addParam[name={test_name}]/addField" : str(result),
                }
                r = requests.put(url, params=params, auth=(user, password), verify=False)
                if r.status_code != 200:
                    print(f" - Failed to set test result {test_name} for scan {scan}: {r.text}")
            except Exception as exc:
                print(f" - Failed to set test result {test_name} for scan {scan}: {str(exc)}")
                traceback.print_exc()

def check_session(options, sessiondir, scandata):
    """
    Run QC on a session
    """
    print(f"Checking session from {sessiondir}")
    scansdir = [d for d in os.listdir(sessiondir) if d.lower() == "scans"]
    if len(scansdir) != 1:
        raise RuntimeError(f"ERROR: Expected single scan dir, got {scansdir}")
    scansdir = os.path.join(sessiondir, scansdir[0])

    for scan in os.listdir(scansdir):
        scandir = os.path.join(scansdir, scan)
        print(f" - Checking {scan}")
        scanid = [scanmd["ID"] for scanmd in scandata if scan.startswith(scanmd["ID"])]
        if len(scanid) != 1:
            print(f"ERROR - could not reliably get scan ID for {scan}: metadata was {scandata}")
            continue
        check_scan(options, scan, scandir, scanid[0])

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        argparse.ArgumentParser.__init__(self, prog="imgqc", add_help=False, **kwargs)
        self.add_argument("--input", help="Input directory", required=True)
        self.add_argument("--project", help="XNAT project")
        self.add_argument("--subject", help="XNAT subject")
        self.add_argument("--session", help="XNAT session")

def main():
    """
    Main script entry poin
    """
    options = ArgumentParser().parse_args()
    if not os.path.isdir(options.input):
        print(f"ERROR: Input directory {options.input} not specified or does not exist")
        sys.exit(1)

    try:
        with open("version.txt") as f:
            version = f.read()
    except IOError:
        version = "(unknown)"

    print(f"Image QC v{version}")

    # Hack to disable certificate validation for HTTPS connections. This is required
    # becuase the certificate used for UoN servers are not always signed by a CA that
    # is recognized by the fixed set of CA certificates built in to python requests.
    os.environ["CURL_CA_BUNDLE"] = ""

    # We need to download scan metadata to identify the ID of the scan more reliably from the directory name
    host, user, password = os.environ["XNAT_HOST"], os.environ["XNAT_USER"], os.environ["XNAT_PASS"]
    r = requests.get(f"{host}/data/projects/{options.project}/subjects/{options.subject}/experiments/{options.session}/scans?format=csv", verify=False, auth=(user, password))
    if r.status_code != 200:
        raise RuntimeError(f"Failed to download session scan data: {r.text}")
    scandata = list(csv.DictReader(io.StringIO(r.text)))
    
    found_session = False
    for path, dirs, files in os.walk(options.input):
        if "scans" in [d.lower() for d in dirs]:
            if not found_session:
                found_session = True
                check_session(options, path, scandata)
            else:
                print("WARN: Found another session: {path} - ignoring")

if __name__ == "__main__":
    main()
