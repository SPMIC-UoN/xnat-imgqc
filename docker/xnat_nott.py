"""
Local functions for XNAT containers developed to work with XNAT instances
at Nottingham or used by Nottingham researchers
"""
import csv
import getpass
import io
import os
import sys
import requests
import logging
import tempfile
import urllib, urllib3

import xmltodict

LOG = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def setup_logging(options):
    if options.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO)

def get_version(options):
    try:
        with open("version.txt") as f:
            options.version = f.read().strip()
    except IOError:
        options.version = "(unknown)"

def convert_dicoms(dicomdir, niftidir):
    os.makedirs(niftidir, exist_ok=True, mode=0o777)
    cmd = "dcm2niix -o %s %s %s" % (niftidir, "-m n -f %d_%q -z y", dicomdir)
    LOG.info(cmd)
    retval = os.system(cmd)
    if retval != 0:
        LOG.warning("DICOM->NIFTI conversion failed")
        return None
    return niftidir

def get_host_url(options):
    """
    Get the 'real' URL for XNAT, since it may be subject to redirects and these mess up POST/PUT requests
    """
    if not options.host:
        options.host = os.environ["XNAT_HOST"]
    LOG.info(f"Checking host URL: {options.host}")
    r = requests.get(options.host, verify=False, allow_redirects=False)
    if r.status_code in (301, 302):
        new_host = r.headers['Location']
        LOG.info(f" - Redirect detected: {new_host}")
        # Sometimes gets redirected to login page - don't want this!
        if "/app/" in new_host:
            new_host = new_host[:new_host.index("/app/")]
        options.host = new_host
    options.host = options.host.rstrip("/")

def get_credentials(options):
    get_host_url(options)
    if not options.user:
        options.user = os.environ.get("XNAT_USER", None)
    if not options.user:
        options.user = input("XNAT username: ")
    options.password = os.environ.get("XNAT_PASS", None)
    if not options.password:
        options.password = getpass.getpass()
    LOG.info(f"Using XNAT server at: {options.host} with username: {options.user}")

def get_projects(options):
    """
    Get project details
    """
    LOG.debug(f"Getting projects")
    try:
        params={"format" : "csv"}
        csvdata = xnat_get(options, "data/projects/", params=params)
        return list(csv.DictReader(io.StringIO(csvdata)))
    except:
        LOG.exception("Error getting projects")
        return []

def get_project(options, project_identifier):
    """
    Get project details from specified project name/ID

    :param project_identifier: Case insensitive identifier, may be ID or name
    """
    project_identifier = project_identifier.lower()
    projects = get_projects(options)
    for p in projects:
        if p["ID"].lower() == project_identifier or p["name"].lower() == project_identifier:
            return project_identifier

    project_names = [p["name"] for p in projects]
    raise RuntimeError(f"Project not found: {project_identifier} - known project: {project_names}")

def get_subjects(options, project):
    """
    Get subject details for specified project
    """
    project_id = project["ID"]
    LOG.debug(f"Getting subjects for prject {project_id}")
    params={"format" : "csv"}
    csvdata = xnat_get(options, f"data/projects/{project_id}/subjects/", params=params)
    subjects = list(csv.DictReader(io.StringIO(csvdata)))
    return subjects

def get_sessions(options, project, subject):
    """
    Get session details for specified project and subject
    """
    project_id = project["ID"]
    subject_id = subject["ID"]
    LOG.debug(f"Getting sessions for project {project_id}, subject {subject_id}")
    sessions = []

    params = {"xsiType": "xnat:mrSessionData", "format" : "csv"}
    csvdata = xnat_get(options, f"data/projects/{project_id}/subjects/{subject_id}/experiments/", params=params)
    for session in list(csv.DictReader(io.StringIO(csvdata))):
        session["subject"] = subject_id
        session["subject_label"] = subject['label']
        sessions.append(session)
    return sessions

def get_all_sessions(options, project):
    """
    Get session details for all subjects in specified project
    """
    project_id = project["ID"]
    LOG.debug(f"Getting all sessions for project {project_id}")
    
    subjects = get_subjects(options, project)
    sessions = []
    for subject in subjects:
        sessions += get_sessions(options, project, subject)
    return sessions

def get_assessors(options, session, assessor_xsitype):
    """
    Get the results from the ImgQC assessor for a session

    Assumes only one such assessor exists - which should be the case!

    :return: List of scan dictionaries
    """
    session_id = session["ID"]
    params={"format" : "csv", "xsiType" : assessor_xsitype, "columns" : "ID"}
    csvdata = xnat_get(options, f"data/experiments/{session_id}/assessors/", params=params)
    assessors = []
    for row in csv.DictReader(io.StringIO(csvdata), skipinitialspace=True):
        assessor_id = row['ID']
        assessor_xml = xnat_get(options, f"data/experiments/{session_id}/assessors/{assessor_id}", params={"format" : "xml"})
        assessor = xmltodict.parse(assessor_xml)[assessor_xsitype]
        assessor["ID"] = assessor_id
        assessors.append(assessor)

    return assessors

def xnat_login(options):
    """
    Attempt to use the auth service to log in but fall back on HTTP basic auth if not working
    """
    url = f"{options.host}/data/services/auth"
    auth_params={"username" : options.user, "password" : options.password}
    LOG.info(f"Attempting log in: {url}")
    r = requests.put(url, verify=False, data=urllib.parse.urlencode(auth_params))
    LOG.debug(f"status: {r.status_code}")
    if r.status_code == 200:
        LOG.info(" - Logged in using auth service")
        options.cookies = {"JSESSIONID" : r.text}
        options.auth = None
    else:
        LOG.info(f" - Failed to log in using auth service - will use basic auth instead")
        options.cookies = {}
        options.auth = (options.user, options.password)
    LOG.info("DONE login")

def xnat_get(options, url, params=None):
    """
    Get text content from XNAT, e.g. CSV/XML data
    """
    LOG.info(f"Executing GET on {options.host}")
    url = url.lstrip("/")
    url = f"{options.host}/{url}"
    LOG.info(f" - URL: {url}")
    tries = 0
    while tries < 10:
        tries += 1
        r = requests.get(url, verify=False, cookies=options.cookies, auth=options.auth, params=params)
        if r.status_code == 200:
            break
    if r.status_code != 200:
        raise RuntimeError(f"Failed to execute GET after 10 tries: {r.status_code} {r.text}")
    return r.text

def xnat_download(options, url, params=None, local_fname=None):
    LOG.info(f"Downloading data from {options.host}")
    url = url.lstrip("/")
    url = f"{options.host}/{url}"
    LOG.info(f" - URL: {url}")
    r = requests.get(url, verify=False, cookies=options.cookies, auth=options.auth, params=params, stream=True)
    LOG.debug(f" - status: {r.status_code}")
    if r.status_code == 401:
        print(" - Session expired, will re-login and retry")
        xnat_login(options)
        r = requests.get(url, verify=False, cookies=options.cookies, auth=options.auth, params=params, stream=True)
    r.raise_for_status()

    if not local_fname:
        local_fname = tempfile.NamedTemporaryFile(delete=False).name
    try:
        with open(local_fname, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
            LOG.info(f" - Downloaded to: {local_fname}")

        stats = os.stat(local_fname)
        LOG.info(f" - Byte size: {stats.st_size}")
        return local_fname
    except:
        if local_fname and os.path.exists(local_fname):
            os.remove(local_fname)
        raise

def xnat_upload(options, url, local_fname, replace_assessor=None):
    """
    Upload data to XNAT
    """
    LOG.info(f"Uploading data to {options.host}")
    url = url.lstrip("/")
    url = f"{options.host}/{url}"
    LOG.info(f" - URL: {url}")

    with open(local_fname, "r") as f:
        files = {'file': f}
        url = f"{options.host}/{url}"
        while True:
            r = requests.post(url, files=files, auth=options.auth, cookies=options.cookies, verify=False, allow_redirects=False) 
            if r.status_code == 409:
                LOG.info(" - File already exists")
                if replace_assessor:
                    LOG.info(" - will delete and replace")
                    delete_url = url + replace_assessor
                    LOG.info(f" - Delete URL: {delete_url}")
                    r = requests.delete(delete_url, auth=options.auth, cookies=options.cookies, verify=False)
                    if r.status_code == 200:
                        LOG.info(" - Delete successful - re-posting")
                        f.seek(0)
                        continue

            if r.status_code != 200:
                raise RuntimeError(f"Failed to upload data: {r.status_code} {r.text}")
            break
