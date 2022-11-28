"""
ImgQC: Simple script to grab population statistics from all the image QC
       metrics in a project so we can define variables for flagging outliers
"""
import argparse
import getpass
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import numpy as np

class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, **kwargs):
        argparse.ArgumentParser.__init__(self, prog="imgqc", add_help=False, **kwargs)
        self.add_argument("--host", help="XNAT host")
        self.add_argument("--project", help="XNAT project")

def main():
    options = ArgumentParser().parse_args()

    user = input("Username: ")
    password = getpass.getpass()

    data = {}
    url = f"{options.host}/data/projects/{options.project}/subjects/"
    r = requests.get(url, auth=(user, password), params={"format" : "csv"}, verify=False)
    r.raise_for_status()
    subjects = r.text.splitlines()
    for s in subjects[1:]:
        id = s.split(",")[0]
        url = f"{options.host}/data/projects/{options.project}/subjects/{id}/experiments/"
        r = requests.get(url, auth=(user, password), params={"format" : "csv"}, verify=False)
        r.raise_for_status()
        exps = r.text.splitlines()
        for exp in exps[1:]:
            exp_id = exp.split(",")[0]
            url = f"{options.host}/data/projects/{options.project}/subjects/{id}/experiments/{exp_id}/assessors"
            r = requests.get(url, auth=(user, password), params={"format" : "csv"}, verify=False)
            r.raise_for_status()
            assess = r.text.splitlines()
            for ass in assess[1:]:
                ass_id = ass.split(",")[0]
                if "ImgQC" in ass:
                    url = f"{options.host}/data/projects/{options.project}/subjects/{id}/experiments/{exp_id}/assessors/{ass_id}"
                    r = requests.get(url, auth=(user, password), params={"format" : "xml"}, verify=False)
                    r.raise_for_status()
                    # hacky xml 'parsing'
                    name, result = None, None
                    for l in r.text.splitlines():
                        if "xnat_imgqc:name" in l:
                            name = l.split("xnat_imgqc:name")[1].strip("<").strip(">").split()[0].lower()
                        if "xnat_imgqc:result" in l:
                            result = float(l.split("xnat_imgqc:result")[1].replace("<", "").replace(">", "").replace("/", "").split()[0])
                        if name and result:
                            if name not in data:
                                data[name] = []
                            data[name].append(result)
                            name, result = None, None

    for name, values in data.items():
        print(f"{name} {np.mean(values)} {np.std(values)}")

if __name__ == "__main__":
    main()
