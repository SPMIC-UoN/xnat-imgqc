#!/bin/bash

cp Dockerfile.in Dockerfile
python scripts/cmd2label.py imgqc_cmd.json >> Dockerfile

tag=`cat version.txt`
docker build -t martincraig/xnat-imgqc .
docker tag martincraig/xnat-imgqc martincraig/xnat-imgqc:$tag 
docker push martincraig/xnat-imgqc:$tag
docker push martincraig/xnat-imgqc:latest
