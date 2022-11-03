Docker container to run generic image-based QC as an XNAT container service
===========================================================================

Prerequisites
-------------

 - XNAT 1.7 or 1.8
 - Container service plugin installed (this is done by default in XNAT 1.8)
 - Docker installed on XNAT server

Installation instructions
-------------------------

1. Building the data type plugin

    cd plugin
    ./gradlew jar

2. Copy the plugin to the XNAT plugin directory

    cp build/libs/xnat-imgqc-plugin-0.0.1.jar $XNAT_HOME/plugins

3. Restart the XNAT server

For example on Redhat/Centos `sudo systemctl restart tomcat`

4. Install the data type

 - Log in to XNAT as administrator. From the menu select `Administer->Data Types`
 - Select `Set up additional data type`
 - Select `xnat_imgqc:QCData`
 - Enter `ImgQCData` for the singular and plural names, otherwise just click `Next` leaving other options unchanged
 - `ImgQCData` should now be listed in the data types list

5. Install the Docker image 

 - From the menu select `Administer->Plugin Settings`
 - Select `Images and commands`
 - Select `Add new image`
 - For `Image Name` enter `martincraig/xnat-imgqc`. Leave version blank
 - Select `Pull image`

6. Add the command definition if required

Note that there is a bug in some versions of XNAT that means the command definition is not correctly extracted
from the Docker image. Under `Administer->Plugin Settings`, look for ImgQC under `Command Configurations`. If
it is *not* present you will need to do the following:

 - Under `Images and Commands` expand hidden images
 - Find `martincraig/xnat-imgqc` and click `Add Command`
 - Delete any text, and paste the contents of `docker/img_qc_cmd.json` into the window
 - Click `Save command`

7. Enable the command for the XNAT server

This can be done under `Images and Commands` on the `Plugin Settings` page

8. Enable the command for a project

Select a project and click `Project Settings` from the menu. The ImgQC command should be listed and can 
be enabled. Default settings can also be added

9. Run the command

Select an MR session, click `Run Container` and select ImgQC

