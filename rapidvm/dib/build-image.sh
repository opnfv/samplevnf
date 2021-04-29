#!/usr/bin/env bash
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# A shell script to build the PROX VM image using diskimage-builder
#
usage() {
    echo "Usage: $0 [-i image_name] [-g gs-url] [-v]"
    echo "   -i image_appendix    image name to be pushed to google storage)"
    echo "   -g gs_url            url to store the image"
    echo "   -v                   verify only (build but do not push to google storage)"
    echo "   -w cache             cache directory for disk-image-create"
    exit 1
}

# set -e
#default values
image_appendix="test"
workspace="home/jenkins-ci/opnfv/slave_root/workspace"
gs_url="artifacts.opnfv.org/samplevnf/images"
verify_only=0
while getopts i:g:v:w: flag
do
    case "${flag}" in
        i) image_appendix=${OPTARG};;
        g) gs_url=${OPTARG};;
        v) verify_only=1;;
        w) workspace=${OPTARG};;
        *) usage;exit 1;;
    esac
done
echo "gs_url: $gs_url";
echo "Verify only: $verify_only";
image_name=rapid-${image_appendix}
echo "image name: $image_name.qcow2"
echo "workspace: $workspace"

 install diskimage-builder
python3 -m venv dib-rapid-venv
. dib-rapid-venv/bin/activate
pip3 install --upgrade pip
pip3 install six
pip3 install diskimage-builder
pip3 install gsutil

echo "Checking if image exists in google storage..."
if  command -v gsutil >/dev/null; then
    if gsutil -q stat gs://$gs_url/$image_name.qcow2; then
        echo "Image already exists at http://$gs_url/$image_name.qcow2"
    fi
    echo "Starting build..."
    echo
else
    echo "Cannot check image availability in OPNFV artifact repository (gsutil not available)"
fi

# Add rapid elements directory to the DIB elements path
export ELEMENTS_PATH=`pwd`/elements
# canned user/password for direct login
export DIB_DEV_USER_USERNAME=prox
export DIB_DEV_USER_PASSWORD=prox
export DIB_DEV_USER_PWDLESS_SUDO=Y
# Set the data sources to have ConfigDrive only
export DIB_CLOUD_INIT_DATASOURCES="Ec2, ConfigDrive, OpenStack"
# Use ELRepo to have latest kernel
export DIB_USE_ELREPO_KERNEL=True
echo "Building $image_name.qcow2..."
cache=$workspace/cache
mkdir $cache
#time disk-image-create -o $image_name --image-cache $cache centos7 cloud-init rapid vm

ls -l $image_name.qcow2


if [ $verify_only -eq 1 ]; then
    echo "Image verification SUCCESS"
    echo "NO upload to google storage (-v)"
else
    if command -v gsutil >/dev/null; then
        echo "Uploading $image_name.qcow2..."
        gsutil cp $image_name.qcow2 gs://$gs_url/$image_name.qcow2
        echo "You can access image at http://$gs_url/$image_name.qcow2"
    else
        echo "Cannot upload new image to the OPNFV artifact repository (gsutil not available)"
        exit 1
    fi
fi
deactivate
rm -r dib-rapid-venv
