#!/usr/bin/env bash
##
## Copyright (c) 2010-2019 Intel Corporation
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

PROX_DEPLOY_DIR="."
PROX_IMAGE_NAME="prox_slim"
RSA_KEY_FILE_NAME="rapid_rsa_key"

DOCKERFILE="Dockerfile"
DOCKER_REGISTRY="localhost:5000"

USE_DOCKER_CACHE="n"

IMAGE_BUILD_LOG="dockerimage-build.log"

function create_ssh_key()
{
	if [ -f ./${RSA_KEY_FILE_NAME} ]; then
		read -p "RSA key already exist! Do you want to remove it (yYnN)?" -n 1 -r

		if [ "${REPLY}" == "y" ] || [ "${REPLY}" == "Y" ]; then
			echo "Removing existing key..."
			sleep 3

			[ -f "./${RSA_KEY_FILE_NAME}" ] && rm -rf ./${RSA_KEY_FILE_NAME}
			[ -f "./${RSA_KEY_FILE_NAME}.pub" ] && rm -rf ./${RSA_KEY_FILE_NAME}.pub
		else
			echo "Using existing key..."
			return
		fi
	fi

	echo "Generating new RSA key..."
	ssh-keygen -t rsa -b 4096 -N "" -f ./${RSA_KEY_FILE_NAME}
}

function build_prox_image()
{
	if [ "${USE_DOCKER_CACHE}" == "y" ]; then
		echo "Building image using cache..."
		docker build --rm -t ${PROX_IMAGE_NAME}:latest -f ${DOCKERFILE} ${PROX_DEPLOY_DIR} 2>&1 | tee ./${IMAGE_BUILD_LOG}
	else
		echo "Building image without cache..."
		docker build --no-cache --rm -t ${PROX_IMAGE_NAME}:latest -f ${DOCKERFILE} ${PROX_DEPLOY_DIR} 2>&1 | tee ./${IMAGE_BUILD_LOG}
	fi
}

function save_prox_image()
{
	echo "Saving image ${PROX_IMAGE_NAME}:latest to ./${PROX_IMAGE_NAME}.tar"
	docker save -o ./${PROX_IMAGE_NAME}.tar ${PROX_IMAGE_NAME}:latest
}

function load_prox_image()
{
	echo "Loading image ./${PROX_IMAGE_NAME}.tar"
	docker load -i ./${PROX_IMAGE_NAME}.tar
}

function push_prox_image()
{
	docker tag ${PROX_IMAGE_NAME}:latest ${DOCKER_REGISTRY}/${PROX_IMAGE_NAME}
	docker push ${DOCKER_REGISTRY}/${PROX_IMAGE_NAME}
}

function print_help()
{
	echo "${0}: [build|load|push]"
	echo "    build: build and save image ${PROX_IMAGE_NAME}:latest using ${DOCKERFILE}"
	echo "    load:  load saved image from ${PROX_IMAGE_NAME}.tar file in the local registry"
	echo "    push:  tag and push local ${PROX_IMAGE_NAME}:latest image in the ${DOCKER_REGISTRY}/${PROX_IMAGE_NAME} registry"
}

if [ "$1" == "build" ]; then
	create_ssh_key
	build_prox_image
	save_prox_image
elif [ "$1" == "load" ]; then
	load_prox_image
elif [ "$1" == "push" ]; then
	push_prox_image
else
	print_help
fi
