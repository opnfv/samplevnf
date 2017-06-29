###############################################################
#   Docker container for VNF_Catalogue Schema Migration Service
###############################################################
# Purpose: Don't run it from here! Use docker-compose(See README.md)
#
# Maintained by Kumar Rishabh :: penguinRaider
##
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
#

FROM node:boron
MAINTAINER KumarRishabh::penguinRaider <shailrishabh@gmail.com>
LABEL version="v0.0.1" description="Open Source VNF_Catalogue for OPNFV"

ENV DB_HOST mysql
ENV DB_USER vnf_user
ENV DB_PASSWORD vnf_password
ENV DB_DATABASE vnf_catalogue

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY package.json /usr/src/app/

# RUN npm config set proxy http://10.4.20.103:8080
# RUN npm config set https-proxy http://10.4.20.103:8080

RUN npm install

COPY . /usr/src/app

# The ordering of events should be coming up of mysql service and then migration
# of schema for the database. To enforce this causal relationship we use a 3rd_party script.
CMD [ "./3rd_party/wait-for-it/wait-for-it.sh", "mysql:3306", "-t", "0", "--", "node", "migrate"]
