###############################################################
#   Docker container for VNF_Catalogue cronjob service
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

RUN apt-get update
RUN apt-get install vim -y
RUN apt-get install cron -y

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

# ADD crontab /etc/cron.d/simple-cron

COPY . /usr/src/app

RUN chmod +x git_count_loc.sh
RUN chmod +x script.sh

RUN crontab crontab
RUN sed -i '/session    required     pam_loginuid.so/c\#session    required   pam_loginuid.so' /etc/pam.d/cron

# Give execution rights on the cron job
# RUN chmod 0644 /etc/cron.d/simple-cron
#
# # Create the log file to be able to run tail
RUN touch /var/log/cron.log

# The ordering of events should be coming up of mysql service and then running
# of cronjob. To enforce this causal relationship we use a 3rd_party script.
CMD [ "./3rd_party/wait-for-it/wait-for-it.sh", "mysql:3306", "-t", "0", "--", "cron", "&&", "tail", "-f", "/var/log/cron.log"]
