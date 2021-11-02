##
## Copyright (c) 2019 Intel Corporation
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

##################################################
# Build all components in separate builder image #
##################################################
FROM centos:7 as builder

ARG BUILD_DIR=/opt/rapid

COPY ./port_info ${BUILD_DIR}/port_info

COPY ./deploycentostools.sh ${BUILD_DIR}/
RUN chmod +x ${BUILD_DIR}/deploycentostools.sh \
  && ${BUILD_DIR}/deploycentostools.sh -k deploy

#############################
# Create slim runtime image #
#############################
FROM centos:7

ARG BUILD_DIR=/opt/rapid

COPY ./deploycentostools.sh ${BUILD_DIR}/
COPY --from=builder ${BUILD_DIR}/install_components.tgz ${BUILD_DIR}/install_components.tgz
COPY --from=builder ${BUILD_DIR}/src ${BUILD_DIR}/src

RUN chmod a+rwx ${BUILD_DIR} && chmod +x ${BUILD_DIR}/deploycentostools.sh \
 && ${BUILD_DIR}/deploycentostools.sh -k runtime_image

# Expose SSH and PROX ports
EXPOSE 22 8474

# Copy SSH keys
COPY ./rapid_rsa_key.pub /home/centos/.ssh/authorized_keys
COPY ./rapid_rsa_key.pub /root/.ssh/authorized_keys

RUN chown centos:centos /home/centos/.ssh/authorized_keys \
 && chmod 600 /home/centos/.ssh/authorized_keys \
 && chown root:root /root/.ssh/authorized_keys \
 && chmod 600 /root/.ssh/authorized_keys

# Copy startup script
COPY ./start.sh /start.sh
RUN chmod +x /start.sh

ENTRYPOINT ["/start.sh"]
