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

FROM ubuntu:20.04 as builder

ARG DPDK_VERSION=22.07
ENV DPDK_VERSION=${DPDK_VERSION}

ARG BUILD_DIR="/opt/rapid"
ENV BUILD_DIR=${BUILD_DIR}

ENV DEBIAN_FRONTEND=noninteractive

# Install Dependencies
RUN apt update && apt -y install git wget gcc unzip libpcap-dev libncurses5-dev \
        libedit-dev liblua5.3-dev linux-headers-generic iperf3 pciutils \
        libnuma-dev vim tuna wireshark make driverctl openssh-server sudo \
        meson python3-pyelftools pkg-config

WORKDIR ${BUILD_DIR}

# Install DPDK
RUN wget http://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz \
    && tar -xf ./dpdk-${DPDK_VERSION}.tar.xz \
    && cd dpdk-${DPDK_VERSION} \
    && meson build -Dlibdir=lib/x86_64-linux-gnu -Denable_driver_sdk=true \
    && ninja -C build install

WORKDIR ${BUILD_DIR}

# Install Prox
RUN git clone https://gerrit.opnfv.org/gerrit/samplevnf \
    && cd samplevnf/VNFs/DPPD-PROX \
    && COMMIT_ID=$(git rev-parse HEAD) \
    && echo "${COMMIT_ID}" > ${BUILD_DIR}/commit_id \
    && meson build \
    && ninja -C build \
    && cp ${BUILD_DIR}/samplevnf/VNFs/DPPD-PROX/build/prox ${BUILD_DIR}/prox

# Build and copy port info app
WORKDIR ${BUILD_DIR}/samplevnf/VNFs/DPPD-PROX/helper-scripts/rapid/port_info
RUN meson build \
    && ninja -C build \
    && cp ${BUILD_DIR}/samplevnf/VNFs/DPPD-PROX/helper-scripts/rapid/port_info/build/port_info_app ${BUILD_DIR}/port_info_app

RUN ldconfig && pkg-config --modversion libdpdk > ${BUILD_DIR}/dpdk_version
# Create Minimal Install
RUN ldd ${BUILD_DIR}/prox | awk '$2 ~ /=>/ {print $3}' >> ${BUILD_DIR}/list_of_install_components \
    && echo "${BUILD_DIR}/prox" >> ${BUILD_DIR}/list_of_install_components \
    && echo "${BUILD_DIR}/port_info_app" >> ${BUILD_DIR}/list_of_install_components \
    && echo "${BUILD_DIR}/commit_id" >> ${BUILD_DIR}/list_of_install_components \
    && echo "${BUILD_DIR}/dpdk_version" >> ${BUILD_DIR}/list_of_install_components \
    && find /usr/local/lib/x86_64-linux-gnu -not -path '*/\.*' >> ${BUILD_DIR}/list_of_install_components \
    && tar -czvhf ${BUILD_DIR}/install_components.tgz -T ${BUILD_DIR}/list_of_install_components

#############################
# Create slim runtime image #
#############################
FROM ubuntu:20.04

ARG BUILD_DIR="/opt/rapid"
ENV BUILD_DIR=${BUILD_DIR}

ENV DEBIAN_FRONTEND=noninteractive

# Install Runtime  Dependencies
RUN apt update -y
# Install required dynamically linked libraries + required packages
RUN apt -y install sudo openssh-server libatomic1

COPY --from=builder ${BUILD_DIR}/install_components.tgz ${BUILD_DIR}/install_components.tgz

WORKDIR /
RUN tar -xvf ${BUILD_DIR}/install_components.tgz --skip-old-files
RUN ldconfig
RUN rm ${BUILD_DIR}/install_components.tgz

# Expose SSH and PROX ports
EXPOSE 22 8474

RUN useradd -rm -d /home/rapid -s /bin/bash -g root -G sudo -u 1000 rapid \
    && chmod 777 ${BUILD_DIR} \
    && echo 'rapid:rapid' | chpasswd \
    && mkdir /home/rapid/.ssh

# Copy SSH keys
COPY ./rapid_rsa_key.pub /home/rapid/.ssh/authorized_keys
COPY ./rapid_rsa_key.pub /root/.ssh/authorized_keys

RUN chown rapid:root /home/rapid/.ssh/authorized_keys \
 && chmod 600 /home/rapid/.ssh/authorized_keys \
 && chown root:root /root/.ssh/authorized_keys \
 && chmod 600 /root/.ssh/authorized_keys

#RUN apt-get clean && apt autoremove --purge
RUN apt-get autoremove -y && apt-get clean all && rm -rf /var/cache/apt

# Copy startup script
COPY ./start.sh /start.sh
RUN chmod +x /start.sh

ENTRYPOINT ["/start.sh"]
