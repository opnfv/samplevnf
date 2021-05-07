##
## Copyright (c) 2020-2021 Intel Corporation
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

FROM opnfv/xtesting

RUN apk upgrade --update

ENV RAPID_TEST =rapid_tst009_throughput

RUN git clone https://git.opnfv.org/samplevnf /samplevnf
WORKDIR /samplevnf/VNFs/DPPD-PROX/helper-scripts/rapid
RUN chmod 400 /samplevnf/VNFs/DPPD-PROX/helper-scripts/rapid/rapid_rsa_key
COPY testcases.yaml /usr/lib/python3.8/site-packages/xtesting/ci/testcases.yaml
RUN apk add python3-dev openssh-client && cd /samplevnf/VNFs/DPPD-PROX/helper-scripts/rapid/ && git init && pip3 install .
CMD ["run_tests", "-t", "all"]
