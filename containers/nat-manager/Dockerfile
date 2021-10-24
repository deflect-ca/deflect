# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM debian:buster-slim

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    iptables

WORKDIR /root

COPY ./requirements.txt ./
COPY ./map_port.py ./

RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "map_port.py"]
