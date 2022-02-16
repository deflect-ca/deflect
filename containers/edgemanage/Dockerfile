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
    bind9utils \
    git # TODO: Remove when edgemanage is installed from pypi

RUN mkdir -p /etc/edgemanage/edges
RUN mkdir -p /var/lib/edgemanage/health
RUN mkdir -p /var/lock/edgemanage
RUN mkdir -p /var/tmp/edgemanage
RUN mkdir -p /etc/edgemanage/canaries

COPY edgemanage.yaml /etc/edgemanage/
COPY myobject.edgemanage /etc/edgemanage/

# TODO: Install from pypi
RUN pip3 install git+https://github.com/deflect-ca/edgemanage

CMD \
    for dnet in $(ls /etc/edgemanage/edges); \
    do \
        /usr/local/bin/edge_manage \
            --daemonise \
            --dnet $dnet; \
    done \
    && tail -f /var/log/edgemanage.log
