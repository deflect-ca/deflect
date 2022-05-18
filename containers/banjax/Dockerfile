# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM golang:1.17.0-buster

WORKDIR /opt/banjax

RUN mkdir -p /etc/banjax
RUN mkdir -p /var/log/banjax

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        iptables

COPY ./banjax-config.yaml /etc/banjax/
RUN go install github.com/deflect-ca/banjax@v0.2.2

EXPOSE 8081

CMD ["banjax"]
