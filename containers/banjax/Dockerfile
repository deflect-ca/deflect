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

# We don't copy file here anymore, config is taken from a volume bind at /etc/banjax
RUN go install github.com/deflect-ca/banjax@d871454f

EXPOSE 8081

CMD ["banjax"]
