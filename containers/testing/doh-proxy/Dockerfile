# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
# 
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM debian:buster-slim

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    certbot \
    python3 \
    python3-pip \
    netcat

WORKDIR /root

RUN pip3 install doh-proxy

# COPY fullchain1.pem /root
# COPY privkey1.pem /root

EXPOSE 443
# CMD doh-proxy \
#     --upstream-resolver=127.0.0.1 \
#     --certfile=./fullchain1.pem \
#     --keyfile=./privkey1.pem
# 
# XXX the trusted IPs are the nginx hosts in front of this
# need to not hard-code them here
CMD doh-httpproxy \
    --debug \
    --trusted \
    --upstream-resolver=127.0.0.1 \
    --port 8085 \
    --listen-address=0.0.0.0
