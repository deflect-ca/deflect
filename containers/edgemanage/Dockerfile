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
    cron \
    git # TODO: Remove when edgemanage is installed from pypi

RUN mkdir -p /etc/edgemanage/edges
RUN mkdir -p /var/lib/edgemanage/health
RUN mkdir -p /var/lock/edgemanage
RUN mkdir -p /var/tmp/edgemanage

COPY init.sh init.sh
COPY check.sh check.sh
COPY check-to-reload.sh check-to-reload.sh

# TODO: Install from pypi
RUN pip3 install git+https://github.com/deflect-ca/edgemanage

RUN touch /etc/cron.d/cronjob
RUN touch /var/log/edgemanage.log
# Add dnets to crontab
RUN ./init.sh
RUN chmod 0644 /etc/cron.d/cronjob
RUN crontab /etc/cron.d/cronjob

HEALTHCHECK CMD ./check.sh
#CMD ./init.sh && tail -f /var/log/edgemanage.log
CMD cron && tail -f /var/log/edgemanage.log
