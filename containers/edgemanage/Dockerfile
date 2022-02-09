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
    supervisor \
    bind9utils \
    cron \
    git # TODO: Remove when edgemanage is installed from pypi

RUN mkdir -p /etc/edgemanage/edges
RUN mkdir -p /var/lib/edgemanage/health
RUN mkdir -p /var/lock/edgemanage
RUN mkdir -p /var/tmp/edgemanage
RUN mkdir -p /etc/edgemanage/zones
RUN mkdir -p /etc/edgemanage/zones/dnext1
RUN mkdir -p /var/cache/bind
RUN mkdir -p /etc/edgemanage/canaries

COPY edgemanage.yaml /etc/edgemanage/
COPY myobject.edgemanage /etc/edgemanage/
RUN touch /etc/edgemanage/zones/dnext1/example.com.zone
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# TODO: Install from pypi
RUN pip3 install git+https://github.com/deflect-ca/edgemanage@feature/override-dns

# XXX: Use cron for easy debugging
RUN echo "* * * * * /usr/local/bin/edge_manage -A dnext1 -v >> /var/log/cron.log 2>&1" > /etc/cron.d/cronjob
RUN chmod 0644 /etc/cron.d/cronjob
RUN crontab /etc/cron.d/cronjob
RUN touch /var/log/cron.log
CMD cron && tail -f /var/log/cron.log

# TODO: run supervisor with a non-root user
# CMD ["/usr/bin/supervisord"]
