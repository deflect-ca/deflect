# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# FROM internetsystemsconsortium/bind9:9.16

# WORKDIR /root

FROM ubuntu:focal
MAINTAINER BIND 9 Developers <bind9-dev@isc.org>

ENV DEBIAN_FRONTEND noninteractive
ENV LC_ALL C.UTF-8

RUN apt-get -qqqy update
RUN apt-get -qqqy install apt-utils software-properties-common dctrl-tools

ARG DEB_VERSION=1:9.16.20-2+ubuntu20.04.1+isc+1
RUN add-apt-repository -y ppa:isc/bind
RUN apt-get -qqqy update && apt-get -qqqy dist-upgrade && apt-get -qqqy install bind9 bind9-utils
RUN mkdir -p /etc/bind          && chmod 755 /etc/bind
RUN mkdir -p /var/cache/bind    && chmod 755 /var/cache/bind
RUN mkdir -p /var/lib/bind      && chmod 755 /var/lib/bind
RUN mkdir -p /var/log/bind      && chmod 755 /var/log/bind
RUN mkdir -p /var/log           && chmod 755 /var/log
RUN mkdir -p /run/named         && chmod 755 /run/named

EXPOSE 53/udp 53/tcp 953/tcp

COPY named.conf.options /etc/bind/
COPY named.conf.options-private /etc/bind/

COPY rndc.conf /etc/bind/
COPY rndc.key /etc/bind/

# CMD ["/usr/sbin/named", "-f", "-d", "2"]
CMD ["/usr/sbin/named", "-g", "-c", "/etc/bind/named.conf", "-u", "root"]
