# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM internetsystemsconsortium/bind9:9.17

WORKDIR /root

COPY named.conf.options /etc/bind/
# XXX these are for debugging and should normally not be here
COPY rndc.conf /etc/bind/
COPY rndc.key /etc/bind/

EXPOSE 53/udp
CMD ["/usr/sbin/named", "-f", "-d", "2"]
