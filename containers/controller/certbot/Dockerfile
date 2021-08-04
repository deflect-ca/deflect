# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
# 
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM python:3.9.2-slim-buster

WORKDIR /root

RUN pip3 install certbot certbot-dns-standalone

# RUN certbot --staging --non-interactive --agree-tos --email joe@joelanders.net \
# 	certonly --preferred-challenges dns --authenticator
# 	certbot-dns-standalone:dns-standalone
# 	--certbot-dns-standalone:dns-standalone-address=0.0.0.0
# 	--certbot-dns-standalone:dns-standalone-port=53 -d example.com
# 

EXPOSE 5053
# XXX use exec form (with an array)
# CMD netcat -ulp 5053
# CMD ["tail", "-f", "/dev/null"]
CMD ["sleep", "infinity"]
# CMD ["while :; do :; done & kill -STOP $! && wait $!"]
