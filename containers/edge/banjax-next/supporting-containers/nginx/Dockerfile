# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
# 
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM debian:buster-slim AS purge-plugin-build-target

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nginx-extras \
    build-essential \
    git \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev

WORKDIR /root

# XXX should we make this a submodule or vendor it some way?
RUN git clone https://github.com/torden/ngx_cache_purge.git --depth 1
RUN git clone https://github.com/nginx/nginx.git --depth 1 --branch release-1.19.2

WORKDIR /root/nginx

# XXX the plugin needs to be build with exactly the same configuration as nginx
# itself.
# since we're building (some of) nginx here, maybe we should use this instead
# of the upstream nginx image? or maybe modify their Dockerfile to "make modules"
RUN ./auto/configure \
    --add-dynamic-module=/root/ngx_cache_purge/ \
    --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx \
    --with-compat --with-file-aio --with-threads --with-http_addition_module \
    --with-http_auth_request_module --with-http_dav_module \
    --with-http_flv_module --with-http_gunzip_module \
    --with-http_gzip_static_module --with-http_mp4_module \
    --with-http_random_index_module --with-http_realip_module \
    --with-http_secure_link_module --with-http_slice_module \
    --with-http_ssl_module --with-http_stub_status_module \
    --with-http_sub_module --with-http_v2_module --with-mail \
    --with-mail_ssl_module --with-stream --with-stream_realip_module \
    --with-stream_ssl_module --with-stream_ssl_preread_module \
    --with-cc-opt="$(CFLAGS)" --with-ld-opt="$(LDFLAGS)" \
    && make modules



FROM nginx:1.19.2

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    psmisc

RUN mkdir -p /data/nginx

COPY --from=purge-plugin-build-target \
    /root/nginx/objs/ngx_http_cache_purge_module.so \
    /usr/lib/nginx/modules/ngx_http_cache_purge_module_torden.so

COPY nginx.conf /etc/nginx/

RUN mkdir -p /etc/ssl/sites
RUN mkdir -p /etc/ssl-uploaded/sites

RUN mkdir -p /var/log/banjax-next

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
