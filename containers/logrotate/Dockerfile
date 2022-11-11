FROM alpine:3.12

RUN set -x \
  && apk add --no-cache logrotate tini tzdata moreutils \
  && mv /etc/periodic/daily/logrotate /etc/.logrotate.cronjob

COPY ./entrypoint.sh /entrypoint.sh
COPY ./logrotate.d/banjax /etc/logrotate.d/
COPY ./logrotate.d/nginx /etc/logrotate.d/

RUN chmod 644 /etc/logrotate.d/banjax /etc/logrotate.d/nginx

ENTRYPOINT ["tini", "-g", "--"]
CMD ["/entrypoint.sh"]
