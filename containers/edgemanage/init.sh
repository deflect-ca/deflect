#!/bin/bash

# clear file
> /tmp/cronjob

for dnet in $(ls -l /etc/edgemanage/edges | grep '^-' | awk '{print $9}'); \
do \
    echo -n " $dnet" >> /tmp/cronjob
done

# fallback, if empty add dnext1 anyway
[ -s /tmp/cronjob ] || echo -n " dnext1" >> /tmp/cronjob

echo "* * * * * /edgemanage_loop.sh$(cat /tmp/cronjob)" > /etc/cron.d/cronjob

# reload config
crontab /etc/cron.d/cronjob
