#!/bin/bash

for dnet in $(ls -l /etc/bind/deflect_zones | grep "^d" | awk '{print $9}'); \
do \
    echo "* * * * * /usr/local/bin/edge_manage -A $dnet 2>&1" >> /etc/cron.d/cronjob
    # /usr/local/bin/edge_manage \
    #    --daemonise \
    #    --dnet $dnet; \
done

# fallback, if empty add dnext1 anyway
[ -s /etc/cron.d/cronjob ] || echo "* * * * * /usr/local/bin/edge_manage -A dnext1 2>&1" >> /etc/cron.d/cronjob
