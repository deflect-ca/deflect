#!/bin/bash

for dnet in $(ls /etc/edgemanage/edges); \
do \
    /usr/local/bin/edge_manage \
        --daemonise \
        --dnet $dnet; \
done

# XXX: Check if there's a good reason to manually create the log or not
sleep 0.5 && touch /var/log/edgemanage.log &
