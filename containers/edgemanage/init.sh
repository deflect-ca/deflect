#!/bin/bash

for dnet in $(ls /etc/edgemanage/edges); \
do \
    /usr/local/bin/edge_manage \
        --daemonise \
        --dnet $dnet; \
done
