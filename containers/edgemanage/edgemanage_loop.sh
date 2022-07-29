#!/bin/bash

# loop through dnets to run edgemanage safely
# integrate with nagios and daemon.log

# VERBOSELOGDIR=/tmp/edgemanage

LOCKFILE=/var/run/edgemanage_loop.lock

# if lockfile exists, add 1 to it's value so that nagios can keep an eye
# on whether we're taking too long.  if it doesn't exist, create. and check
# that the recorded PID still exists, in case the loop was killed early without
# properly clearing it's lock
if [ -e "$LOCKFILE" ] ; then
        LOCK=$(<$LOCKFILE)
        PID=${LOCK%:*}
        COUNT=${LOCK#*:}
        if ps -p $PID  >/dev/null 2>&1 ; then
                NUM=$(( $COUNT + 1 ))
                echo ${PID}:${NUM} > $LOCKFILE
                exit 1
            else
                echo $$:1 > $LOCKFILE
        fi
    else
        echo $$:1 > $LOCKFILE
fi

for DNET in $@ ; do
        if [ -n "$VERBOSELOGDIR" ] ; then
                [ -d "$VERBOSELOGDIR" ] || mkdir $VERBOSELOGDIR
                /usr/local/bin/edge_manage -A $DNET -v >$VERBOSELOGDIR/$(date +%Y.%m.%d-%H.%M.%S).${DNET}.log 2>&1
            else
                /usr/local/bin/edge_manage -A $DNET >/dev/null 2>&1
        fi
done

rm $LOCKFILE
