#!/bin/bash
CONFIG_FILE=/etc/edgemanage/edgemanage.yaml
LOOK_UP="Edge list is"

# Gets variables from edgemanage config file
log_path=$(grep logpath\: $CONFIG_FILE | cut -d: -f 2)
frequency=$(grep run_frequency\: $CONFIG_FILE | cut -d: -f 2)

# Obtains the last log and calculates its timestamp
last_datetime=$(grep  "${LOOK_UP}" $log_path | tail -1 | cut -d, -f 1)
last_timestamp=$(date -d "${last_datetime}" +%s)
now=$(date +%s)

# Sets a timeout and calculates the elapsed time between now and the latest log entry
timeout=$(( $frequency * 2 ))
elapsed=$(( $now - $last_timestamp ))


if (( $elapsed > $timeout )); then
    exit 1
fi
