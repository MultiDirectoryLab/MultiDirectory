#!/bin/bash

/usr/sbin/kea-dhcp4 -c /etc/kea/kea-dhcp4.conf &

/usr/sbin/kea-ctrl-agent -c /etc/kea/kea-ctrl-agent.conf &

wait
