#!/bin/bash
test -f /opt/zone.key && echo 'KEY EXISTS, SKIPPING...' || tsig-keygen zone > /opt/zone.key
source docker-entrypoint.sh
