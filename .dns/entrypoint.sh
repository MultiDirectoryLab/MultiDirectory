#!/bin/bash
/usr/local/bin/docker-entrypoint.sh &
/venvs/bin/python3.12 -m uvicorn --factory dns_api:create_app --host 0.0.0.0 --reload &

wait -n

exit $?