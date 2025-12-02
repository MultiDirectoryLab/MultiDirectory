#!/bin/bash

fix_rndc_key() {
    local rndc_key="/etc/bind/rndc.key"
    if [ -f "$rndc_key" ]; then
        chown bind:bind "$rndc_key" 2>/dev/null || chown 100:101 "$rndc_key" 2>/dev/null || true
        chmod 640 "$rndc_key" 2>/dev/null || true
    fi
}

/usr/local/bin/docker-entrypoint.sh &

fix_rndc_key

/venvs/.venv/bin/python3.13 -m uvicorn --factory dns_api:create_app --host 0.0.0.0 --reload &

wait -n

exit $?
