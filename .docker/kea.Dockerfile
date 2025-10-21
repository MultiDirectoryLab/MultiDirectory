FROM jonasal/kea-dhcp4:3.1.2-alpine AS runtime

COPY --from=jonasal/kea-hooks:3.1.2-alpine /hooks /usr/lib/kea/hooks

RUN touch /kea/config/kea-dhcp4.conf

RUN cat > /kea/config/kea-dhcp4.conf <<EOF
{
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": [ "*" ],
            "dhcp-socket-type": "raw"
        },
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "/kea/sockets/dhcp4.socket"
        },
        "lease-database": {
            "type": "memfile",
            "name": "/kea/leases/dhcp4.csv",
            "lfc-interval": 3600
        },

        "multi-threading": {
            "enable-multi-threading": true,
            "thread-pool-size": 4,
            "packet-queue-size": 28
        },
        "hooks-libraries": [
            {
                "library": "libdhcp_host_cmds.so"
            },
            {
                "library": "libdhcp_subnet_cmds.so"
            },
            {
                "library": "libdhcp_lease_cmds.so"
            },
        ],
        "parked-packet-limit": 128,
        "valid-lifetime": 6000,
        "renew-timer": 900,
        "rebind-timer": 1800,
        "loggers": [
            {
                "name": "kea-dhcp4",
                "output_options": [
                    {
                        "output": "stdout",
                        "pattern": "%D{%Y-%m-%d %H:%M:%S.%q} %-5p [%c/%i.%t] %m\n"
                    },
                    {
                        "output": "/kea/logs/dhcp4.log",
                        "flush": true,
                        "maxsize": 1048576,
                        "maxver": 8,
                        "pattern": "%D{%Y-%m-%d %H:%M:%S.%q} %-5p [%c/%i.%t] %m\n"
                    }
                ],
                "severity": "INFO",
                "debuglevel": 0
            }
        ]
    }
}
EOF

RUN chmod 750 /kea/config/kea-dhcp4.conf

RUN ldconfig /usr/local/lib/kea/hooks