"""Dumps Let's Encrypt certificate from the `acme.json` file.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import base64
import json
import os
import time

from loguru import logger


def dump_acme_cert(resolver: str = "md-resolver") -> None:
    """Dump Let's Encrypt certificate from the `acme.json` file.

    acme file can be generated long enough to exit the script,
    try read until file contents is generated.
    """
    if os.path.exists("/certs/cert.pem") and os.path.exists(
        "/certs/privkey.pem"
    ):
        logger.info("Certeficate and key already exists, exiting...")
        return

    if not os.path.exists("/certs/acme.json"):
        logger.warning("Cannot load ACME file, exiting...")
        return

    try:
        with open("/certs/acme.json") as certfile:
            data = json.load(certfile)

        domain = data[resolver]["Certificates"][0]["domain"]["main"]
        cert: str = data[resolver]["Certificates"][0]["certificate"]
        key: str = data[resolver]["Certificates"][0]["key"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as err:
        logger.error("Error loading TLS certeficate, exiting...")
        time.sleep(5)
        raise SystemExit(1) from err

    logger.info(f"Loaded certeficate for {domain}")

    with (
        open("/certs/cert.pem", "w") as cert_f,
        open("/certs/privkey.pem", "w") as key_f,
    ):
        cert_f.write(base64.b64decode(cert.encode("ascii")).decode())
        key_f.write(base64.b64decode(key.encode("ascii")).decode())

    # The config time needs to be updated in order
    # for the certificates to be updated.
    os.utime("/traefik.yml", (time.time(), time.time()))

    logger.info("Certeficate and key dumped")
    return
