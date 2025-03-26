"""Dumps Let's Encrypt certificate from the `acme.json` file.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import base64
import json
import os

from loguru import logger


def dump_acme_cert() -> None:
    """Dump Let's Encrypt certificate from the `acme.json` file."""
    if not os.path.exists("/certs/acme.json"):
        logger.warning("Cannot load ACME file for MultiDirectory")
        return

    if os.path.exists("/certs/cert.pem") and os.path.exists(
        "/certs/privkey.pem"
    ):
        logger.info("Cert already exists")
        return

    try:
        with open("/certs/acme.json") as certfile:
            data = json.load(certfile)

        domain = data["md-resolver"]["Certificates"][0]["domain"]["main"]
        cert = data["md-resolver"]["Certificates"][0]["certificate"]
        key = data["md-resolver"]["Certificates"][0]["key"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        logger.warning("Cannot load TLS cert for MultiDirectory")
        return

    else:
        logger.info(f"Loaded cert for {domain}")

        cert = base64.b64decode(cert.encode("ascii")).decode()
        key = base64.b64decode(key.encode("ascii")).decode()

        with open("/certs/cert.pem", "w") as f:
            f.write(cert)

        with open("/certs/privkey.pem", "w") as f:
            f.write(key)

        logger.info("Cert dumped")
