"""Dumps Let's Encrypt certificate from the `acme.json` file.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import base64
import json
import os
import shutil

from loguru import logger


def write_with_backup(filepath: str, content: str) -> None:
    """Backup the file and write the content."""
    if os.path.exists(filepath):
        shutil.copy(filepath, f"{filepath}.bak")
        logger.info(f"Backup created: {filepath}.bak")

    with open(filepath, "w") as file:
        file.write(content)


acme_exc = SystemError(
    "Let's Encrypt certificate not found. The `acme.json` "
    "file might not have been generated or lacks certificate details. "
    "This can also occur if the certificate failed to generate "
    "for localhost, as Let's Encrypt only issues "
    "certificates for public domains. "
    "Try deleting and recreating the `acme.json` file, "
    "or consider using a self-signed certificate "
    "for local environments or closed networks."
)

if not os.path.exists("/certs/acme.json"):
    logger.critical("Cannot load ACME file for MultiDirectory")
    raise acme_exc

try:
    with open("/certs/acme.json") as certfile:
        data = json.load(certfile)

    domain = data["md-resolver"]["Certificates"][0]["domain"]["main"]
    cert = data["md-resolver"]["Certificates"][0]["certificate"]
    key = data["md-resolver"]["Certificates"][0]["key"]
except (KeyError, IndexError, TypeError, json.JSONDecodeError) as err:
    logger.critical("Cannot load TLS cert for MultiDirectory")
    raise acme_exc from err

else:
    logger.info(f"Saved cert for {domain}")

    cert = base64.b64decode(cert.encode("ascii")).decode()
    key = base64.b64decode(key.encode("ascii")).decode()

    write_with_backup("/certs/cert.pem", cert)
    write_with_backup("/certs/privkey.pem", key)

    logger.info(
        "Let's Encrypt cert saved to /certs/cert.pem, /certs/privkey.pem"
    )
