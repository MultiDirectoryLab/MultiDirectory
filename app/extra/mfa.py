"""MFA CLI for local iteraction."""

import json

from loguru import logger
from websockets.sync.client import connect


def main() -> None:  # noqa

    with connect('ws://api.localhost/api/multifactor/connect') as conn:
        logger.info(json.loads(conn.recv()))
        conn.send(json.dumps({"username": "mdadmin", "password": "password"}))
        logger.info(json.loads(conn.recv()))
        logger.info(json.loads(conn.recv()))


if __name__ == '__main__':
    main()
