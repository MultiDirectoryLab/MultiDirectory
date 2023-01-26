"""Test client for LDAP server."""

from ldap3 import Connection, Server
from loguru import logger


def run_client():
    """Run bind and search request."""
    server = Server('127.0.0.1:389')
    conn = Connection(
        server, 'CN=User 1,OU=IT,DC=multifactor,DC=dev', 'password', version=3)
    logger.info('connecting')
    try:
        conn.bind()
    except Exception as exc:
        logger.error(f'failed {exc}')
    else:
        search_res = conn.search(
            'o=test',
            search_filter='(&(name=bob)(mail=*@example.com)(|(dept=accounting)(dept=operations)))',
            attributes=['objectClass', 'baseName']
        )
        logger.info(f'OK {search_res}')
        res = conn.unbind()
        logger.info(f'OK {res}')


if __name__ == '__main__':
    run_client()
