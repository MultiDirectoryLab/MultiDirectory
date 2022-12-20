"""Test client for LDAP server."""

from ldap3 import Connection, Server
from loguru import logger


def run_client():
    """Run bind and search request."""
    server = Server('127.0.0.1:389')
    conn = Connection(server, 'CN=FooUser,OU=Users,DC=multifactor,DC=local', 'password', version=3)
    logger.info('connecting')
    try:
        conn.bind()
    except Exception as exc:
        logger.error(f'failed {exc}')
    else:
        search_res = conn.search('o=test', '(objectclass=*)')
        logger.info(f'OK {search_res}')
        res = conn.unbind()
        logger.info(f'OK {res}')


if __name__ == '__main__':
    run_client()
