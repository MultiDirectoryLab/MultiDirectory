from ldap3 import Connection, Server


def run_client():
    server = Server('127.0.0.1:389')
    conn = Connection(server, 'username', 'password', version=3)
    print('connecting')
    try:
        conn.bind()
    except Exception as e:
        print('failed', e)
    else:
        print('OK', conn.search('o=test', '(objectclass=*)'))
