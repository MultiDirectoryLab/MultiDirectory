from ldap3 import Connection, Server


def run_client():
    server = Server('127.0.0.1:389')
    conn = Connection(server, 'username', 'password')
    try:
        conn.bind()
    except Exception:
        return
    print(conn)
