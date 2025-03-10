#!/bin/bash

apt-get update && apt-get -y install ldap-utils krb5-user iproute2;

touch /etc/krb5.conf && echo """\
[libdefaults]\n\
    default_realm = MD.LOCALHOST\n\
    dns_lookup_realm = false\n\
    dns_lookup_kdc = false\n\
    realm_try_domains = 1\n\
    ticket_lifetime = 24h\n\
    renew_lifetime = 7d\n\
    forwardable = true\n\
\n\
[realms]\n\
    MD.LOCALHOST = {\n\
        kdc = md.localhost\n\
        admin_server = md.localhost\n\
        default_domain = md.localhost\n\
    }\n\

[domain_realm]\n\
    .md.localhost = MD.LOCALHOST\n\
    md.localhost = MD.LOCALHOST\n\
""" > /etc/krb5.conf;

echo "127.0.0.1 md.localhost" >> /etc/hosts;

curl -X 'POST' \
  'http://md.localhost:8000/auth/setup' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "domain": "md.localhost",
  "username": "admin",
  "user_principal_name": "admin",
  "display_name": "admin",
  "mail": "admin@example.com",
  "password": "Password123"
}' -m 30;

echo "Password123" | kinit admin;
echo -e "Performing LDAP authentication via GSSAPI";

ldapwhoami -H ldap://md.localhost:389 -Y GSSAPI;

exit $?;