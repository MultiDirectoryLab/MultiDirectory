FROM debian:bookworm
ENV KRB5_TRACE=/dev/stdout
RUN set -eux; \
    apt-get update -y; \
    apt-get install \
    krb5-kdc-ldap \
    krb5-pkinit \
    wamerican \
    libsasl2-modules-gssapi-mit \
    --no-install-recommends -y

RUN touch /etc/krb5.conf && echo """\
[libdefaults]\n\
    # default_realm = MD.LOCALHOST\n\
    dns_lookup_realm = false\n\
    dns_lookup_kdc = false\n\
    noaddresses = TRUE\n\
[realms]\n\
    MD.LOCALHOST = {\n\
        kdc = kerberos:88\n\
        admin_server = kerberos:749\n\
        default_domain = md.localhost\n\
    }\n\
    MD2.LOCALHOST = {\n\
        kdc = kerberos2:88\n\
        admin_server = kerberos2:749\n\
        default_domain = md2.localhost\n\
    }\n\
[domain_realm]\n\
    .md.localhost = MD.LOCALHOST\n\
    md.localhost = MD.LOCALHOST\n\
    .md2.localhost = MD2.LOCALHOST\n\
    md2.localhost = MD2.LOCALHOST\n\
[capaths]\n\
    MD.LOCALHOST = {\n\
        MD2.LOCALHOST = .\n\
    }\n\
    MD2.LOCALHOST = {\n\
        MD.LOCALHOST = .\n\
    }\n\
""" > /etc/krb5.conf;
