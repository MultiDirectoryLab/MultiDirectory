FROM debian:bookworm

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
    default_realm = MD.MULTIFACTOR.DEV\n\
    noaddresses = TRUE\n\
[realms]\n\
    MD.MULTIFACTOR.DEV = {\n\
        kdc = kerberos:88\n\
        admin_server = kerberos:749\n\
        default_domain = kerberos\n\
    }\n\
""" >> /etc/krb5.conf;
