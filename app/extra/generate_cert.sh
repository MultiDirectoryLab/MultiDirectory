#! /bin/bash

test -f /certs/krbcert.pem && echo "CERT EXISTS, SKIPPING..." || openssl \
    req -nodes -new -x509 \
    -keyout /certs/krbkey.pem \
    -out /certs/krbcert.pem \
    -addext "subjectAltName=DNS:kadmin" \
    -subj '/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=Multifactor/CN=kadmin'
