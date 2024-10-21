#! /bin/bash
# 3 years
test -f /certs/krbcert.pem && echo "CERT EXISTS, SKIPPING..." || openssl \
    req -nodes -new -x509 \
    -days 1095 \
    -keyout /certs/krbkey.pem \
    -out /certs/krbcert.pem \
    -addext "subjectAltName=DNS:kadmin_api" \
    -subj '/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=Multifactor/CN=kadmin_api'
