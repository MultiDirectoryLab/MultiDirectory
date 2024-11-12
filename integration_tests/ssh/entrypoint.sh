#!/bin/bash
mkdir /certs;
openssl req -nodes -new -x509 -keyout /certs/privkey.pem -out /certs/cert.pem -subj \
    '/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=Multifactor/CN=md.multifactor.dev';
python multidirectory.py --ldap;
