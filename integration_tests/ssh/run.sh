#!/bin/bash

curl -X 'POST' \
  'http://localhost:8000/auth/setup' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "domain": "md.multifactor.dev",
  "username": "admin",
  "user_principal_name": "admin",
  "display_name": "admin",
  "mail": "admin@example.com",
  "password": "password"
}' -m 30;
echo -e "performing ssh conn";
sshpass -p password \
  ssh \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  admin@localhost -p 222 "exit 0";
exit $?;
