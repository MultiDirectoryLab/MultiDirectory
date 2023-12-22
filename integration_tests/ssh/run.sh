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
echo "\nperforming ssh conn\n";
sshpass -p password \
  ssh \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  -o ConnectTimeout=30 \
  -o ConnectionAttempts=3 \
  admin@localhost -p 222 "exit 0";
exit $?;
