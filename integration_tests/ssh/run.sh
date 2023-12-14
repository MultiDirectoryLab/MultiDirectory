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
echo "performing ssh conn"
sshpass -p password ssh admin@localhost -p 222
echo $?
