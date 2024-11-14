#!/bin/bash
touch .env
> .env

read -p "Enter postgres user [default: user]: " postgres_user
postgres_user=${postgres_user:-user}

read -p "Enter postgres database name [default: postgres]: " postgres_db
postgres_db=${postgres_db:-postgres}

read -p "Enter postgres host (leave it default if you are using default database) [default: postgres]: " postgres_host
postgres_host=${postgres_host:-postgres}


read -p "Enter postgres password [default: autogenerate]: " postgres_password
postgres_password=${postgres_password:-$(openssl rand -hex 16)}


read -p "Enter interface domain [required]: " domain
if [ -z "$domain" ]; then echo "interface domain required" && exit 1; fi

secret_key=$(openssl rand -hex 32)

echo "POSTGRES_HOST="$postgres_host >> .env
echo "POSTGRES_USER="$postgres_user >> .env
echo "POSTGRES_DB="$postgres_db >> .env
echo "POSTGRES_PASSWORD="$postgres_password >> .env
echo "DOMAIN="$domain >> .env
echo "SECRET_KEY="$secret_key >> .env
