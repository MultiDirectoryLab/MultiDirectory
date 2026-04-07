#!/bin/bash
touch .env

get_env_var() {
    local var_name="$1"
    grep -q "^${var_name}=" .env
}

add_env_var() {
    local var_name="$1"
    local var_value="$2"
    echo "${var_name}=${var_value}" >> .env
}

cp /etc/resolv.conf resolv.conf

# DEFAULT_NAMESERVER
if ! get_env_var "DEFAULT_NAMESERVER"; then
    while true; do
        read -p "Enter host server ip address: " server_ip
        if [ -n "$server_ip" ]; then
            add_env_var "DEFAULT_NAMESERVER" "$server_ip"
            break
        fi
        echo "Host server ip address required."
    done
fi

# POSTGRES_USER
if ! get_env_var "POSTGRES_USER"; then
    read -p "Enter postgres user [default: user]: " postgres_user
    postgres_user=${postgres_user:-user}
    add_env_var "POSTGRES_USER" "$postgres_user"
fi

# POSTGRES_DB
if ! get_env_var "POSTGRES_DB"; then
    read -p "Enter postgres database name [default: postgres]: " postgres_db
    postgres_db=${postgres_db:-postgres}
    add_env_var "POSTGRES_DB" "$postgres_db"
fi

# POSTGRES_HOST
if ! get_env_var "POSTGRES_HOST"; then
    read -p "Enter postgres host (leave it default if you are using default database) [default: postgres]: " postgres_host
    postgres_host=${postgres_host:-postgres}
    add_env_var "POSTGRES_HOST" "$postgres_host"
fi

# POSTGRES_PASSWORD
if ! get_env_var "POSTGRES_PASSWORD"; then
    read -p "Enter postgres password [default: autogenerate]: " postgres_password
    postgres_password=${postgres_password:-$(openssl rand -hex 16)}
    add_env_var "POSTGRES_PASSWORD" "$postgres_password"
fi

# DOMAIN
if ! get_env_var "DOMAIN"; then
    while true; do
        read -p "Enter interface domain [required]: " domain
        if [ -n "$domain" ]; then
            add_env_var "DOMAIN" "$domain"
            break
        fi
        echo "Interface domain required."
    done
fi

# Add domain to /etc/hosts
domain="$(. ./.env 2>/dev/null; printf '%s' "$DOMAIN")"
host="127.0.0.1 ${domain}"
if ! grep -qFx "$host" /etc/hosts 2>/dev/null; then
    printf '%s\n' "$host" | sudo tee -a /etc/hosts >/dev/null
fi

# SECRET_KEY
if ! get_env_var "SECRET_KEY"; then
    secret_key=$(openssl rand -hex 32)
    add_env_var "SECRET_KEY" "$secret_key"
fi

# CERTS_DIR
if [ ! -d "certs" ]; then
    mkdir -p "certs"
    echo "Created directory: certs"
else
    echo "Directory already exists: certs"
fi

# DNS_API_KEY
if ! get_env_var "PDNS_API_KEY"; then
    dns_api_key=$(openssl rand -hex 16)
    sed -i "s|supersecretapikey|${dns_api_key}|g" recursor.conf
    sed -i "s|supersecretapikey|${dns_api_key}|g" pdns.conf
    add_env_var "PDNS_API_KEY" "$dns_api_key"
fi

# DNSDIST_API_KEY
if ! get_env_var "PDNS_DIST_KEY"; then
    dnsdist_key=$(openssl rand -base64 32)
    sed -i "s|supersecretapikey|${dnsdist_key}|g" dnsdist.conf
    add_env_var "PDNS_DIST_KEY" "$dnsdist_key"
fi

# HOST_MACHINE_NAME
if ! get_env_var "HOST_MACHINE_NAME"; then
    host_machine_name=$(hostname)
    add_env_var "HOST_MACHINE_NAME" "$host_machine_name"
fi
