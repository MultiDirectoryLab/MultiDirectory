#!/bin/bash

TIME=0
TIMEOUT=10
EXITSTATUS=1

touch .env
> .env

read -p "Enter postgres user [default: user]: " postgres_user
postgres_user=${postgres_user:-user}

read -p "Enter postgres database name [default: md]: " postgres_db
postgres_db=${postgres_db:-md}

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
echo "MD_WEB_ADMIN_IMAGE=ghcr.io/multidirectorylab/multidirectory-web-admin:latest" >> .env
echo "MD_IMAGE=ghcr.io/multidirectorylab/multidirectory:latest" >> .env

# set docker node add label = primary
docker node update --label-add type=primary $HOSTNAME

# generate certs
openssl req -nodes -new -x509 -keyout certs/privkey-md.pem -out certs/cert-md.pem -subj '/C=RU/ST=Moscow/L=Moscow/O=Multidirectory/OU=IT/CN='$domain

sleep 1

#deploy stack md1 

env $(cat .env | grep ^[A-Z] | xargs) docker stack deploy --compose-file docker-compose-swarm.yml md1 

sleep 1

until [[ $TIME -eq $TIMEOUT ]] || [[ $EXITSTATUS -eq 0 ]]; do
        echo $TIME 'check running postgres ..'
        if ( docker stack ps md1 --format "{{.Image}} {{.CurrentState}}" --filter "desired-state=running" --no-trunc | grep Running | grep pgpool ); then
                EXITSTATUS=0
        else
                EXITSTATUS=1
        fi
        sleep 3
        ((TIME++))
done

sleep 1

#RUN migration
docker run --rm -it --network md --env-file .env ghcr.io/multidirectorylab/multidirectory:latest sh -c 'alembic upgrade head' 

echo "done ... visit https://$domain "
