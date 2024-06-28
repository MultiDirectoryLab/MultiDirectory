# MultiDirectory-CI
Ready to deploy ldap and http server.

Configuration repository for
1. [MultiDirecory](https://github.com/MultifactorLab/MultiDirectory) - ldap and JSON web API server

2. [MultiDirectory-Web-Admin](https://github.com/MultifactorLab/MultiDirectory-Web-Admin) - web interface for API

All services are running through [traefik](https://doc.traefik.io/traefik/providers/docker/), using [postgres](https://www.postgresql.org/) as database, other DBMS are incompatible.

## Installation HA mode docker swarm (linux only)

1. Install [docker](https://docs.docker.com/engine/install/) and [docker compose](https://docs.docker.com/compose/install/)

2. Register and assosiate domain with your server IP, for e.g. `multidirectory.example.com` -> `255.255.255.255`

3. 
``` sh 
git clone https://github.com/MultiDirectoryLab/MultiDirectory-CI.git
cd MultiDirecory-CI
```

4. Generate config `.env` file with:

    On primary postgres node run `./setup-swarm.sh` for Unix systems then follow instructions.
    Script will generate `.env` file, services will be deployed automatically. 
    To check services running: 
    ``` docker service ls ```

5. Login https://<YOUR_DOMAIN>  

## Update services:

Run following command:

Compose v2:
```sh
env $(cat .env | grep ^[A-Z] | xargs) docker stack deploy --compose-file docker-compose-swarm.yml md1 
```

To update config files (docker-compose.yml and setup.*), please, redownload repository, using step 3.


## Development

To access docs and redoc of API, request `/api/redoc` and `/api/docs` url from your API domain.

## Custom database

To deploy MultiDirectory with custom postgres database, you can setup following variables in `.env` file:

    POSTGRES_HOST
    POSTGRES_USER
    POSTGRES_PASSWORD
    POSTGRES_DB

Please, note, other DBMS, rather than PostgreSQL, are incompatiple with MultiDirectory app.

In that case you may need to remove `postgres` service from `docker-compose.yml` file.
