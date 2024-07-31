# MultiDirectory
Ready to deploy ldap and http server.

Configuration repository for
1. [MultiDirecory](https://github.com/MultiDirectoryLab/MultiDirectory) - ldap and JSON web API server

2. [MultiDirectory-Web-Admin](https://github.com/MultiDirectoryLab/MultiDirectory-Web-Admin) - web interface for API

All services are running through [traefik](https://doc.traefik.io/traefik/providers/docker/), using [postgres](https://www.postgresql.org/) v15+ as database, other DBMS are incompatible.

## Installation

1. Install [docker](https://docs.docker.com/engine/install/) and [docker compose](https://docs.docker.com/compose/install/)

2. Register and associate domain with your server IP, for e.g. `multidirectory.example.com` -> `255.255.255.255`

3. Create multidirectory folder:
```sh
mkdir MultiDirectory; cd MultiDirectory;
```

4. Generate config `.env` file with:

### For Linux:
```sh
bash <(curl https://raw.githubusercontent.com/MultiDirectoryLab/MultiDirectory/main/.package/setup.sh);
curl -O https://raw.githubusercontent.com/MultiDirectoryLab/MultiDirectory/main/.package/docker-compose.yml;
curl https://raw.githubusercontent.com/MultiDirectoryLab/MultiDirectory/main/LICENSE
```

Then follow .env file fill instructions.
After generating `.env` file, services are ready to deploy

### For Windows:
```sh
curl -O https://raw.githubusercontent.com/MultiDirectoryLab/MultiDirectory/main/.package/setup.bat;
curl -O https://raw.githubusercontent.com/MultiDirectoryLab/MultiDirectory/main/.package/docker-compose.yml;
curl https://raw.githubusercontent.com/MultiDirectoryLab/MultiDirectory/main/LICENSE
```

Run `./setup.bat`, then follow instructions.
After generating `.env` file, services are ready to deploy

5. Start services with command:

Compose v2:
```sh
docker compose pull; docker compose up -d
```

## Update services:

Run following command:

Compose v2:
```sh
docker compose down; docker compose pull; docker compose up -d
```

To update config files (docker-compose.yml and setup.*), please, redownload repository, using step 4.


## Development

To access docs and redoc of API, request `/api/redoc` and `/api/docs` url from your API domain.

## Custom database

To deploy MultiDirectory with custom postgres database, you can setup following variables in `.env` file:

    POSTGRES_HOST
    POSTGRES_USER
    POSTGRES_PASSWORD
    POSTGRES_DB

In that case you may need to remove `postgres` service from `docker-compose.yml` file.

Please note that only PostgreSQL DBMS version 15 or later is compatible with the MultiDirectory app.
