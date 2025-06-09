# local development commands
help: ## show help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m\033[0m\n"} /^[$$()% a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

before_pr:
	ruff format . --preview
	ruff check . --preview --fix --unsafe-fixes
	ruff format . --preview
	mypy .
	darglint2 .kerberos/ app

build:  ## build app and manually generate self-signed cert
	make down
	docker compose build

up:  ## run tty container with related services, use with run command
	make down; docker compose up

test:  ## run tests
	docker compose -f docker-compose.test.yml down --remove-orphans
	make down;
	docker compose -f docker-compose.test.yml up --no-log-prefix --attach test --exit-code-from test

run:  ## runs server 386/636 port
	clear;docker exec -it multidirectory bash -c "python ."

launch:  ## run standalone app without tty container
	docker compose down;
	docker compose run bash -c "alembic upgrade head && python ."

downgrade:  ## re-run migration
	docker exec -it multidirectory_api bash -c\
		"alembic downgrade -1; alembic upgrade head;"

down:  ## shutdown services
	docker compose -f docker-compose.test.yml down --remove-orphans
	docker compose down --remove-orphans

# server stage/development commands

stage_gen_cert:  ## generate self-signed cert
	docker compose -f docker-compose.dev.yml run server bash -c "cd /certs; openssl req -nodes -new -x509 -keyout privkey.pem -out cert.pem"

stage_build:  ## build stage server
	docker compose -f docker-compose.dev.yml down
	docker compose -f docker-compose.dev.yml build

stage_up:  ## run app and detach
	make stage_down;
	docker compose -f docker-compose.dev.yml up -d

stage_down:  ## stop all services
	docker compose -f docker-compose.dev.yml down --remove-orphans

stage_update:  ## update service
	make stage_down;
	make stage_build;
	docker compose -f docker-compose.dev.yml pull;
	make stage_up;
	docker exec -it multidirectory-ldap bash -c\
		"alembic downgrade -1; alembic upgrade head; python -m extra.setup_dev"

krb_client_build:  ## build krb client service
	docker build -f integration_tests/kerberos/Dockerfile . -t krbclient:runtime

krb_client:  ## run krb client bash
	docker run --rm --init -it --name krbclient --network multidirectory_default krbclient:runtime bash

migrations:  ## generate migration file
	docker compose run ldap_server alembic revision --autogenerate

migrate:  ## upgrade db
	docker compose run ldap_server alembic upgrade head
