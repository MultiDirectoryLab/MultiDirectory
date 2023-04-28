# local development commands
help: ## show help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m\033[0m\n"} /^[$$()% a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

build:  ## build app and manually generate self-signed cert
	docker-compose down
	docker-compose build

cert:  ## create self-signed cert
	docker-compose run server bash -c "cd /certs; openssl req -nodes -new -x509 -keyout privkey.pem -out cert.pem"

up:  ## run tty container with related services, use with run command
	docker-compose down; docker-compose up

run:  ## runs server 386/636 port
	clear;docker exec -it multidirectory bash -c "python ."

launch:  ## run standalone app without tty container
	docker-compose down;
	docker-compose run bash -c "alembic upgrade head && python ."

recreate:  ## re-run migration
	docker exec -it multidirectory bash -c\
		"alembic downgrade -1; alembic upgrade head; PYTHONPATH=/app python extra/setup_dev.py"

deploy:  ## deploy ready-to use
	make build
	make recreate
	make launch

down:
	docker-compose down

# server stage/development commands

stage_gen_cert:  ## generate self-signed cert
	docker-compose -f docker-compose.dev.yml run server bash -c "cd /certs; openssl req -nodes -new -x509 -keyout privkey.pem -out cert.pem"

stage_build:  ## build stage server
	docker-compose -f docker-compose.dev.yml down
	docker-compose -f docker-compose.dev.yml build

stage_up:  ## run app and detach
	make stage_down;
	docker-compose -f docker-compose.dev.yml up -d

stage_down:  ## stop all services
	docker-compose -f docker-compose.dev.yml down || true

stage_update:  ## update service
	git pull;
	make stage_down;
	make stage_build;
	make stage_up;
	docker exec -it multidirectory-ldap bash -c\
		"alembic downgrade -1; alembic upgrade head; PYTHONPATH=/app python extra/setup_dev.py"
