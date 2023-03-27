# local development commands

build:
	docker-compose down
	docker-compose build
	docker-compose run server bash -c\
		"cd /certs;\
		openssl genrsa -out key.pem 2048;\
		openssl genrsa -aes256 -out key.pem 2048;\
		openssl req -new -key key.pem -out signreq.csr;\
		openssl x509 -req -days 365 -in signreq.csr -signkey key.pem -out certificate.pem;\
		openssl x509 -text -noout -in certificate.pem"

up:
	docker-compose down; docker-compose up

run:
	clear;docker exec -it multidirectory bash -c "python ."

launch:
	docker-compose down; docker-compose run bash -c "python ."

recreate:
	docker exec -it multidirectory bash -c\
		"alembic downgrade -1; alembic upgrade head; PYTHONPATH=/app python extra/setup_dev.py"

# server development commands

stage_build:
	docker-compose -f docker-compose.dev.yml down
	docker-compose -f docker-compose.dev.yml build
	docker-compose -f docker-compose.dev.yml run server bash -c\
		"cd /certs;\
		openssl genrsa -out key.pem 2048;\
		openssl genrsa -aes256 -out key.pem 2048;\
		openssl req -new -key key.pem -out signreq.csr;\
		openssl x509 -req -days 365 -in signreq.csr -signkey key.pem -out certificate.pem;\
		openssl x509 -text -noout -in certificate.pem"

stage_up:
	docker-compose -f docker-compose.dev.yml up -d

stage_down:
	docker-compose -f docker-compose.dev.yml down || true

stage_update:
	git pull;
	make stage_down;
	make stage_build;
	make stage_up;
	docker exec -it multidirectory-ldap bash -c\
		"alembic downgrade -1; alembic upgrade head; PYTHONPATH=/app python extra/setup_dev.py"
