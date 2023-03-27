# local development commands

build:
	docker-compose build

up:
	docker-compose down; docker-compose up

run:
	clear;docker exec -it multidirectory bash -c "python ."

recreate:
	docker exec -it multidirectory bash -c\
		"alembic downgrade -1; alembic upgrade head; PYTHONPATH=/app python extra/setup_dev.py"

# server development commands

stage_up:
	docker-compose -f docker-compose.dev.yml up -d

stage_down:
	docker-compose -f docker-compose.dev.yml down

stage_update:
	git pull;
	make_down;
	docker-compose -f docker-compose.dev.yml up -d --build;
	docker exec -it multidirectory-ldap bash -c\
		"alembic downgrade -1; alembic upgrade head; PYTHONPATH=/app python extra/setup_dev.py"
