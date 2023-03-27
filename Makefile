build:
	docker-compose build

up:
	docker-compose down; docker-compose up

run:
	clear;docker exec -it multidirectory bash -c "python ."

recreate:
	docker exec -it multidirectory bash -c\
		"alembic downgrade -1; alembic upgrade head; PYTHONPATH=/app python extra/setup_dev.py"
