#!/bin/bash
# clean volumes after "docker stack rm md1" for clean initial setup
docker volume ls --format={{.Name}} | grep md1 | xargs docker volume rm
