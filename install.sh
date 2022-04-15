#!/bin/bash 

docker compose create

echo "alias distill='docker compose -f ${PWD}/docker-compose.yml run distill'" >> ${HOME}/.bashrc
