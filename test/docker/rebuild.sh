#!/bin/bash
set -e

bash clean.sh || echo 'clean had errors..continuing'

. common.sh


for composefile in $(ls -1 docker-compose-*.yml); do
  docker compose -f $composefile build
  docker compose -f $composefile up
done


