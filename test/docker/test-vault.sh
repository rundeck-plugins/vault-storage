#!/bin/bash

export DOCKER_COMPOSE_SPEC=docker-compose-vault.yml
export TEST_DIR=/home/rundeck/vault-tests/vault
export TEST_SCRIPT=/home/rundeck/vault-tests/run-tests.sh
export VAULT_TOKEN=thisisatoken123.


# clean up docker env
docker compose -f $DOCKER_COMPOSE_SPEC down --volumes --remove-orphans

set -e

# re-build docker env
docker compose -f $DOCKER_COMPOSE_SPEC build


# run docker
docker compose -f $DOCKER_COMPOSE_SPEC up -d

sleep 60

docker compose -f $DOCKER_COMPOSE_SPEC logs

echo "up completed, running tests..."

set +e

echo $DOCKER_COMPOSE_SPEC
echo $TEST_DIR
echo $TEST_SCRIPT

docker compose -f $DOCKER_COMPOSE_SPEC exec -T --user rundeck rundeck1 bash \
	vault-tests/run.sh $TEST_DIR $TEST_SCRIPT vaulttest

EC=$?
echo "run_tests.sh finished with: $EC"


# Stop and clean all
#docker-compose -f $DOCKER_COMPOSE_SPEC down --volumes --remove-orphans

exit $EC
