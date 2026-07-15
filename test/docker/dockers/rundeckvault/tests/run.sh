#!/bin/bash

set -e
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
export PATH=/usr/lib/jvm/java-11-openjdk-amd64/jre/bin:$PATH

TEST_DIR=$1
TEST_SCRIPT=${2:-/tests/run-tests.sh}
TEST_PROJECT=${3:-testproj1}

: ${TEST_DIR?"Dir required"}
: ${TEST_SCRIPT?"Script required"}
: ${TEST_PROJECT?"Project required"}



echo "run_tests with $TEST_DIR and $TEST_SCRIPT for project $TEST_PROJECT"

# define env vars used by rd tool
export RD_USER=admin
export RD_PASSWORD=admin
export RD_URL="http://$RUNDECK_NODE:4440"
export RD_COLOR=0
export RD_OPTS="-Dfile.encoding=utf-8"
export RD_HTTP_TIMEOUT=45

echo "starting tests"

#creating project
rd projects create -p $TEST_PROJECT

set +e
chmod -w "$TEST_SCRIPT"
chmod +x "$TEST_SCRIPT"
sync

$TEST_SCRIPT \
	--rdeck-base "$HOME" \
	--rundeck-project "$TEST_PROJECT" \
	--rundeck-user "$USERNAME" \
    --test-dir "$TEST_DIR"
EC=$?

echo "tests finished with $EC"


exit $EC