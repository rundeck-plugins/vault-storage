#!/bin/bash
#/ trigger local ci test run

set -euo pipefail
IFS=$'\n\t'
readonly ARGS=("$@")
DOCKER_DIR=$PWD/test/docker

rd_get_version(){
    local CUR_VERSION=$(grep rundeck.version.number= `pwd`/version.properties | cut -d= -f 2)

    echo "${CUR_VERSION}"
}


rd_get_plugin_version(){
    local CUR_VERSION=$(grep plugin.version.number= `pwd`/version.properties | cut -d= -f 2)
    echo "${CUR_VERSION}"
}

usage() {
      grep '^#/' <"$0" | cut -c4- # prints the #/ lines above as usage info
}
die(){
    echo >&2 "$@" ; exit 2
}

check_args(){
	if [ ${#ARGS[@]} -gt 0 ] ; then
    	DOCKER_DIR=$1
	fi
}
copy_jar(){
	local FARGS=("$@")
	local DIR=${FARGS[0]}
	local buildJar
	buildJar=$(find "$PWD/build/libs" -maxdepth 1 -name "$(basename "$PWD")-*.jar" \
		-not -name "*-sources.jar" -not -name "*-javadoc.jar" | sort | tail -1)
	test -n "$buildJar" && test -f "$buildJar" || die "Jar file not found in $PWD/build/libs"
	local JAR=$(basename "$buildJar")
	mkdir -p $DIR
	cp "$buildJar" $DIR/dockers/rundeckvault/plugins
	echo $DIR/dockers/rundeckvault/plugins/$JAR
}
run_tests(){
	local FARGS=("$@")
	local DIR=${FARGS[0]}

	cd $DIR

	bash $DIR/test-vault.sh
	bash $DIR/test-existing-vault.sh
    bash $DIR/test-existing-vault1.x.sh
}
run_docker_test(){
	local FARGS=("$@")
	local DIR=${FARGS[0]}
	local launcherJar
	launcherJar=$( copy_jar $DIR ) || die "Failed to copy jar"
	echo "Testing: $launcherJar"
	run_tests $DIR
}


main() {
    check_args
    run_docker_test $DOCKER_DIR
}
main
