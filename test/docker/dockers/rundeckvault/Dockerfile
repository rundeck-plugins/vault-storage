FROM rundeck/rundeck:SNAPSHOT

USER root

RUN apt-get update && \
    apt-get -y install apt-transport-https curl && \
    apt-get -y install jq software-properties-common


# add cli tool debian repo
RUN curl -s https://packagecloud.io/install/repositories/pagerduty/rundeck/script.deb.sh | os=any dist=any bash
RUN apt-get -y update
RUN apt-get -y install rundeck-cli

# RUNDECK
## RUNDECK setup env

## Install Java
RUN \
 add-apt-repository -y ppa:openjdk-r/ppa  && \
 apt-get update && \
 apt-get install -y openjdk-11-jdk

ENV USERNAME=rundeck \
    USER=rundeck \
    HOME=/home/rundeck \
    LOGNAME=$USERNAME \
    TERM=xterm-256color

#RUN update-alternatives  --list java
#RUN update-alternatives --set java /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java

WORKDIR $HOME
USER rundeck

COPY --chown=rundeck:root remco /etc/remco

# Copy files.
RUN sudo mkdir -p /tests
COPY tests /tests
RUN sudo chmod -R a+x /tests/*

RUN mkdir -p $HOME/vault-tests
COPY tests $HOME/vault-tests
RUN sudo chown -R rundeck:root $HOME/vault-tests
RUN sudo chmod -R a+x $HOME/vault-tests/*

VOLUME $HOME/vault-tests

COPY --chown=rundeck:root ./plugins ./libext


