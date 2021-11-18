ARG IMAGE
FROM ${IMAGE}

USER root

RUN apt-get update && \
    apt-get -y install apt-transport-https curl && \
    apt-get -y install jq

# add cli tool debian repo
RUN curl -s https://packagecloud.io/install/repositories/pagerduty/rundeck/script.deb.sh | os=any dist=any bash
RUN apt-get -y update
RUN apt-get -y install rundeck-cli

# RUNDECK
## RUNDECK setup env

ENV USERNAME=rundeck \
    USER=rundeck \
    HOME=/home/rundeck \
    LOGNAME=$USERNAME \
    TERM=xterm-256color


WORKDIR $HOME
USER rundeck

COPY --chown=rundeck:root remco /etc/remco
COPY --chown=rundeck:root logback.groovy /home/rundeck/server/config

COPY --chown=rundeck:root ./plugins ./libext

VOLUME ["/home/rundeck/server/data"]

EXPOSE 4440
ENTRYPOINT [ "docker-lib/entry.sh" ]
