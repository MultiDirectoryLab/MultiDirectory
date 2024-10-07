FROM ubuntu/bind9:latest

RUN chown bind:bind /opt

ENTRYPOINT ["/bin/bash", "-c", "test -f /opt/zone.key && echo 'KEY EXISTS, SKIPPING...' || tsig-keygen zone. > /opt/zone.key && source docker-entrypoint.sh"]