FROM ubuntu/bind9:latest

COPY .dns/dns-entrypoint.sh /
RUN chmod 777 /dns-entrypoint.sh

ENTRYPOINT ["/dns-entrypoint.sh"]