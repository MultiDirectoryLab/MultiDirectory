FROM debian:latest

RUN apt update && apt install curl gnupg apt-transport-https -y
RUN curl -1sLf 'https://dl.cloudsmith.io/public/isc/kea-2-4/setup.deb.sh' | bash
RUN apt update && apt install kea iproute2 systemctl -y

EXPOSE 67/udp

RUN mkdir /var/lib/kea
RUN mkdir /run/kea && chown _kea:_kea /run/kea
RUN touch /var/lib/kea/kea-leases4.csv && chown _kea:_kea /var/lib/kea

COPY .docker/entrypoints/kea_entrypoint.sh /kea_entrypoint.sh
RUN chmod +x /kea_entrypoint.sh

CMD ["/kea_entrypoint.sh"]
