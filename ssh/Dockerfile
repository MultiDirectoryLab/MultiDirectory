FROM debian:latest

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get -y install libnss-ldapd libpam-ldapd openssh-sftp-server openssh-server
RUN apt-get update && apt-get -y install rsyslog
RUN mkdir -p /var/run/sshd
ADD init.sh /init.sh
RUN chmod u+x /init.sh

EXPOSE 22

CMD /init.sh
