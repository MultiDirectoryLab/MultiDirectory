#! /bin/bash

unset -v IP
unset -v STATE
unset -v DEVICE

while getopts i:s:d: opt; do
        case $opt in
                i) IP=$OPTARG ;;
		s) STATE=$OPTARG ;;
		d) DEVICE=$OPTARG ;;
                *)
                        echo 'Error in command line parsing' >&2
                        exit 1
        esac
done

shift "$(( OPTIND - 1 ))"

if [ -z "$IP" ] || [ -z "$STATE" ] || [ -z "$DEVICE" ]; then
        echo 'Missing -i or -s or -d. Example: -i 192.168.1.200 -s MASTER -d eth0 ' >&2
        exit 1
fi

# Determine OS platform
UNAME=$(uname | tr "[:upper:]" "[:lower:]")
# If Linux, try to determine specific distribution
if [ "$UNAME" == "linux" ]; then
    # If available, use LSB to identify distribution
    if [ -f /etc/lsb-release -o -d /etc/lsb-release.d ]; then
        export DISTRO=$(lsb_release -i | cut -d: -f2 | sed s/'^\t'//)
    # Otherwise, use release info file
    else
        export DISTRO=$(ls -d /etc/[A-Za-z]*[_-][rv]e[lr]* | grep -v "lsb" | cut -d'/' -f3 | cut -d'-' -f1 | cut -d'_' -f1)
    fi
fi
# For everything else (or if above failed), just use generic identifier
[ "$DISTRO" == "" ] && export DISTRO=$UNAME
unset UNAME

if [ $DISTRO == "Ubuntu" ]; then
    apt-get update
    apt install -y keepalived
else
    yum update
    yum install -y keepalived ipvsadm
fi  

echo "Adding keepalived user for running checks"
adduser --disabled-password --gecos "" keepalived


echo "
global_defs {
    enable_script_security
    script_user keepalived
}
vrrp_script chk_docker {
    script \"pgrep dockerd\" #Had to use this on debian distros
    #script "pidof dockerd"
    interval 1
    weight 20
}
vrrp_script chk_traefik {
    script \"pgrep traefik\" #Had to use this on debian distros
    #script "pidof traefik"
    interval 30
    weight 10
}
vrrp_script keepalived_check {
      script \"nc -zvw1 localhost 443\"
      interval 5
      timeout 5
      rise 3
      fall 3
}
vrrp_instance SWARM {
  state $STATE
  interface $DEVICE
  virtual_router_id 51
  priority 100
  advert_int 1
  authentication {
        auth_type PASS
        auth_pass qwerty
  }
  virtual_ipaddress {
    $IP/24
  }
  track_script {
    chk_docker
    chk_traefik
    keepalived_check
  }
}
" >  /etc/keepalived/keepalived.conf

lsmod | grep -P '^ip_vs\s' || (echo "modprobe ip_vs" >> /etc/modules && modprobe ip_vs)
systemctl enable keepalived
systemctl start keepalived
