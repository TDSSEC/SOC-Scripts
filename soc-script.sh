#!/bin/bash

##############required###resorces###############
##https://github.com/IntellexApps/blcheck#######
##https://github.com/doomedraven/VirusTotalApi##
################################################

CK="\033[30m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PINK="\033[35m"
CYAN="\033[36m"
WHITE="\033[37m"
NORMAL="\033[0;39m"

blcheck=$(whereis blcheck | cut -d " " -f2)

if [ "$(id -u)" = "0" ]; then
  printf "$RED This script should not be ran as root \n $NORMAL" 1>&2
  exit 1
fi

printf "$GREEN your external IP is: \n $NORMAL"
curl -s http://whatismijnip.nl |cut -d " " -f 5

sleep 3

IP=$1
if  [[ -z "$IP" ]]; then
  read -p "Target ? :  " IP
fi

PT=$2
if  [[ -z "$PT" ]]; then
  read -p "Passive Total key, e.g user@example.com:key ? :  " PT
fi

printf "$GREEN ####NSLOOKUP RESULTS##### \n $NORMAL"
/usr/bin/nslookup $IP
sleep 1

printf "$GREEN ####WHOIS RESULTS#### \n $NORMAL"
/usr/bin/whois $IP
sleep 1

printf "$GREEN ####REVERSE DNS RESULTS#### \n $NORMAL"
/usr/bin/host $IP
sleep 1

printf "$GREEN ####NMAP RESULTS#### \n $NORMAL"
/usr/bin/nmap --host-timeout 10 -Pn $IP
sleep 1

printf "$GREEN ####HTTP HEADDER#### \n $NORMAL"
/usr/bin/curl --progress -m 5 -kI http://$IP
sleep 1

printf "$GREEN ####BLACK LIST RESULTS#### \n $NORMAL"
$blcheck $IP
sleep 2

printf "$GREEN ####VIRUSTOTAL RESULTS#### \n $NORMAL"
python /home/jthorpe/VirusTotalApi/vt/vt.py -u $IP # --static really annoying
sleep 3
python /home/jthorpe/VirusTotalApi/vt/vt.py -ur $IP
sleep 2

printf "$GREEN ####PASSIVE TOTAL RESULTS#### \n $NORMAL"
curl --progress -X GET "https://api.passivetotal.org/v2/enrichment?query=$IP" \
    -u $PT | python -mjson.tool
sleep 2
