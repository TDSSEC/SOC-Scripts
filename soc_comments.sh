#!/bin/bash

out=working_file

if [[ -f "$out" ]]; then
    echo $out exists - removing
    rm $out
fi

out2=pt_working

if [[ -f "$out2" ]]; then
    echo $out2 exists - removing
    rm $out2
fi

echo ""

log=$1
if  [[ -z "$log" ]]; then
    read -p "raw log file: " log
fi

echo $log >> working_file

IP1=$(cat working_file | cut -d "," -f 8)
IP2=$(cat working_file | cut -d "," -f 9)
port1=$(cat working_file | cut -d "," -f 26)
port2=$(cat working_file | cut -d "," -f 27)
Zone1=$(cat working_file | cut -d "," -f 17)
Zone2=$(cat working_file | cut -d "," -f 18)
action=$(cat working_file | cut -d "," -f 31)
detected=$(cat working_file | cut -d "," -f 33)
flow=$(cat working_file | cut -d "," -f 36)
date=$(cat working_file | cut -d "," -f 7)
location=$(cat working_file | cut -d "," -f 40)

echo ""
echo "--------------------"
echo "| $flow |"
echo "--------------------"

blcheck=$(whereis blcheck | cut -d " " -f2)

query=$2
if  [[ -z "$query" ]]; then
    echo ""
    echo $IP1
    echo $IP2
    echo ""
    read -p "query what ip ?: " query
fi

PT=$3
if  [[ -z "$PT" ]]; then
  read -p "Passive Total key, e.g user@example.com:key ? :  " PT
fi

blresult=$($blcheck $query | grep Blacklisted)

if [[ "$blresult" == *"0"* ]]; then
 blresulted=" $query is not blacklisted."
else
 blresulted=" $query is blacklisted."
fi

echo $blresulted

resolve=$(host $query | cut -d " " -f 5)

if [[ "$resolve" == *"NXDOMAIN"* ]]; then
  resolved=" $resolve could not be resolved "
else
  resolved=" resolves to $resolve"
fi

curl --progress -X GET "https://api.passivetotal.org/v2/enrichment?query=$query" \
    -u $PT | python -m json.tool >>pt_working

while true; do
  read -p "Do you want to do another ?: " yn
    case $yn in
      [Yy]* )
      echo "" ;
      echo $IP1 ;
      echo $IP2 ;
      echo "" ;
      read -p "query what ip ?: " query2 ;

      blresult2=$($blcheck $query2 | grep Blacklisted) ;

      if [[ "$blresult2" == *"0"* ]]; then
       blresulted2=" $query2 is not blacklisted." ;
      else
       blresulted2=" $query2 is blacklisted." ;
      fi

      echo $blresulted2 ;

      resolve2=$(host $query2 | cut -d " " -f 5) ;

      if [[ "$resolve2" == *"NXDOMAIN"* ]]; then
        resolved2=" $resolve2 could not be resolved " ;
      else
        resolved2=" resolves to $resolve2" ;
      fi

      curl --progress -X GET "https://api.passivetotal.org/v2/enrichment?query=$query2" \
          -u $PT | python -m json.tool >>pt_working ;;

      [Nn]* ) break ;;
      * ) echo "Please answer yes or no.";;
    esac
done

echo ""
echo "----------------------------------
The IPs involved were $IP1 and $IP2,
with the corresponding zones being $Zone1 and $Zone2.
The traffic-flow for this was $flow.
The action by the Firewall was to $action.
$blresulted.
$blresulted2.
$query $resolved.
$query2 $resolved2.
Passive Total research shows the following:
$(cat pt_working )
"
