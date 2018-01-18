#!/usr/bin/env python
# requires sqlite3 DB
# Written by TomSqr94 2017

import requests
import sys
import sqlite3
import argparse
import re
import json

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

## IP lookup/analysis functions ------------------------------------------------------------------------------------------
def blacklist(ip):
    result = requests.get('http://api.moocher.io/badip/' + ip)
    if result.status_code == 404 or result.status_code == 400:
        status="IP is Not Blacklisted"
    else:
        status=bcolors.FAIL + "IP is Blacklisted" + bcolors.ENDC
    return status

def passiveTotal(ip):
    url = 'https://api.passivetotal.org/v2/enrichment'
    auth = ('<username>', '<apikey>')
    params = {}
    params['query']=[ip]
    response = requests.get(url, auth=auth, params=params)
    loaded_content = json.loads(response.content)
    return (json.dumps(loaded_content, sort_keys=True, indent=4))
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def geoLocation(ip):
    result = requests.get('http://api.hackertarget.com/geoip/?q=' + ip)
    return result.text

def reverseLookup(ip):
    result = requests.get('http://api.hackertarget.com/reversedns/?q=' + ip)
    return result.text

## Parsing functions ----------------------------------------------------------------------------------------------
def palo(log):
    IP1 = log.split(',')[7]
    IP2 = log.split(',')[8]
    flow = log.split(',')[35]
    action = log.split(',')[30]
    zone1 = log.split(',')[16]
    zone2 = log.split(',')[17]
    threat = log.split(',')[32]
    time = log.split(',')[1]

    # discover threat ID (extracts numbers from threat variable above)
    threatid = re.search(r"\(([A-Za-z0-9_]+)\)", threat)
    cur.execute('SELECT Description FROM palo WHERE id LIKE "%{}%";'.format(threatid.group(1)))
    data = cur.fetchone()

    if 'None' in str(data):
        threatDesc = raw_input("Not in DB. ENTER the Description: ")
        cur.execute('INSERT INTO palo (id, Description) VALUES ("{}","{}");'.format(threatid.group(1), threatDesc))
        con.commit()
        cur.execute('SELECT Description FROM palo WHERE id LIKE "%{}%";'.format(threatid.group(1)))
        data = cur.fetchone()
        print bcolors.WARNING + "[+] Description saved to Palo Alto Table Description" + bcolors.ENDC
    else:
        cur.execute('SELECT Description FROM palo WHERE id LIKE "%{}%";'.format(threatid.group(1)))
        data = cur.fetchone()

    count = raw_input("\nHow many logs have we seen so far?: ")
    print('\nAnalysis on Event:')
    print('Date and Time the incident first started = {}').format(time)
    print('Exploit Name & Threat ID = {}').format(threat)
    print('Number of logs (count) generated for this = {}').format(count)
    print('Information on this Exploit = {}').format(data[0])
    print('''\nIP Addresses involved = {}, located in the {} zone and {}, located in the {} zone.''').format(IP1, zone1, IP2, zone2)
    print('Traffic flow of session = {}').format(flow)
    print('Action taken by the Firewall = {}').format(action)

def forti(log):
    #re.search is obtaining all characters within brackets before it see's next set of characters i.e 'dstip' below...
    IP1 = re.search('srcip=(.*) dstip', log)
    IP2 = re.search('dstip=(.*) sessionid', log)
    action = re.search('action=(.*) proto', log)
    time = re.search('time=(.*) devname', log)
    date = re.search('date=(.*) time', log)
    country = re.search('action=(.*) proto', log)
    attack = re.search('attack=(.*) srcport', log)
    attackid = re.search('attackid=(.*) profile', log)

    cur.execute('SELECT severity FROM fortinet WHERE id LIKE "%{}%";'.format(attackid.group(1)))
    data = cur.fetchone()

    if 'None' in str(data):
        threatSeverity = raw_input("Not in DB. ENTER the Severity: ")
        threatURL = raw_input("Not in DB. Enter the FortiGate URL: ")
        cur.execute('INSERT INTO fortinet (id, severity, url) VALUES ("{}","{}","{}");'.format(attackid.group(1), threatSeverity, threatURL))
        con.commit()
        cur.execute('SELECT severity FROM fortinet WHERE id LIKE "%{}%";'.format(attackid.group(1)))
        data = cur.fetchone()
        print bcolors.WARNING + "[+] Severity saved to Fortinet Table severity" + bcolors.ENDC
        cur.execute('SELECT url FROM fortinet WHERE id LIKE "%{}%";'.format(attackid.group(1)))
        url = cur.fetchone()
        print bcolors.WARNING + "[+] URL saved to Fortinet Table URL" + bcolors.ENDC
    else:
        cur.execute('SELECT severity FROM fortinet WHERE id LIKE "%{}%";'.format(attackid.group(1)))
        data = cur.fetchone()
        cur.execute('SELECT url FROM fortinet WHERE id LIKE "%{}%";'.format(attackid.group(1)))
        url = cur.fetchone()


    count = raw_input("\nHow many logs have we seen so far?: ")
    print('''*''') *50
    print('\nAnalysis on Event:')
    print('Date and Time the incident first started = {} at {}.').format(date.group(1), time.group(1))
    print('Exploit Name & Attack ID = {}').format(attackid.group(1))
    print('Number of logs (count) generated for this = {}').format(count)
    print('Information on this Exploit = This has a severity rating of {}. More information can be found here: {}').format(data[0], url[0])
    print('''\nIP Addresses involved = {} going to {}.''').format(IP1.group(1), IP2.group(1))
    print('Action taken by the Firewall = {}').format(action.group(1))

if __name__ == '__main__':

    # DB connection
    con = sqlite3.connect('/mnt/c/Users/<pathtoDB>/threat.db')
    cur = con.cursor()

    # arguments
    parser = argparse.ArgumentParser('[+] log parser - with added extras')
    #parser.add_argument('-l', '--log', help='log to parse in quotes', required=False)
    parser.add_argument('-pa', '--palo', help='use palo alto parsing', required=False)
    parser.add_argument('-for', '--fortigate', help='use fortigate parsing', required=False)
    # Testing IP background checking
    parser.add_argument('-i', '--ip', help='background check ip', required=False)

    # no arguments = show help
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    if args.palo:
        palo(args.palo)

    if args.fortigate:
        forti(args.fortigate)

    if args.ip:
    #    analyse(args.ip)
        cur.execute('SELECT ip FROM address WHERE ip LIKE "%{}%";'.format(args.ip))
        data = cur.fetchone()
        if 'None' in str(data):
            cur.execute('INSERT INTO address (ip, counter) VALUES ("{}", "{}");'.format(args.ip, '1'))
            print bcolors.WARNING + "[+] IP Address was unknown and has been added to the DB" + bcolors.ENDC
            con.commit()
        else:
            cur.execute('UPDATE address SET counter = counter + 1 WHERE ip = "{}";'.format(args.ip))
            cur.execute('SELECT counter FROM address WHERE ip LIKE "%{}%";'.format(args.ip))
            data = cur.fetchone()
            print bcolors.FAIL + '''[!] I have seen this IP Address {} times.'''.format(data[0])  +bcolors.ENDC
            con.commit()

        print bcolors.WARNING + '\nAnalysis on the suspected bad IP: ' +bcolors.ENDC
        print('Blacklisted = ' + blacklist(args.ip))
        print('Geo-Information = '+ geoLocation(args.ip))
        print('Reverse-Lookup = '+ reverseLookup(args.ip))
        print('\nHow I will action this Event:\n')
        print('PassiveTotal confirmed as malicious = ' + passiveTotal(args.ip))

    # close the db
    con.close()
