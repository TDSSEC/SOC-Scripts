#!/usr/bin/env python
# Written by TomSQR on 11/07/2017
# requires sqllite db

import requests
import sys
import sqlite3
import argparse
import re

def windows(log):
    #log = raw_input('\nEnter RAW Log text: ')
    #formatted = re.findall(r"[\w']+", log)
    IP1 = re.search('srcip=(.*) dstip', log)
    IP2 = re.search('dstip=(.*) sessionid', log)
    action = re.search('action=(.*) proto', log)
    time = re.search('time=(.*) devname', log)
    date = re.search('date=(.*) time', log)
    country = re.search('action=(.*) proto', log)
    attack = re.search('attack=(.*) srcport', log)
    attackid = re.search('attackid=(.*) profile', log)
    # discover threat ID (extracts numbers from threat variable above)
    #threatid = re.search(r"\(([A-Za-z0-9_]+)\)", attackid)

    cur.execute('SELECT severity FROM fortinet WHERE id LIKE "%{}%";'.format(attackid.group(1)))
    data = cur.fetchone()

    if 'None' in str(data):
        threatSeverity = raw_input("Not in DB. ENTER the Severity: ")
        threatURL = raw_input("Not in DB. Enter the FortiGate URL: ")
        cur.execute('INSERT INTO fortinet (id, severity, url) VALUES ("{}","{}","{}");'.format(attackid.group(1), threatSeverity, threatURL))
        con.commit()
        cur.execute('SELECT severity FROM fortinet WHERE id LIKE "%{}%";'.format(attackid.group(1)))
        data = cur.fetchone()
    else:
        cur.execute('SELECT severity FROM fortinet WHERE id LIKE "%{}%";'.format(attackid.group(1)))
        sev = cur.fetchone()
        cur.execute('SELECT url FROM fortinet WHERE id LIKE "%{}%";'.format(attackid.group(1)))
        data = cur.fetchone()
        print data
    count = raw_input("\nHow many logs have we seen so far?: ")
    print('''*''') *50
    print('\nAnalysis on Event:')
    print('Date and Time the incident first started = {} at {}.').format(date.group(1), time.group(1))
    print('Exploit Name & Attack ID = {}').format(attackid.group(1))
    print('Number of logs (count) generated for this = {}').format(count)
    print('Information on this Exploit = This has a severity rating of {}. More information can be found here: {}').format(sev[0], data[0])
    print('''\nIP Addresses involved = {} going to {}.''').format(IP1.group(1), IP2.group(1))
    #print('Traffic flow of session = {}').format(flow)
    print('Action taken by the Firewall = {}').format(action.group(1))
    print('\nAnalysis on the suspected bad IP:')
    print('Blacklisted = ')
    print('PassiveTotal confirmed as malicious = ')
    print('Geo-Information = ')
    print('Reverse-Lookup = ')
    print('\nHow I will action this Event:\n')


if __name__ == '__main__':

    # DB connection
    con = sqlite3.connect('/mnt/c/Users/<pathtoDB>/threat.db')
    cur = con.cursor()

    # arguments
    parser = argparse.ArgumentParser('[+] log parser - with added extras')
    parser.add_argument('-l', '--log', help='log to parse in quotes', metavar='"LOG"', required=True)
    parser.add_argument('-for', '--fortigate', help='use FortiGate parsing', required=False, action='store_true')

    # no arguments = show help
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    if args.fortigate:
        forti(args.log)
    #elif args.forti:
        #fortifunction(args.log)
    else:
        print('[!] parser type required')
        sys.exit(1)

    # close the db
    con.close()
