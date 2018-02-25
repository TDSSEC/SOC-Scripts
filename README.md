# SOC-Scripts
This is a python script I have written to perform 2 functions:  
**1) IP Address Analysis:**  
```
Black List Checker - Returns true or false
VirusTotal Check - Is the IP or site known to be running anything malicious?
PassiveTotal Check - Further analysis on IP history, resolutions and flags for malware
IP Resolution - Display what the IP currently resolves to
WHOIS data - WHOIS data...
Geo-IP data - Geo-locational data
Private DB - Has this IP been seen before by yourself? If so, displays how many times!
```
**2) Syslog parsing to clearly understand what the syslog message is saying:**  
```
Palo Alto Firewall Syslog - Versions 7+
FortiGate Firewall Syslog
```

## parser.py 
This takes the syslog from either a Palo Alto Firewall or FortiGate Firewall and parses it into quick and easy to read text.
There is an option to write the output into a SQLite DB in order to instantly pull information for specific threats and to see if you have spotted the same IP address before.

**Usage:**
`python ./parser.py -pa -i <IP>`

Arguments:
```
'-l', '--log' + syslog to parse
'-pa', '--palo' = set it to use palo alto parsing
'-for', '--fortigate' = set it to use fortigate parsing
'-i', '--ip' + <IP Address> = background check IP. This scans through blacklist checkers, passive total, virus total etc. Requires API keys!
```
  
## threat.db
This is the Database that stores useful information about IP addresses.

It also has tables to store Palo Alto threat IDs and there descriptions. 

### Updates/Issues
- Currently working on FortiGate Database improvements  
- Windows logs need to be updated
