# SOC-Scripts
Scripts used to parse syslog from different FW Vendors

## parser.py 
This takes the syslog from either a Windows DC (evt2sylog), Palo Alto Firewall or FortiGate Firewall and parses it into quick and easy to read text.
There is an option to write the output into a SQLite DB in order to instantly pull information for specific threats and to see if you have spotted the same IP address before.

Arguments:
'-l', '--log' + syslog to parse
'-pa', '--palo' = set it to use palo alto parsing
'-for', '--fortigate' = set it to use fortigate parsing
'-i', '--ip' + <IP Address> = background check IP. This scans through blacklist checkers, passive total, virus total etc. Requires API keys!
  
