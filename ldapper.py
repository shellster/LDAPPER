#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Version 1.6

import argparse
import json
import os
import re
import sys
import yaml

import colorama

from queries import custom_search
from utilities import escape_ldap
from ldap_connector import LDAP3Connector
from ldap_connector import ImpacketLDAPConnector

#Python 2 message
if sys.version_info[0] == 2:
    print("Python 2 is no longer supported.  Please upgrade.")
    exit(-1)

colorama.init()

def get_epilog(menu, parent=''):
    epilog = ''
    
    if parent == '':
        epilog = 'Custom Searches:\n'
        
    for i, entry in enumerate(menu):
        number = str(i + 1).rjust(2) if parent == '' else parent + str(i + 1)
        
        epilog += '%s%s%s) %s\n' % (((parent.count('.') + 1) * '\t'), '*' if 'untested' in entry else ' ', number, entry['help'])     

        if 'children' in entry and len(entry['children']):
            epilog += get_epilog(entry['children'], number + '.')
    
    if parent == '':
        epilog += '\nStarred items have never been tested in an environment where they could be verified, so please let me know if they work.'
        
    return epilog

def get_canned_search(menu, args):
    return_data = {}
    
    if re.match('^[0-9.]*[0-9]$', args.search):
        try:
            if args.search.count('.') > 0:
                option = [int(x) - 1 for x in args.search.split('.')]
                
                for i,entry in enumerate(option):
                    if i == (len(option) - 1):
                        return_data = menu[entry]
                    else:
                        menu = menu[entry]['children']
                
            else:
                return_data = menu[int(args.search) - 1]
        except:
            pass
        
        if return_data != {}:
            if 'options' in return_data and len(return_data['options']) > 0:
                answers = []
                
                for i,option in enumerate(return_data['options']):
                    if args.advanced and len(args.advanced) > i and re.match(option['regex'], args.advanced[i]):
                        answers.append(escape_ldap(args.advanced[i]))
                        continue
                    
                    while True:
                        answer = input('%s: ' % option['question'])
                        
                        if re.match(option['regex'], answer):
                            answers.append(escape_ldap(answer))
                            break

                return_data['ldap'] = return_data['ldap'].format(*answers)
                
    return return_data

class OverrideParser(argparse.ArgumentParser):
    def error(self, message):
        if "following arguments are required" in message:
            self.print_help()
            sys.exit(-1)
        else:
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(-1)

parser = OverrideParser(description="AD LDAP Command Line Searching that doesn't suck.", epilog=get_epilog(custom_search), formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--domain', '-D', help='Domain', required=True)
parser.add_argument('--user', '-U', help='Username', required=True)
parser.add_argument('--password', '-P', help='Password or LM:NTLM formatted hash', required=True)
parser.add_argument('--server', '-S', help='DC IP or resolvable name', required=True)
parser.add_argument('--basedn', '-b', help='Base DN should typically be "dc=", followed by the long domain name with periods replaced with ",dc=". Will attempt to derive it if not provided from the LDAP server.', default='')
parser.add_argument('--search', '-s', help='LDAP search string or number indicating custom search from "Custom Searches" list.  Use "-" for read from stdin.', required=True)
parser.add_argument('--maxrecords', '-m', help='Maximum records to return (Default is 100), 0 means all.', default=100, type=int)
parser.add_argument('--pagesize', '-p', help='Number of records to return on each pull (Default is 10).  Should be <= max records.', default=10, type=int)
parser.add_argument('--delay', '-d', help='Millisecond delay between paging requests (Defaults to 0).', default=0, type=int)
parser.add_argument('--format', '-f', help='Format of output (Default is "plain"), can be: plain, json. json_tiny', default='plain', choices=['plain', 'json', 'json_tiny'])
parser.add_argument('--encryption', '-n', help="3) Connect to 636 TLS (Default); 2) Connect 389 No TLS, but attempt STARTTLS and fallback as needed (not available with impacket); 1) Connect to 389, Force Plaintext", default=3, type=int, choices=[1, 2, 3]) 
parser.add_argument('--advanced', '-a', help="Advanced way to pass options for canned searches that prompt for additional input (for multiple prompts, pass argument in the order of prompting)", nargs='*') 
parser.add_argument('--outfile', '-o', help="Output File (if specified output will be routed here instead of stdout [Can prevent encoding errors in Windows])", default=None, type=str) 
parser.add_argument("--engine", "-e", help='Pick the engine to use (Defaults to "ldap3"). SEE OPSEC NOTES!', default='ldap3', choices=["ldap3", "impacket"])
parser.add_argument('attributes', metavar='attribute', nargs='*', help='Attributes to return (Defaults to all for custom query.  For canned queries, pass a "*" to get all attributes instead of default ones.)')

args = parser.parse_args()  

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

if args.encryption == 2 and args.engine == "impacket":
    print(f'{colorama.Fore.RED}Error: Cannot section --encryption to 2 when using --engine of "impacket"{colorama.Style.RESET_ALL}', file=sys.stderr)
    parser.print_help()
    sys.exit(2)

if args.search == '-':
    if os.isatty(0):
        parser.print_help()
        sys.exit(3)
    
    args.search = sys.stdin.read()

if args.delay < 0:
    print(f'{colorama.Fore.RED}Error: "delay" must be 0 or greater{colorama.Style.RESET_ALL}', file=sys.stderr)
    parser.print_help()
    sys.exit(4)

pagesize = 10 if args.pagesize <= 0 else args.pagesize
maxrecords = 100 if args.maxrecords < 0 else args.maxrecords
pagesize = min(maxrecords, pagesize) if maxrecords != 0 else pagesize

Engine = None

if args.engine == "ldap3":
    Engine = LDAP3Connector
else:
    Engine = ImpacketLDAPConnector

if re.match('[0-9.]*[0-9]', args.search):
    canned_option = get_canned_search(custom_search, args)
    
    if canned_option == {}:
        parser.print_help()
        print(f'{colorama.Fore.RED}Error: You attempted to select a canned search option that is not valid.{colorama.Style.RESET_ALL}', file=sys.stderr)
        exit(5)
        
    args.search = canned_option['ldap']
       
    if 'filter' in canned_option and len(canned_option['filter']) > 1 and args.attributes == []:
        args.attributes = canned_option['filter']
else:
    if args.search[0] != '(' and args.search[-1] != ')':
        args.search = f'({args.search})'

if len(args.attributes) > 0:
    if len(args.attributes) == 1 and args.attributes[0].strip() == '*':
        args.attributes = []
    else:
        args.attributes.append('cn')
        args.attributes = set(map(str.lower, args.attributes))

if args.outfile:
    try:
        out = open(args.outfile, 'wb')
    except Exception:
        print(f'{colorama.Fore.RED}Error: Unable to open or create specified output file.{colorama.Style.RESET_ALL}', file=sys.stderr)
        exit(6)
else:
    out = sys.stdout.buffer

try:
    records_found = False
    
    with Engine(args.server, args.encryption, args.domain, args.user, args.password, args.basedn, pagesize, maxrecords, args.delay) as engine:
        for i, record in enumerate(engine.search(args.search, args.attributes)):
            records_found = True
            
            if args.format in ['json', 'json_tiny']:
                if i == 0:
                    out.write(b"[")
                    
                    if args.format == 'json':
                        out.write(b"\n")
                else:
                    out.write(b",")
                    
                    if args.format == "json":
                        out.write(b"\n")

            if args.format == 'json':
                out.write(json.dumps(record, indent=4, sort_keys=True).encode("utf-8") + b"\n")
            elif args.format == 'json_tiny':
                out.write(json.dumps(record, ensure_ascii=False).encode("utf-8"))
            else:
                out.write(record['cn'].encode('utf-8') + b'\n')
                
                for key in record:
                    if key != "cn":
                        if isinstance(record[key], list):
                            out.write((f"   {key}:\n        " + "\n        ".join(record[key]) + "\n").encode("utf-8"))
                        else:
                            out.write(f"   {key}: {record[key]}\n".encode("utf-8"))       

                out.write(b"\n")

            if maxrecords > 0 and i >= maxrecords:
                break

        if not records_found:
            print(f'{colorama.Fore.YELLOW}NOTICE: No results were returned for your query{colorama.Style.RESET_ALL}', file=sys.stderr)
        elif args.format in ['json', 'json_tiny']:
            out.write(b"]\n")
                    
        out.flush()
        
        if maxrecords > 0 and i >= maxrecords:       
            print(f'{colorama.Fore.YELLOW}NOTICE: Search returned at least as many records as maxrecords argument allowed.  You may be missing results.{colorama.Style.RESET_ALL}', file=sys.stderr)

        if args.outfile:
            try:
                out.close()
            except Exception:
                pass

except Exception as ex:
    import logging
    logging.exception("")
    print(f'{colorama.Fore.RED}Error: {ex}{colorama.Style.RESET_ALL}', file=sys.stderr)