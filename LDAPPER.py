#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Version 1.4

from __future__ import print_function
import ldap3, argparse, sys, os, yaml, re, json, time, colorama
import datetime

#Python 2 message
if sys.version_info[0] == 2:
    print("Python 2 is no longer supported.  Please upgrade.")
    exit(-1)

colorama.init()

def ldap_time_stamp(dt):
    MagicNumber = 116444736000000000
    return str(int(time.mktime(dt.timetuple()) *10000000) + MagicNumber)

custom_search = [
    {
     'help': 'Get all users',
     'ldap': '(objectcategory=user)', 
     'filter': ['cn', 'description', 'mail', 'memberOf', 'sAMAccountName'],
     'children': [
        {
         'help': 'Get specific user (You will be prompted for the username)',
         'ldap': '(&(objectclass=user)(|(CN={0})(sAMAccountName={0})))', 
         'filter': ['cn', 'description', 'mail', 'memberOf', 'sAMAccountName'],
         'options': [
            {
                'question': 'Username to search for',
                'regex': '.+'
            }
          ]
        }
     ]
    },
    {
     'help': 'Get all groups (and their members)',
     'ldap': '(objectclass=group)', 
     'filter': ['member', 'displayName'],
     'children': [
        {
         'help': 'Get specific group (You will be prompted for the group name)',
         'ldap': '(&(objectclass=group)(|(CN={0})(sAMAccountName={0})))', 
         'filter': ['member', 'displayName'],
         'options': [
            {
                'question': 'Group name to search for',
                'regex': '.+'
            }
          ]
        }
     ]
    },
    {
     'help': 'Get all printers',
     'ldap': '(objectCategory=printeQueue)',
    },
    {
     'help': 'Get all computers',
     'ldap': '(&(objectCategory=computer)(lastLogonTimestamp>=' + ldap_time_stamp(datetime.datetime.today() - datetime.timedelta(days=90)) + '))', 
     'filter': ['dNSHostName', 'description', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'servicePrincipalName', 'lastLogonTimestamp'],
     'children': [
        {
         'help': 'Get specific computer (You will be prompted for the computer name)',
         'ldap': '(&(objectCategory=computer)(lastLogonTimestamp>=' + ldap_time_stamp(datetime.datetime.today() - datetime.timedelta(days=90)) + ')(|(CN={0})(dNSHostName={0})))', 
         'filter': ['dNSHostName', 'description', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'servicePrincipalName', 'lastLogonTimestamp'],
         'options': [
            {
                'question': 'Computer name to search for',
                'regex': '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
            }
          ]
        }
     ]
    },
    {
     'help': 'Get Domain/Enterprise Administrators',
     'ldap': '(&(objectCategory=group)(|(CN=Domain Admins)(CN=Administrators)(CN=Enterprise Admins)))',
     'filter': ['member']
    },
    {
     'help': 'Get Domain Trusts',
     'ldap': '(objectClass=trustedDomain)'
    },
    {
     'help': 'Search for Unconstrained SPN Delegations (Potential Priv-Esc)',
     'ldap': '(userAccountControl:1.2.840.113556.1.4.803:=524288)',
     'filter': ['cn', 'servicePrincipalName']
    },
    {
     'help': 'Search for Accounts where PreAuth is not required. (ASREPROAST)',
     'ldap': '(userAccountControl:1.2.840.113556.1.4.803:=4194304)',
     'filter': ['cn', 'distinguishedName']
    },
    {
     'help': 'Search for User SPNs (KERBEROAST)',
     'ldap': '(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))',
     'filter': ['userPrincipalName', 'servicePrincipalName'],
     'children': [
        {
         'help': 'Search for specific User SPN (You will be prompted for the User Principle Name)',
         'ldap': '(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer))(userPrincipalName={0}))', 
         'filter': ['userPrincipalName', 'servicePrincipalName'],
         'options': [
            {
                'question': 'User Principle Name to search for',
                'regex': '.+'
            }
          ]
        }
     ]     
    },
    {
     'help': 'Show All LAPS LA Passwords (that you can see)',
     'ldap': '(ms-Mcs-AdmPwd=*)',
     'filter': ['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'dNSHostName'],
     'children': [
        {
         'help': 'Search for specific Workstation LAPS Password (You will be prompted for the Workstation Name)',
         'ldap': '(&(|(CN={0})(dNSHostName={0})))', 
         'filter': ['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'dNSHostName'],
         'options': [
            {
                'question': 'Workstation to search for',
                'regex': '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
            }
          ]
        }
     ]
    },
    {
     'help': 'Search for common plaintext password attributes (UserPassword, UnixUserPassword, unicodePwd, and msSFU30Password)',
     'ldap': '(|(UserPassword=*)(UnixUserPassword=*)(unicodePwd=*)(msSFU30Password=*))',
     'untested': True
    },
    {
     'help': 'Show All Quest Two-Factor Seeds (if you have access)',
     'ldap': '(defender-tokenData=*)'
    }, 
    {
     'help': 'Oracle "orclCommonAttribute" SSO password hash',
     'ldap': '(&(objectcategory=user)(orclCommonAttribute=*))',
     'filter': ['cn', 'memberOf', 'sAMAccountName', 'orclCommonAttribute']
    },
    {
     'help': 'Oracle "userPassword" SSO password hash',
     'ldap': '(&(objectcategory=user)(userPassword=*))',
     'filter': ['cn', 'memberOf', 'sAMAccountName', 'userPassword'],
     'untested': True
    },
    {
     'help': 'Get SCCM Servers',
     'ldap': '(objectClass=mSSMSManagementPoint)',
     'filter': ['cn', 'mSSMSMPName', 'mSSMSCapabilities', 'mSSMSSiteCode', 'mSSMSVersion'],
    }
]

def escape_ldap(term):
    term = re.sub(r'([,#+><;"=])', r'\\\1', term.replace('\\', '\\\\'))
    
    m1 = re.search('^([ ]+)', term)
    m2 = re.search('([ ]+)$', term)
    
    term = term.strip()
    
    if m1 and m1.group(1):
        term = (len(m1.group(1)) * '\\ ') + term
        
    if m2 and m2.group(1):
        term = term + (len(m2.group(1)) * '\\ ')
    
    return term
    
def get_epilog(menu=custom_search, parent=''):
    global custom_search
    
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

def get_canned_search(args):
    global custom_search
    
    return_data = {}
    
    if re.match('^[0-9.]*[0-9]$', args.search):
        try:
            if args.search.count('.') > 0:
                option = [int(x) - 1 for x in args.search.split('.')]
                level = custom_search
                
                for i,entry in enumerate(option):
                    if i == (len(option) - 1):
                        return_data = level[entry]
                    else:
                        level = level[entry]['children']
                
            else:
                return_data = custom_search[int(args.search) - 1]
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

parser = OverrideParser(description="AD LDAP Command Line Searching that doesn't suck.", epilog=get_epilog(), formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--domain', '-D', help='Domain', required=True)
parser.add_argument('--user', '-U', help='Username', required=True)
parser.add_argument('--password', '-P', help='Password or LM:NTLM formatted hash', required=True)
parser.add_argument('--server', '-S', help='DC IP or resolvable name (can be comma-delimited list for round-robin)', required=True)
parser.add_argument('--basedn', '-b', help='Base DN should typically be "dc=", followed by the long domain name with periods replaced with ",dc=". Will attempt to derive it if not provided from the LDAP server.', default='')
parser.add_argument('--search', '-s', help='LDAP search string or number indicating custom search from "Custom Searches" list.  Use "-" for read from stdin.', required=True)
parser.add_argument('--maxrecords', '-m', help='Maximum records to return (Default is 100), 0 means all.', default=100, type=int)
parser.add_argument('--pagesize', '-p', help='Number of records to return on each pull (Default is 10).  Should be <= max records.', default=10, type=int)
parser.add_argument('--delay', '-d', help='Millisecond delay between paging requests (Defaults to 0).', default=0, type=int)
parser.add_argument('--format', '-f', help='Format of output (Default is "plain"), can be: plain, json. json_tiny', default='plain', choices=['plain', 'json', 'json_tiny'])
parser.add_argument('--encryption', '-n', help="3) Connect to 636 TLS (Default); 2) Connect 389 No TLS, but attempt STARTTLS and fallback as needed; 1) Connect to 389, Force Plaintext", default=3, type=int, choices=[1, 2, 3]) 
parser.add_argument('--advanced', '-a', help="Advanced way to pass options for canned searches that prompt for additional input (for multiple prompts, pass argument in the order of prompting)", nargs='*') 
parser.add_argument('--outfile', '-o', help="Output File (if specified output will be routed here instead of stdout [Can prevent encoding errors in Windows])", default=None, type=str) 
parser.add_argument('attributes', metavar='attribute', nargs='*', help='Attributes to return (Defaults to all for custom query.  For canned queries, pass a "*" to get all attributes instead of default ones.)')

args = parser.parse_args()  

if len(sys.argv) == 1:
    parser.print_help()
    exit(-1)

if args.search == '-':
    if os.isatty(0):
        parser.print_help()
        exit(-1)
    
    args.search = sys.stdin.read()

ldap3.set_config_parameter('DEFAULT_ENCODING', 'utf-8')
    
servers = [server.strip() for server in args.server.split(',')]

server_pool = ldap3.ServerPool(None, ldap3.ROUND_ROBIN, active=True, exhaust=True)

if args.encryption == 3:
    for server in servers:
        server_pool.add(ldap3.Server(server.strip(), port=636, get_info=ldap3.ALL, use_ssl=True))
else:
    for server in servers:
        server_pool.add(ldap3.Server(server.strip(), port=389, get_info=ldap3.ALL))

if re.match('[0-9.]*[0-9]', args.search):
    canned_option = get_canned_search(args)
    
    if canned_option == {}:
        parser.print_help()
        print((colorama.Fore.RED + '\n%s\n' + colorama.Style.RESET_ALL) % 'Error: You attempted to select a canned search option that is not valid.', file=sys.stderr)
        exit(-1)
        
    args.search = canned_option['ldap']
       
    if 'filter' in canned_option and len(canned_option['filter']) > 1 and args.attributes == []:
        args.attributes = canned_option['filter']
else:
    if args.search[0] != '(' and args.search[-1] != ')':
        args.search = '(%s)' % args.search

if len(args.attributes) > 0:
    if len(args.attributes) == 1 and args.attributes[0].strip() == '*':
        args.attributes = []
    else:
        args.attributes.append('cn')
        args.attributes = set(map(str.lower, args.attributes))

if args.outfile:
    try:
        out = open(args.outfile, 'wb')
    except:
        print("Unable to open or create specified output file.")
        exit(-1)
else:
    out = sys.stdout.buffer

with ldap3.Connection(server_pool, user=r'%s\%s' % (args.domain, args.user), password=args.password, authentication=ldap3.NTLM, read_only=True) as conn:
    if args.encryption == 2:
        try:
            conn.start_tls()
        except:
            print((colorama.Fore.YELLOW + '\n%s\n' + colorama.Style.RESET_ALL) %'NOTICE: Unable to use STARTTLS', file=sys.stderr)
 
    if not conn.bind():
        print((colorama.Fore.RED + '\n%s\n' + colorama.Style.RESET_ALL) %'ERROR: An error occurred while attempting to connect to the server(s).  If the ip(s) are correct, your credentials are likely invald', file=sys.stderr)
        exit(-1)
    
    if len(args.basedn) == 0:
        try:
            args.basedn = vars(conn.server.info)['other']['defaultNamingContext'][0]
        
            if len(args.basedn) == 0:
                raise Exception('Bad BaseDN')
        except:
            print((colorama.Fore.RED + '\n%s\n' + colorama.Style.RESET_ALL) % 'Error: You failed to provide a Base DN and we were unable to derive it.', file=sys.stderr)
            exit(-1)
    
    i = 0
    
    pagesize = 10 if args.pagesize <= 0 else args.pagesize
    maxrecords = 100 if args.maxrecords < 0 else args.maxrecords
    pagesize = min(maxrecords, pagesize) if maxrecords != 0 else pagesize

    cookie = True
    looptrack = ""
    
    conn.search(args.basedn, args.search, search_scope=ldap3.SUBTREE, attributes=[ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES], paged_size=pagesize)
    
    while cookie:
        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        
        for entry in conn.entries:
            printable_entry =json.loads(entry.entry_to_json())
            
            if len(args.attributes) > 0:
                attributes = {x.lower():x for x in printable_entry['attributes']}
                printable_entry['attributes'] = {attributes[x]:printable_entry['attributes'][attributes[x]] for x in args.attributes if x in attributes}
            
            if looptrack == "":
                looptrack = printable_entry['dn']
            elif looptrack == printable_entry['dn']:
                #in spite of cookie paging, AD starts looping forever
                cookie = False
                break
            
            i += 1
            
            if args.format in ['json', 'json_tiny']:
                if i == 1:
                    out.write(b"[")
                    if args.format == 'json':
                        out.write(b"\n")
                else:
                    out.write(b",")

            if args.format == 'json':
                out.write(json.dumps(printable_entry, indent=4, sort_keys=True).encode("utf-8") + b"\n")
            elif args.format == 'json_tiny':
                out.write(json.dumps(printable_entry, ensure_ascii=False).encode("utf-8"))
            else:
                out.write(printable_entry['dn'].encode('utf-8') + b'\n')

                if 'attributes' in printable_entry:
                    #ugly hacks abound to deal with objects containig unserializable data and to to pretty print the attributes
                    try:
                        out.write(re.sub(r'^', r'  ', re.sub(r'^(\s*)-', r'\1 ', yaml.safe_dump(yaml.safe_load(json.dumps(printable_entry['attributes'], ensure_ascii=False)), allow_unicode=True, default_flow_style=False),  flags=re.M),  flags=re.M).encode('utf-8') + b'\n')
                    except:
                        print('Character Encoding Error.')            

            if maxrecords > 0 and i >= maxrecords:
                print((colorama.Fore.YELLOW + '\n%s\n' + colorama.Style.RESET_ALL) % 'NOTICE: Search returned at least as many records as maxrecords argument allowed.  You may be missing results.', file=sys.stderr)
                break
        
        if args.delay > 0:
            time.sleep(args.delay / 1000)
        
        if maxrecords != 0:
            pagesize = min((maxrecords - i), pagesize)
        
        conn.search(args.basedn, args.search, search_scope=ldap3.SUBTREE, attributes=[ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES], paged_size=pagesize, paged_cookie=cookie)
        
        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']

if i == 0:
    print((colorama.Fore.YELLOW + '\n%s\n' + colorama.Style.RESET_ALL) % 'NOTICE: No results were returned for your query', file=sys.stderr)
elif args.format in ['json', 'json_tiny']:
    out.write(b"]")

if args.outfile:
    try:
        out.close()
    except:
        pass