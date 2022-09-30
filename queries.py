import datetime

from utilities import unix_to_ldap_timestamp

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
     'ldap': '(objectCategory=printQueue)',
    },
    {
     'help': 'Get all computers',
     'ldap': '(&(objectCategory=computer)(lastLogonTimestamp>=' + unix_to_ldap_timestamp(datetime.datetime.today() - datetime.timedelta(days=90)) + '))', 
     'filter': ['dNSHostName', 'description', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'servicePrincipalName', 'lastLogonTimestamp'],
     'children': [
        {
         'help': 'Get specific computer (You will be prompted for the computer name)',
         'ldap': '(&(objectCategory=computer)(lastLogonTimestamp>=' + unix_to_ldap_timestamp(datetime.datetime.today() - datetime.timedelta(days=90)) + ')(|(CN={0})(dNSHostName={0})))', 
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
