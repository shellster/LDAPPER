import datetime
import re
import socket
import time

from impacket.smbconnection import SMBConnection

_MagicNumber = 116444736000000000


def unix_to_ldap_timestamp(dt):
    return str(int(time.mktime(dt.timetuple()) * 10000000) + _MagicNumber)

def ldap_to_unix_timestamp(dt):
    dt = int(dt)
    
    if dt == 9223372036854775807:
        return datetime.date.max.replace()
    
    dt -= _MagicNumber
    dt /= 10000000
    return datetime.datetime.utcfromtimestamp(dt)

def binary_to_sid(buf):
    version = int(buf[0])
    subAuthorityCount = int(buf[1])
    identifierAuthority = int.from_bytes(buf[2:8], "little")
    sidString = f"S-{version}-{subAuthorityCount}"
    
    for i in range(8, len(buf), 4):
        number = int.from_bytes(buf[i:i+4], "little")
        sidString += f"-{number}"
            
    return sidString

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


def splitn(s, n):
    return list(map("".join, zip(*[iter(s)] * n)))


def attempt_to_derive_basedn(dc, domain, username, password):
    # Attempt to derive baseDN via SMB resolution using impacket:
    try:
        s = SMBConnection(domain, dc)
        s.login(username, password)
        s.logoff()

        domain_long = s.getServerDNSDomainName()

        return "dc=" + ",dc=".join(domain_long.split("."))
    except Exception:
        pass

    # Attempt to derive baseDN via DNS resolution (domains are often dcname.domain.corp):
    try:
        results = socket.gethostbyaddr(dc)

        for result in results:
            result = result.split(".")
            if len(result) > 2:
                return "dc=" + ",dc=".join(result[1:])
    except Exception:
        pass

    return None