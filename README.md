Introduction
============
This tool was written to address a lot of the issues I was experiencing with ldapsearch
and AD interaction in general.  In particular, this tool addresses the following
problems that I've experienced:

1) Inability to return more than a thousand results from AD.  This tool supports
LDAP record paging and works around other AD bugs to allow an arbitrary numbers 
of records to be retrieved.

2) Inability to use NTLM credentials in an intuitive fashion to authenticate.
You can provide the NETBIOS domain name, username, and password to authenticate to a Windows DC.

3) Inability to precisely control the number of returned records, the speed at 
which they are returned, and the number of records pulled at a time. This tool
allows you to control all of these items, including adding delays between each
paged call. In addition, multiple DC's can be specified for round-robining querying.

4) Inability to return the results in easily digestible forms. This tool currently
supports three formats:

*   plain: A nice, readable, text version of the data with sub-items tabbed in.
*   json: JSON output, with extra white space for easy readability.
*   json_tiny: JSON output with all extra whitespace stripped.

5) Inability to return only attributes you care about.  This tool allows you to
either return all attributes, or return only the ones you want.

6) Inability to have a list of pre-baked, commonly used queries, saved.

Installation
============
    git clone ...
    pip install -r requirements.txt
    
Directions
==========
    # python3 ldapper.py
        usage: ldapper.py [-h] --domain DOMAIN --user USER --password PASSWORD
                          --server SERVER [--basedn BASEDN] --search SEARCH
                          [--maxrecords MAXRECORDS] [--pagesize PAGESIZE]
                          [--delay DELAY] [--format {plain,json,json_tiny}]
                          [--encryption {1,2,3}]
                          [--advanced [ADVANCED [ADVANCED ...]]] [--outfile OUTFILE]
                          [--engine {ldap3,impacket}]
                          [attribute [attribute ...]]

        AD LDAP Command Line Searching that doesn't suck.

        positional arguments:
          attribute             Attributes to return (Defaults to all for custom query.  For canned queries, pass a "*" to get all attributes instead of default ones.)

        optional arguments:
          -h, --help            show this help message and exit
          --domain DOMAIN, -D DOMAIN
                                Domain
          --user USER, -U USER  Username
          --password PASSWORD, -P PASSWORD
                                Password or LM:NTLM formatted hash
          --server SERVER, -S SERVER
                                DC IP or resolvable name
          --basedn BASEDN, -b BASEDN
                                Base DN should typically be "dc=", followed by the long domain name with periods replaced with ",dc=". Will attempt to derive it if not provided from the LDAP server.
          --search SEARCH, -s SEARCH
                                LDAP search string or number indicating custom search from "Custom Searches" list.  Use "-" for read from stdin.
          --maxrecords MAXRECORDS, -m MAXRECORDS
                                Maximum records to return (Default is 100), 0 means all.
          --pagesize PAGESIZE, -p PAGESIZE
                                Number of records to return on each pull (Default is 10).  Should be <= max records.
          --delay DELAY, -d DELAY
                                Millisecond delay between paging requests (Defaults to 0).
          --format {plain,json,json_tiny}, -f {plain,json,json_tiny}
                                Format of output (Default is "plain"), can be: plain, json. json_tiny
          --encryption {1,2,3}, -n {1,2,3}
                                3) Connect to 636 TLS (Default); 2) Connect 389 No TLS, but attempt STARTTLS and fallback as needed (not available with impacket); 1) Connect to 389, Force Plaintext
          --advanced [ADVANCED [ADVANCED ...]], -a [ADVANCED [ADVANCED ...]]
                                Advanced way to pass options for canned searches that prompt for additional input (for multiple prompts, pass argument in the order of prompting)
          --outfile OUTFILE, -o OUTFILE
                                Output File (if specified output will be routed here instead of stdout [Can prevent encoding errors in Windows])
          --engine {ldap3,impacket}, -e {ldap3,impacket}
                                Pick the engine to use (Defaults to "ldap3"). SEE OPSEC NOTES!

        Custom Searches:
                  1) Get all users
                          1.1) Get specific user (You will be prompted for the username)
                  2) Get all groups (and their members)
                          2.1) Get specific group (You will be prompted for the group name)
                  3) Get all printers
                  4) Get all computers
                          4.1) Get specific computer (You will be prompted for the computer name)
                  5) Get Domain/Enterprise Administrators
                  6) Get Domain Trusts
                  7) Search for Unconstrained SPN Delegations (Potential Priv-Esc)
                  8) Search for Accounts where PreAuth is not required. (ASREPROAST)
                  9) Search for User SPNs (KERBEROAST)
                          9.1) Search for specific User SPN (You will be prompted for the User Principle Name)
                 10) Show All LAPS LA Passwords (that you can see)
                         10.1) Search for specific Workstation LAPS Password (You will be prompted for the Workstation Name)
                *11) Search for common plaintext password attributes (UserPassword, UnixUserPassword, unicodePwd, and msSFU30Password)
                 12) Show All Quest Two-Factor Seeds (if you have access)
                 13) Oracle "orclCommonAttribute" SSO password hash
                *14) Oracle "userPassword" SSO password hash
                 15) Get SCCM Servers
                 16) Search for Accounts where password is not required. (PasswordNotRequired)

        Starred items have never been tested in an environment where they could be verified, so please let me know if they work.

Example
=======

For the purposes of these examples, assume the following:

    NETBIOS NAME: EMP
    FULL DOMAIN NAME: EXAMPLE.LOCAL
    DC IPs: 10.0.0.2, 10.0.0.3
    USERNAME: bob
    PASSWORD: password
    
Retrieve all records return only the cn attribute:

    python ldapper.py -D 'EMP' -U 'bob' -P 'password' -S '10.0.0.2,10.0.0.3' -m 0  -s '(cn=*)' cn

Retrieve details about a specific user (will be prompted for username):

    python ldapper.py -D 'EMP' -U 'bob' -P 'password' -S '10.0.0.2,10.0.0.3' -m 0  -s '1.1'
    
Retrieve details about a specific user (pass username so you don't get prompted):

    python ldapper.py -D 'EMP' -U 'bob' -P 'password' -S '10.0.0.2,10.0.0.3' -m 0  -s '1.1' -a 'alice'

Retrieve top 100 user Kerberos SPNs, no more than five at a time, with two seconds between each page request in compact JSON form:

    python ldapper.py -D 'EMP' -U 'bob' -P 'password' -S '10.0.0.2,10.0.0.3' -m 100 -p 5 -d 2000 -f json_tiny -s '(&(objectcategory=user)(serviceprincipalname=*))' serviceprincipalname userprincipalname
    
Manually retrieve all records for printers and show all related attributes:

    python ldapper.py -D 'EMP' -U 'bob' -P 'password' -S '10.0.0.2,10.0.0.3' -m 0  -s '(objectClass=printQueue)'

Search for Unconstrained SPN Delegations with no effort:

    python ldapper.py -D 'EMP' -U 'bob' -P 'password' -S '10.0.0.2,10.0.0.3' -m 0  -s 4


OPSEC Warnings
==============

1) When using the Impacket engine and not supplying a baseDN, the tool will attempt an SMB authentication and connection to the domain controller to acquire the NETBIOS name of the domain, to derive the baseDN.  This behavior may result in a detection in a highly sentive environment.  Either do not use Impacket in such an environment, or always specify the baseDN.

2) Impacket will either do a full LDAPS connection or a fully unencrypted connection.  It cannot use STARTTLS at the moment, so if a plaintext LDAP connection will get caught, either only attempt a full TLS connection or do not use the Impacket engine.

3) Impacket does not provide the most control around how fast records are pulled.  Therefore, the "--delay" option is only partially implemented.  If delaying record pulling is critical, do not use the Impacket engine.

References
==========

Kerberoast: https://adsecurity.org/?p=2293

ASREPRoast: http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/

Unconstrained Delegation Abuse: http://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/

Oracle nonsense: https://blogs.oracle.com/mwilcox/entry/clarifying_ovd-ad_eus_password and http://onlineappsdba.com/index.php/2014/03/03/what-hashing-algorithm-oid-uses-to-store-user-password-ssha-or-md5/

Qwest/Defender/Oneidentity 2nd Factor Token Data: http://support-public.cfm.quest.com/43565_Defender_5.9_AdminGuide.pdf

Common plaintext passwords: https://www.blackhillsinfosec.com/domain-goodness-learned-love-ad-explorer/

Change Log
==========

Version 1.7
-----------

1) Check for accounts that don't need credentials, courtesy of @nyxgeek.

Version 1.6
-----------

1) Added Impacket as an alternative to LDAP3 because LDAP3 doesn't always work (and neither does Impacket).

2) Removed multiple LDAP server selection as this feature is not really needed, and does not really exist in Impacket.

3) Refactored everything.


Version 1.5
-----------

1) Fix minor pagination bug that could cause some records not to be returned.


Version 1.4
-----------

1) Added SCCM Search Feature.

2) Added output file option.

3) Fixed a few format output things.


Version 1.3
-----------

1) Added the ability to take LDAP Query from stdin.

2) Automatically wrap query in brackets if the user did not already do that.

3) Fixed Python 2 Support Bug.


Future Plans
============

If you have some common search enumerations you use, let me know so I can add them to the list.

1) Maybe make an offline search/parser of previously pulled data?

...

Credit and Contact
==================

Written by Shelby Spencer (shellster).  Contact me with bugs or feature requests.
