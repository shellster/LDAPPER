import datetime
import json
import logging
import queue
import re
import threading
import time

import ldap3
import OpenSSL
from impacket.ldap import ldap

import utilities

"""
WARNING:
If you try to borrow this code, please be aware:
Neither LDAP connector is thread safe!
Impacket library may not be thread safe, more research is needed.
LDAP3 must be instantiate with special parameters to be thread safe (which this library is not doing right now):
https://ldap3.readthedocs.io/en/latest/index.html?highlight=thread#welcome-to-ldap3-s-documentation
"""


class LDAP3Connector:
    basedn = None
    conn = None
    servers = []
    _isconnected = False

    def __init__(self, server, sec_level, domain, username, password, basedn=None, pagesize=10, maxrecord=100, delay=0):
        self.domain = domain
        self.username = username
        self.password = password
        self.basedn = basedn
        self.pagesize = pagesize
        self.maxrecord = maxrecord
        self.delay = delay
        self.sec_level = sec_level
        self.server = None

        # Set Encoding to UTF-8
        ldap3.set_config_parameter("DEFAULT_ENCODING", "utf-8")

        # Shuffle servers if multiple provided to distribute DC load
        
        if sec_level == 3:
            self.server = ldap3.Server(server, port=636, get_info=ldap3.ALL, use_ssl=True)
        else:
            self.server = ldap3.Server(server, port=389, get_info=ldap3.ALL)

        self.conn = ldap3.Connection(
            self.server,
            user="{0}\\{1}".format(self.domain, self.username),
            password=self.password,
            authentication=ldap3.NTLM,
            read_only=True,
        )

        if sec_level == 2:
            try:
                self.conn.start_tls()
            except ldap3.core.exceptions.LDAPStartTLSError:
                pass

        if self.conn.bind():
            if not self.basedn:
                self.basedn = self.conn.server.info.other["defaultNamingContext"][0]

                if not self.basedn:
                    self.basedn = utilities.attempt_to_derive_basedn(
                        server.ip, self.domain, self.username, self.password
                    )

                    if not self.basedn:
                        raise Exception("Unable to derive baseDN")
        else:
            raise Exception("Unable to connect to server")

    def search(self, search, attributes):
        if not attributes:
            attributes = ldap3.ALL_ATTRIBUTES
            
        self.conn.search(
            self.basedn,
            search,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            paged_size=self.pagesize,
        )

        cookie = self.conn.result["controls"]["1.2.840.113556.1.4.319"]["value"][
            "cookie"
        ]

        looptrack = None

        while True:
            for raw_entry in self.conn.entries:
                if looptrack == "":
                    looptrack = raw_entry["cn"]
                elif looptrack == raw_entry["cn"]:
                    # In spite of cookie paging, AD starts looping forever so we detect loop and break
                    cookie = False
                    break

                # Impacket library returns strings for everything, so we do that here to ensure similar behavior to ldap3

                entry = {}
                keys = []
                
                if isinstance(attributes, list):
                    keys = attributes
                else:
                    keys = list(raw_entry.entry_attributes_as_dict)
                
                for key in keys:
                    if key in raw_entry:
                        if len(raw_entry[key]) == 0:
                            entry[key.lower()] = ""
                        elif len(raw_entry[key]) > 1:  # This is a list
                            entry[key.lower()] = [str(x) for x in raw_entry[key]]
                        else:
                            entry[key.lower()] = str(raw_entry[key])

                yield entry

            if len(cookie) == 0:
                break

            self.conn.search(
                self.basedn,
                search,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                paged_size=self.pagesize,
                paged_cookie=cookie,
            )

            cookie = self.conn.result["controls"]["1.2.840.113556.1.4.319"]["value"][
                "cookie"
            ]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.conn.close()
        except Exception:
            pass


class _ImpacketRecordHandler:
    """
    Class exists to basically "curry" the Impacket entry handler callback to pass a per-thread
    queue in the class context. This should make this particular piece thread safe and make
    exceptions less devastating.
    """

    thread_queue = None
    attributes = []

    def __init__(self, thread_queue, attributes, delay):
        self.thread_queue = thread_queue
        self.attributes = attributes
        self.delay = delay

    def handle_record(self, item):
        # Make sure all searched attributes are included in result
        entry = {k: "" for k in self.attributes}

        try:
            for attribute in item["attributes"]:
                name = str(attribute["type"]).lower()
                data = None
                
                if name in ["objectguid"]:
                    # Reformating to match ldap3 format:
                    data = "".join("%02x" % b for b in attribute["vals"][0].asOctets())
                    data = "{{{0}-{1}-{2}-{3}-{4}}}".format(
                        "".join(utilities.splitn(data[0:8], 2)[::-1]),
                        "".join(utilities.splitn(data[8:12], 2)[::-1]),
                        "".join(utilities.splitn(data[12:16], 2)[::-1]),
                        data[16:20],
                        data[20:],
                    )
                elif name == "objectsid":
                    data = utilities.binary_to_sid(attribute["vals"][0])
                else:
                    data = []

                    for item in attribute["vals"]:
                        try:
                            data.append(item.asOctets().decode("utf-8"))
                        except UnicodeDecodeError:
                            data.append("".join("\\x%02x" % b for b in item.asOctets()))

                    
                    for i in range(len(data)):
                        if re.match(r"^\d{14}\.\dZ$", data[i]):
                            data[i] = datetime.datetime.strptime(data[i][:-1], '%Y%m%d%H%M%S.%f').replace(tzinfo=datetime.timezone.utc)
                            data[i] = data[i].strftime('%Y-%m-%d %H:%M:%S+00:00')
                        elif re.search(r"^\d{18,19}$", data[i]):
                            try:
                                data[i] = utilities.ldap_to_unix_timestamp(data[i]).strftime("%Y-%m-%d %H:%M:%S+00:00")
                            except Exception:
                                pass
                    
                    if len(data) == 0:
                        data = ""
                    elif len(data) == 1:
                        data = data[0]

                entry[name] = data

            self.thread_queue.put(entry)
            
            time.sleep(self.delay)
        except TypeError:
            pass
        except Exception:
            logging.exception()
            pass


class ImpacketLDAPConnector:
    basedn = None
    conn = None
    servers = []
    attributes = []
    _isconnected = False

    def __init__(self, server, sec_level, domain, username, password, basedn=None, pagesize=10, maxrecord=100, delay=0):
        self.domain = domain
        self.username = username
        self.password = password
        self.basedn = basedn
        self.pagesize = pagesize
        self.maxrecord = maxrecord
        self.delay = delay
        self.server = None

        if sec_level == 3:
            self.server = "ldaps://{}".format(server)
        else:
            self.server = "ldap://{}".format(server)

        if not self.basedn:
            self.basedn = utilities.attempt_to_derive_basedn(
                server.split("/")[-1], self.domain, self.username, self.password
            )

            if not self.basedn:
                raise Exception("Unable to derive baseDN")

        self.conn = ldap.LDAPConnection(self.server, self.basedn, None)
        self.conn.login(self.username, self.password, self.domain)
            
    def search(self, search, attributes):
        try:
            """
            Impacket either returns all results or calls a callback method for every result.
            We wrap this in a thread and queue so that we can slow it down and bunch our results
            as we want.  We do need to make sure that our processing is fast enough that the LDAP
            connection does not time out.
            """

            sc = ldap.SimplePagedResultsControl(size=self.pagesize)

            thread_queue = queue.Queue(self.pagesize)

            record_handler = _ImpacketRecordHandler(thread_queue, attributes, self.delay)

            self.attributes = attributes

            t = threading.Thread(
                target=self.conn.search,
                kwargs={
                    "searchFilter": search,
                    "attributes": attributes,
                    "sizeLimit": self.maxrecord,
                    "searchControls": [sc],
                    "perRecordCallback": record_handler.handle_record,
                },
            )
            t.daemon = True
            t.start()

            while True:
                try:
                    yield thread_queue.get(block=False)

                except queue.Empty:
                    # If nothing in queue, and the ldap query has died or finished we can exit
                    if not t.is_alive():
                        break

        except ldap.LDAPSearchError as ex:
            raise ex

        except Exception as ex:
            raise ex

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.conn.close()
        except Exception:
            pass