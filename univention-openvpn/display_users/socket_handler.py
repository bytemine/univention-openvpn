import socket
import sys
import os
import json
from netaddr import *

def userlist():
    socket_address = '/var/run/management-udp'
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(socket_address)

    s.recv(1024)
    s.sendall('status 3\n')
    data = s.recv(1024).split('\n')

    s.close()

    cl = filter(lambda d: d.startswith('CLIENT_LIST\t'), data)
    rt = filter(lambda d: d.startswith('ROUTING_TABLE\t'), data)

    result = []

    # iterate over client list
    for c in cl:
        centries = c.split('\t')
        name = centries[1]
        realaddress = centries[2]

        conntype = 0
        virtaddresses = ""

        # iterate over routing table to get all virtual addresses for each client
        for r in rt:
            rentries = r.split('\t')
            rvirtaddress = rentries[1]
            rname = rentries[2]
            rrealaddress = rentries[3]

            if name == rname and realaddress == rrealaddress:
                if IPAddress(rvirtaddress).version == 4:
                    conntype |= 1
                elif IPAddress(rvirtaddress).version == 6:
                    conntype |= 2
                virtaddresses += rvirtaddress + "\n"

        result.append({'name': name, 'conn': 1, 'type': conntype, 'realip': realaddress, 'virtips': virtaddresses, 'cons': centries[6], 'cont': centries[7], 'recv': centries[4], 'sent': centries[5]})

    return result

def killuser(id):
    socket_address = '/var/run/management-udp'
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(socket_address)

    s.recv(1024)
    s.sendall('kill %s\n' % id)
    data = s.recv(1024)

    s.close()

    return data
