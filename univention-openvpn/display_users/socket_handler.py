import socket
import sys
import os
import json

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

    for c in cl:
        centries = c.split('\t')
        name = centries[1]
        realaddress = centries[2]

        virtaddresses = ""

        for r in rt:
            rentries = r.split('\t')
            rname = rentries[2]
            rrealaddress = rentries[3]
            
            if name == rname and realaddress == rrealaddress:
                virtaddresses += rentries[1] + "\n"

        result.append({'name': name, 'connected': 'True', 'realip': realaddress, 'virtips': virtaddresses, 'recv': centries[4], 'sent': centries[5], 'cons': centries[6], 'cont': centries[7]})

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
