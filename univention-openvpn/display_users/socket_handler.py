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

    data = filter(lambda d: d.startswith('CLIENT_LIST\t'), data)

    newdata = []

    for d in data:
        entries = d.split('\t')
        newdata.append({'name': entries[1], 'connected': 'True', 'ips': '%s\n%s' % (entries[2], entries[3]), 'recv': entries[4], 'sent': entries[5], 'cons': entries[6], 'cont': entries[7]})

    return newdata

def killuser(id):
    socket_address = '/var/run/management-udp'
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(socket_address)

    s.recv(1024)
    s.sendall('kill %s\n' % id)
    data = s.recv(1024)

    s.close()
    
    return data
