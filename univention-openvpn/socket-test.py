import socket
import sys
import os
import re

command = 'state'
socket_address = '/etc/openvpn/openvpn-socket'

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(socket_address)

s.sendall(command)

while True:
        data = s.recv(8)
            print 'received: %s' % repr(data)
