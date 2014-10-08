import socket
import sys
import os

def parent():
    while True:
        data = s.recv(8)
        print 'recv: %s' % repr(data)

def child():
    while True:
        cmd = raw_input('> ')
        s.sendall(cmd)

def forker():
    newpid = os.fork()
    if newpid == 0:
        child()
    else:
        parent()

socket_address = '/etc/openvpn/openvpn-socket'
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(socket_address)

forker()
