# Copyright (c) 2014-2015, bytemine GmbH
# All rights reserved.
#
# Redistribution and use in source and binary forms, with
# or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import socket
import sys
import os
import json
import datetime
import time
from netaddr import *

def userlist():
    socket_address = '/var/run/management-udp'
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(socket_address)
    except socket.error as msg:
        return []

    s.recv(1024)
    s.sendall('status 3\n')
    data = []
    buf = ''
    while True:
        buf += s.recv(1024)
        lns = buf.split('\r\n')
        if len(lns) > 1:
            buf = lns.pop()
            data += lns
            if lns.count('END'):
                break

    s.close()

    if data and data[0].startswith('TITLE\tOpenVPN 2.4'):
      offset = 1
    else:
      offset = 0

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

        reltime = str(datetime.timedelta(seconds=(int(time.time()) - int(centries[7+offset]))))

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

        result.append({'name': name, 'conn': 1, 'type': conntype, 'realip': realaddress, 'virtips': virtaddresses, 'cons': centries[6+offset], 'conr': reltime, 'recv': centries[4+offset], 'sent': centries[5+offset]})

    return result

def killuser(id):
    socket_address = '/var/run/management-udp'
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(socket_address)
    except socket.error as msg:
        return "socket not found"

    s.recv(1024)
    s.sendall('kill %s\n' % id)
    data = s.recv(1024)

    s.close()

    return data
