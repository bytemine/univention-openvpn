#!/usr/bin/env python3

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


import json
import web
import listener
import os
import univention.uldap as ul
from socket_handler import *
from OpenSSL import crypto
from M2Crypto import RSA, BIO
from base64 import b64decode

# turn off debug mode (exceptions as html pages)
web.config.debug = False

class MyApplication(web.application):
    def run(self, port=8080, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, ('127.0.0.1', port))

urls = (
    '/display_users/cmd/(.*)', 'display_users'
)
app = MyApplication(urls, globals())


def connected_users():
    listener.setuid(0)
    lo = ul.getMachineConnection()
    users = lo.search('univentionOpenvpnAccount=1')
    users = map(lambda user: user[1].get('uid', [None])[0].decode('utf8', 'ignore'), users)
    myname = listener.configRegistry['hostname']
    me = lo.search('cn=' + myname)
    listener.unsetuid()
    connected_users = userlist()

    # append not connected users
    for user in users:
        if not any(u['name'] == user for u in connected_users):
            connected_users.append({'name': user, 'connected': 0, 'type': 0, 'realip': '', 'virtips': '', 'cons': '', 'conr': '', 'recv': 0, 'sent': 0})

    for user in connected_users:
        pem = open('/etc/openvpn/o4uCA/users/{}/cert.pem'.format(user['name']))
        cxd = crypto.load_certificate(crypto.FILETYPE_PEM, pem.read())
        pem.close()
        dat = cxd.get_notAfter().decode('ascii')
        user['cert'] = '{}-{}-{}'.format(dat[0:4], dat[4:6], dat[6:8])

    data = {"users": connected_users}

    count = str(len(connected_users))

    query = web.ctx.query
    if query:
        # jsonp
        queries = query.split('&')
        callback = queries[0].split('=')[1]
        return '%s({"draw": 1, "recordsTotal": %s, "recordsFiltered": %s, "data": %s});' % (callback, count, count, json.dumps(data))
    else:
        return '{"data": %s}' % json.dumps(data)

def license_stats():
    listener.setuid(0)
    lo = ul.getMachineConnection()
    users = lo.search('univentionOpenvpnAccount=1')
    myname = listener.configRegistry['hostname']
    me = lo.search('(&(cn=%s)(univentionOpenvpnLicense=*))' % myname)
    try:
        key = me[0][1]['univentionOpenvpnLicense'][0]
    except:
        key = ""
    listener.unsetuid()
    connected_users = userlist()

    c_connected_users = len(connected_users)
    c_users = len(users)
    c_licenced = maxvpnusers(key)
    try:
        l = license(key)
        valid = str(date.fromordinal(l['vdate']))
    except:
        valid = "No valid license on this host"

    info = {"expiration": valid, "connected": c_connected_users, "total": c_users, "licenced": c_licenced}

    count = str(len(connected_users))

    query = web.ctx.query
    if query:
        # jsonp
        queries = query.split('&')
        callback = queries[0].split('=')[1]
        return '%s({"draw": 1, "recordsTotal": %s, "recordsFiltered": %s, "info": %s});' % (callback, count, count, json.dumps(info))
    else:
        return '{"info": %s}' % json.dumps(info)

class display_users:
    def GET(self, name):
        name_pieces = name.split('/')

        if 'connected_users' == name_pieces[0]:
            return connected_users()

        elif 'license_stats' == name_pieces[0]:
            return license_stats()

        elif 'kill_user' == name_pieces[0]:
            try:
                id = name_pieces[1]
                kill_answer = killuser(id)
            except:
                pass
            return ""

        else:
            return ""

pubbio = BIO.MemoryBuffer(b'''
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAN0VVx22Oou8UTDsrug/UnZLiX2UcXeE
GvQ6kWcXBhqvSUl0cVavYL5Su45RXz7CeoImotwUzrVB8JnsIcrPYw8CAwEAAQ==
-----END PUBLIC KEY-----
''')
pub = RSA.load_pub_key_bio(pubbio)
pbs = pub.__len__() / 8

def license(key):
    try:
        enc = b64decode(key)
        raw = ''
        while len(enc) > pbs:
            d, key = (enc[:pbs], enc[pbs:])
            raw = raw + pub.public_decrypt(d, 1)
        if len(enc) != pbs:
            return None		# invalid license
        raw = raw + pub.public_decrypt(enc, 1)
        #
        items = raw.rstrip().split('\n')
        if not items:
            return None		# invalid license
        vdate = int(items.pop(0))
        if date.today().toordinal() > vdate:
            return None		# expired
        l = {'valid': True, 'vdate': vdate} # at least one feature returned
        while items:
            kv = items.pop(0).split('=', 1)
            kv.append(True)
            l[kv[0]] = kv[1]

        return l			# valid license
    except:
        return None			# invalid license

def maxvpnusers(key):
    mnlu = 5
    try:
        return max(int(license(key)['u']), mnlu)
    except:
        return mnlu			# invalid license


if __name__ == "__main__":
    app.run(port=38081)

