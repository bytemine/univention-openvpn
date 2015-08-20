#!/usr/bin/env python

import json
import web
import listener
import os
import univention.uldap as ul
from socket_handler import *
from datetime import date
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


pubbio = BIO.MemoryBuffer('''
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
      return None               # invalid license
    raw = raw + pub.public_decrypt(enc, 1)
    items = raw.rstrip().split('\n')
    if not items:
      return None               # invalid license
    vdate = int(items.pop(0))
    if date.today().toordinal() > vdate:
      return None               # expired
    l = {'valid': True, 'vdate': vdate} # at least one feature returned
    while items:
      kv = items.pop(0).split('=', 1)
      kv.append(True)
      l[kv[0]] = kv[1]
    return l                    # valid license
  except:
    return None                 # invalid license

def maxvpnusers(key):
  mnlu = 5
  try:
    return max(int(license(key)['u']), mnlu)
  except:
    return mnlu

def connected_users(name):
    listener.setuid(0)
    lo = ul.getBackupConnection()
    users = lo.search('univentionOpenvpnAccount=1')
    users = map(lambda user: "%s.openvpn" % user[1].get('uid', [None])[0], users)
    myname = listener.baseConfig['hostname']
    me = lo.search('cn=%s' % myname)
    key = me[0][1]['univentionOpenvpnLicense'][0]
    listener.unsetuid()
    connected_users = userlist()

    c_connected_users = len(connected_users)
    c_users = len(users)
    c_licenced = maxvpnusers(key)

    # append not connected users
    for user in users:
        if not any(u['name'] == user for u in connected_users):
            connected_users.append({'name': user, 'connected': 0, 'type': 0, 'realip': '', 'virtips': '', 'cons': '', 'conr': '', 'recv': 0, 'sent': 0})

    for user in connected_users:
        user['cert'] = os.popen("/usr/sbin/univention-certificate dump -name %s|grep 'Not After'|cut -d ':' -f2-" % user['name']).read()

    info = {"connected": c_connected_users, "total": c_users, "licenced": c_licenced}

    data = {"users": connected_users, "info": info}

    count = str(len(connected_users))

    query = web.ctx.query
    if query:
        # jsonp
        queries = query.split('&')
        callback = queries[0].split('=')[1]
        return '%s({"draw": 1, "recordsTotal": %s, "recordsFiltered": %s, "data": %s});' % (callback, count, count, json.dumps(data))
    else:
        return '{"data": %s}' % json.dumps(data)


class display_users:
    def GET(self, name):

        name = name.encode('ascii','ignore')
        name_pieces = name.split('/')

        if 'connected_users' == name_pieces[0]:
            return connected_users(name)

        elif 'kill_user' == name_pieces[0]:
            try:
                id = name_pieces[1]
                kill_answer = killuser(id)
            except:
                pass
            return ""

        else:
            return ""


if __name__ == "__main__":
    app.run(port=38081)

