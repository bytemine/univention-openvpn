#
#       Univention OpenVPN integration -- openvpn4ucs.py
#

# Copyright (c) 2021, bytemine GmbH
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



__package__ = ''  # workaround for PEP 366

import re
import os
import operator as op
import traceback

import listener
import univention.debug as ud
import univention.uldap as ul
import univention.config_registry as ucr
import univention.config_registry.interfaces
import netaddr
import csv

from datetime import date
from M2Crypto import RSA, BIO
from base64 import b64decode


name        = 'openvpn4ucs'
description = 'handle openvpn4ucs related config changes'
filter      = '(|(objectClass=univentionOpenvpn)(objectClass=univentionOpenvpnUser))'
modrdn      = 1


# handle changes wrt. openvpn4ucs
def handler(dn, new, old, cmd):
  global action

  lilog(ud.INFO, 'openvpn4ucs handler')
  try:
    action = None

    # determine sets of changed (incl. new/del) attributes
    usr_chgd = changed(old, new, usr_attrs)
    srv_chgd = changed(old, new, srv_attrs)

    obj = {'n': new, 'a': new, 'm': old, 'd': old, 'r': old}[cmd]

    if usr_chgd:
        handle_user(dn, obj, usr_chgd)

    if srv_chgd:
        handle_server(dn, old, new, srv_chgd)

    if not (usr_chgd or srv_chgd):
        lilog(ud.INFO, 'nothing to do')
  except Exception as e:
    lilog(ud.INFO, traceback.format_exc())


# -----------------------------------------------------------------------------


usr_attrs  = [
    'univentionOpenvpnAccount',
]

srv_attrs = [
    'univentionOpenvpnAddress',
    'univentionOpenvpnPort',
]

def changed(old, new, alist):
    c = {}
    for a in alist:
        old_a = old.get(a, [b''])[0] if old else None
        new_a = new.get(a, [b''])[0] if new else None
        if new_a != old_a:
            c[a] = new_a.decode('utf8')
    return c

isin_and = lambda k, d, o, v: k in d and o(d[k], v)

lilog = lambda l, s: ud.debug(ud.LISTENER, l, 'openvpn4ucs - ' + s)

action = None


def handle_user(dn, obj, changes):
    lilog(ud.INFO, 'user handler')

    if isin_and('univentionOpenvpnAccount', changes, op.eq, '1'):
        return user_enable(dn, obj)

    if isin_and('univentionOpenvpnAccount', changes, op.ne, '1'):
        return user_disable(dn, obj)

    lilog(ud.INFO, 'nothing to do')


def handle_server(dn, old, new, changes):
    lilog(ud.INFO, 'server handler')

    # check if the change is on this host
    cn = old.get('cn', [None])[0]
    if not cn:
      cn = new.get('cn', [None])[0]
    myname = listener.configRegistry['hostname']
    if cn and cn.decode('utf8') != myname:
        lilog(ud.INFO, 'not this host')
        action = None
        return

    return server_modify(dn, old, new, changes)

    lilog(ud.INFO, 'nothing to do')


# -----------


def user_disable(dn, obj):
    lilog(ud.INFO, 'user disable')

    uid = obj.get('uid', [b''])[0].decode('utf8')
    if not uid:
        lilog(ud.ERROR, 'cannot get uid from object, dn: ' + dn)
        return

    lilog(ud.INFO, 'Revoke certificate for ' + uid)

    # revoke cert
    listener.setuid(0)
    try:
        listener.run('/usr/lib/openvpn-int/o4uCert_revoke', ['o4uCert_revoke', uid], uid=0)
    except:
        lilog(ud.ERROR, 'cert revocation failed')
    finally:
        listener.unsetuid()

    # remove readytogo data
    myname = listener.configRegistry['hostname']
    listener.setuid(0)
    try:
        listener.run('/usr/lib/openvpn-int/remove-bundle', ['remove-bundle', uid, '/nonexistent/bla', myname], uid=0)
    except:
        lilog(ud.ERROR, 'removing readytogo packages failed')
    finally:
        listener.unsetuid()


def user_enable(dn, obj):
    lilog(ud.INFO, 'user enable')

    if not check_user_count():
        return			# do nothing

    uid = obj.get('uid', [b''])[0].decode('utf8')
    if not uid:
        lilog(ud.ERROR, 'cannot get uid from object, dn: ' + dn)
        return

    home = obj.get('homeDirectory', [b''])[0].decode('utf8')

    listener.setuid(0)
    try:
        lo = ul.getMachineConnection()
    finally:
        listener.unsetuid()

    name = listener.configRegistry['hostname']

    tmp, server = lo.search('(cn=' + name + ')')[0]

    port = server.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
    addr = server.get('univentionOpenvpnAddress', [b''])[0].decode('utf8')
    proto = 'udp6' if addr and addr.count(':') else 'udp'

    if not name or not port or not addr:
        lilog(ud.ERROR, 'missings params')
        return

    lilog(ud.INFO, 'Create new certificate for %s' % uid)

    try:
        listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', 'yes', uid, home, name, addr, port, proto], uid=0)
    except:
        lilog(ud.ERROR, 'create-bundle failed')
    finally:
        listener.unsetuid()


# -----------


def server_modify(dn, old, new, changes):
    lilog(ud.INFO, 'server modify')

    if not check_user_count():
        return          # do nothing

    global action
    action = None

    if 'cn' in changes or 'univentionOpenvpnPort' in changes or 'univentionOpenvpnAddress' in changes:
        # create/update bundles for users
        name = new.get('cn', [b''])[0].decode('utf8')
        port = new.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
        addr = new.get('univentionOpenvpnAddress', [b''])[0].decode('utf8')
        if name and port and addr:
            update_bundles(name, port, addr)


# -----------


# update readytogo bundles for all active users
def update_bundles(name, port, addr):
    try:
        listener.setuid(0)
        lo = ul.getMachineConnection()
    finally:
        listener.unsetuid()

    vpnusers = lo.search('(univentionOpenvpnAccount=1)')

    for dn, user in vpnusers:
        uid = user.get('uid', [b''])[0].decode('utf8')
        if not uid:
            lilog(ud.ERROR, 'no uid on %s' % dn)
            continue

        lilog(ud.INFO, 'updating bundle for %s' % uid)

        proto = 'udp6' if addr and addr.count(':') else 'udp'
        # update bundle for this openvpn server with new config
        try:
            listener.setuid(0)
            listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', 'no', uid, home, name, addr, port, proto], uid=0)
        except Exception as e:
            lilog(ud.ERROR, 'create-bundle failed for %s: %s' % (uid, e))
        finally:
            listener.unsetuid()

    return


# ===================================================================================================

pubbio = BIO.MemoryBuffer(b'''
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAN0VVx22Oou8UTDsrug/UnZLiX2UcXeE
GvQ6kWcXBhqvSUl0cVavYL5Su45RXz7CeoImotwUzrVB8JnsIcrPYw8CAwEAAQ==
-----END PUBLIC KEY-----
''')
pub = RSA.load_pub_key_bio(pubbio)
pbs = pub.__len__() / 8

import traceback

def license(key):
    try:
        enc = b64decode(key)
        raw = ''
        while len(enc) > pbs:
            d, key = (enc[:pbs], enc[pbs:])
            raw = raw + pub.public_decrypt(d, 1).decode('utf8')
        if len(enc) != pbs:
            return None		# invalid license
        raw = raw + pub.public_decrypt(enc, 1).decode('utf8')
        #
        items = raw.rstrip().split('\n')
        if not items:
            return None		# invalid license
        vdate = int(items.pop(0))
        if date.today().toordinal() > vdate:
            lilog(ud.ERROR, 'license has expired')
            return None		# expired
        l = {'valid': True, 'vdate': vdate} # at least one feature returned
        while items:
            kv = items.pop(0).split('=', 1)
            kv.append(True)
            l[kv[0]] = kv[1]

        lilog(ud.INFO, '| Processing license with ID {}:'.format(l['id']))
        lilog(ud.INFO, '| Valid until: {}'.format(date.fromordinal(l['vdate'])))
        lilog(ud.INFO, '| Users: {}'.format(l['u']))
        lilog(ud.INFO, '| Site-2-Site: {}'.format(l['s2s']))
        return l			# valid license
    except:
        lilog(ud.ERROR, traceback.format_exc())
        return None			# invalid license

def maxvpnusers(key):
    mnlu = 5
    try:
        return max(int(license(key)['u']), mnlu)
    except:
        lilog(ud.ERROR, 'invalid license')
        return mnlu			# invalid license

def check_user_count():
    listener.setuid(0)
    lo = ul.getMachineConnection()
    listener.unsetuid()

    servers = lo.search('(univentionOpenvpnLicense=*)')
    vpnusers = lo.search('(univentionOpenvpnAccount=1)')
    vpnuc = len(vpnusers)
    maxu = 5
    for server in servers:
        key = server[1].get('univentionOpenvpnLicense', [None])[0]
        mu = maxvpnusers(key)
        if mu > maxu: maxu = mu
    lilog(ud.INFO, 'found {} active openvpn users ({} allowed)'.format(vpnuc, maxu))
    if vpnuc > maxu:
        lilog(ud.INFO, 'skipping actions')
        return False
    else:
        return True

# ===================================================================================================
