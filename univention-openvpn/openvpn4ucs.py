#
#       Univention OpenVPN integration -- openvpn-master.py
#

# Copyright (c) 2014-2017, bytemine GmbH
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

import listener
import univention.debug as ud
import univention.uldap as ul
import univention.config_registry as ucr
import netaddr

from datetime import date

import univention_openvpn_common

name        = 'openvpn4ucs'
description = 'handle openvpn4ucs related config changes'
filter      = '(|(objectClass=univentionOpenvpn)(objectClass=univentionOpenvpnUser)(objectClass=univentionOpenvpnSitetoSite))'
modrdn      = 1


# handle changes wrt. openvpn4ucs
def handler(dn, new, old, cmd):
    ud.debug(ud.LISTENER, ud.INFO, 'openvpn4ucs handler')

    # determine sets of changed (incl. new/del) attributes
    usr_chgd = changed(old, new, usr_attrs)
    srv_chgd = changed(old, new, srv_attrs)
    s2s_chgd = changed(old, new, s2s_attrs)

    # get latest/last attribute values
    obj = {'n': new, 'a': new, 'm': new, 'd': old, 'r': old}[cmd]

    if usr_chgd:
        handle_user(dn, obj, usr_chgd, cmd)

    if srv_chgd:
        handle_server(dn, obj, srv_chgd, cmd)

    if s2s_chgd:
        handle_sitetosite(dn, obj, s2s_chgd, cmd)


# perform any restarts necessary
def postrun():
    global action
    if not action:
        return
    # ....


# -----------------------------------------------------------------------------

usr_attrs  = [
    'sambaAcctFlags',
    'univentionOpenvpnAccount',
]

srv_attrs = [
    'univentionOpenvpnActive'
    'univentionOpenvpnAddress',
    'univentionOpenvpnPort',
    'univentionOpenvpnNet',
    'univentionOpenvpnNetIPv6',
    'univentionOpenvpnRedirect',
    'univentionOpenvpnDuplicate',
    'univentionOpenvpnFixedAddresses',
    'univentionOpenvpnUserAddress',
    'univentionOpenvpnDualfactorauth'
    'univentionOpenvpnLicense',
]

s2s_attrs = [
    'univentionOpenvpnSitetoSiteActive',
    'univentionOpenvpnSitetoSitePort',
    'univentionOpenvpnRemote',
    'univentionOpenvpnLocalAddress',
    'univentionOpenvpnRemoteAddress',
    'univentionOpenvpnSecret'
]

def changed(old, new, alist):
    c = {}
    for a in alist:
        old_a = old.get(a)[0] if old else None
        new_a = new.get(a)[0] if new else None
        if new_a != old_a:
            c[a] = new_a
    return c

isin_and = lambda k, d, o, v: k in d and o(d[k], v)

lilog = lambda l, s: ud.debug(ud.LISTENER, l, 'openvpn4ucs - ' + s)

fn_serverconf = '/etc/openvpn/server.conf'
fn_sitetositeconf = '/etc/openvpn/sitetosite.conf'
fn_secret = '/etc/openvpn/sitetosite.key'

fn_r2gbase = '/var/www/readytogo/'

action = None


def handle_user(dn, obj, changes, cmd):
    if cmd in 'dr':
        return user_disable(dn, obj)
    if isin_and('univentionOpenvpnAccount', changes, op.ne, '1'):
        return user_disable(dn, obj)
    flags = changes.get('sambaAcctFlags', [''])[0]
    if 'L' in flags or 'D' in flags or not 'U' in flags:
        return user_disable(dn, obj)
    # below check should not be necessary
    if isin_and('univentionOpenvpnAccount', changes, op.eq, '1'):
        return user_enable(dn, obj)


def handle_server(dn, obj, changes, cmd):
    if cmd in 'dr':
        return server_disable(dn, obj)
    if isin_and('univentionOpenvpnActive', changes, op.ne, '1'):
        return server_disable(dn, obj)
    if isin_and('univentionOpenvpnActive', obj, op.eq, '1'):
        return server_enable(dn, obj)


def handle_sitetosite(dn, obj, changes, cmd):
    if cmd in 'dr':
        return sitetosite_disable(dn, obj)
    if isin_and('univentionOpenvpnSitetoSiteActive', changes, op.ne, '1'):
        return sitetosite_disable(dn, obj)
    if isin_and('univentionOpenvpnSitetoSiteActive', obj, op.eq, '1'):
        return sitetosite_enable(dn, obj)



def user_disable(dn, obj):
    lilog(ud.INFO, 'user disable')

    uid = obj.get('uid', [None])[0]
    if not uid:
        lilog(ud.ERROR, 'cannot get uid from object, dn: ' + dn)
        return

    lilog(ud.INFO, 'Revoke certificate for ' + uid)

    listener.setuid(0)

    try:
        listener.run('/usr/lib/openvpn-int/o4uCert_revoke', ['o4uCert_revoke', uid], uid=0)
    except:
        lilog(ud.ERROR, 'cert revocation failed')

    # remove readytogo data
    udir = fn_r2gbase + uid
    try:
        listener.run('/bin/rm', ['rm', '-f', udir + '/*.zip'], uid=0)
    except:
        lilog(ud.ERROR, 'removing readytogo packages failed')

    listener.unsetuid()



def user_enable(dn, obj):
    ud.debug(ud.LISTENER, ud.INFO, 'openvpn4ucs - user enable')
	pass

    uid = obj.get('uid', [None])[0]
    if not uid:
        lilog(ud.ERROR, 'cannot get uid from object, dn: ' + dn)
        return

    if not univention_openvpn_common.check_user_count(1):
	return			# do nothing

    listener.setuid(0)

    lo = ul.getMachineConnection()
    servers = lo.search('(univentionOpenvpnActive=1)')

    lilog(ud.INFO, 'Create new certificate for %s' % uid)

    # create a bundle for each openvpn server (creates cert if required)
    for server in servers:
        name = server[1].get('cn', [None])[0]
        port = server[1].get('univentionOpenvpnPort', [None])[0]
        addr = server[1].get('univentionOpenvpnAddress', [None])[0]

        proto = 'udp6' if addr and addr.count(':') else 'udp'

        if not name or not port or not addr:
            continue
        try:
            listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', uid, name, addr, port, proto], uid=0)
        except:
            lilog(ud.ERROR, 'create-bundle failed')

    listener.unsetuid()



def server_disable(dn, obj):
    ud.debug(ud.LISTENER, ud.INFO, 'openvpn4ucs - server disable')
	pass

def server_enable(dn, obj):
    ud.debug(ud.LISTENER, ud.INFO, 'openvpn4ucs - server enable')
	pass

def sitetosite_disable(dn, obj):
    ud.debug(ud.LISTENER, ud.INFO, 'openvpn4ucs - sitetosite disable')
	pass

def sitetosite_enable(dn, obj):
    ud.debug(ud.LISTENER, ud.INFO, 'openvpn4ucs - sitetosite enable')
	pass







# ===================================================================================================



