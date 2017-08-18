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
    lilog(ud.INFO, 'openvpn4ucs handler')

    # determine sets of changed (incl. new/del) attributes
    usr_chgd = changed(old, new, usr_attrs)
    srv_chgd = changed(old, new, srv_attrs)
    s2s_chgd = changed(old, new, s2s_attrs)

    obj = {'n': new, 'a': new, 'm': old, 'd': old, 'r': old}[cmd]

    if usr_chgd:
        handle_user(dn, obj, usr_chgd)

    if srv_chgd:
        handle_server(dn, obj, srv_chgd)

    if s2s_chgd:
        handle_sitetosite(dn, obj, s2s_chgd)


# perform any restarts necessary
def postrun():
    global action
    if not action:
        return
    # ....

    lilog(ud.DEBUG, 'postrun action = %s' % (action))

    if action == 'stop':
        # deactivate config
        try:
            listener.setuid(0)
            os.rename (fn_serverconf, fn_serverconf + '-disabled')
        except Exception, e:
            listener.unsetuid()
            ud.debug(ud.LISTENER, ud.ERROR, '4 Failed to deactivate server config: %s' % str(e))
            return

    try:
        listener.setuid(0)
        # broken
        ### listener.run('/etc/init.d/openvpn', ['openvpn', 'restart', 'server'], uid=0)
    finally:
        listener.unsetuid()

    listener.unsetuid()


# -----------------------------------------------------------------------------


usr_attrs  = [
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


def handle_user(dn, obj, changes):
    lilog(ud.DEBUG, 'user handler')

    if isin_and('univentionOpenvpnAccount', changes, op.eq, '1'):
        return user_enable(dn, obj)

    if isin_and('univentionOpenvpnAccount', changes, op.eq, '0'):
        return user_disable(dn, obj)
     

def handle_server(dn, obj, changes):
    lilog(ud.DEBUG, 'server handler')

    if isin_and('univentionOpenvpnActive', changes, op.eq, '1'):
        return server_enable(dn, obj)

    if isin_and('univentionOpenvpnActive', changes, op.ne, '1'):
        return server_disable(dn, obj)

    if isin_and('univentionOpenvpnActive', obj, op.eq, '1'):
        return server_modify(dn, obj, changes)


def handle_sitetosite(dn, obj, changes):
    lilog(ud.DEBUG, 'sitetosite handler')

    if isin_and('univentionOpenvpnSitetoSiteActive', changes, op.eq, '1'):
        return sitetosite_enable(dn, obj)

    if isin_and('univentionOpenvpnSitetoSiteActive', changes, op.ne, '1'):
        return sitetosite_disable(dn, obj)

    if isin_and('univentionOpenvpnSitetoSiteActive', old, op.eq, '1'):
        return sitetosite_modify(dn, obj)


# -----------


def user_disable(dn, obj):
    lilog(ud.INFO, 'user disable')

    uid = obj.get('uid', [None])[0]
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
    udir = fn_r2gbase + uid
    listener.setuid(0)
    try:
        listener.run('/bin/rm', ['rm', '-f', udir + '/*.zip'], uid=0)
    except:
        lilog(ud.ERROR, 'removing readytogo packages failed')
    finally:
        listener.unsetuid()

    # cleanup ccd data
    listener.setuid(0)
    try:
        lo = ul.getMachineConnection()
    finally:
        listener.unsetuid()

    myname = listener.baseConfig['hostname']
    tmp, server = lo.search('(cn=' + myname + ')')[0]
    port = server.get('univentionOpenvpnPort', [None])[0]
    if port:
        ccd = '/etc/openvpn/ccd-' + port + '/'
        ips = '/etc/openvpn/ips-' + port
        ipsv6 = '/etc/openvpn/ipsv6-' + port
        uid = obj.get('uid', [None])[0]

        listener.setuid(0)
        try:
            univention_openvpn_common.delete_file(4, ccd + client_cn + ".openvpn")
            delete_entry(client_cn, ips)
            delete_entry(client_cn, ipsv6)
        finally:
            listener.unsetuid()




def user_enable(dn, obj):
    lilog(ud.INFO, 'user enable')

    if not univention_openvpn_common.check_user_count(1):
	return			# do nothing

    uid = obj.get('uid', [None])[0]
    if not uid:
        lilog(ud.ERROR, 'cannot get uid from object, dn: ' + dn)
        return

    listener.setuid(0)
    try: 
        lo = ul.getMachineConnection()
    finally:
        listener.unsetuid()

    name = listener.baseConfig['hostname']

    tmp, server = lo.search('(cn=' + name + ')')[0]

    port = server.get('univentionOpenvpnPort', [None])[0]
    addr = server.get('univentionOpenvpnAddress', [None])[0]
    proto = 'udp6' if addr and addr.count(':') else 'udp'

    if not name or not port or not addr:
        return

    lilog(ud.INFO, 'Create new certificate for %s' % uid)

    try:
        listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', uid, name, addr, port, proto], uid=0)
    except:
            lilog(ud.ERROR, 'create-bundle failed')
    finally:
        listener.unsetuid()


    # ccd config for user

    network = server.get('univentionOpenvpnNet', [None])[0]

    ipnw = netaddr.IPNetwork(network)
    if ipnw.size == 1:
        netmask = '255.255.255.0'
        network = str(ipnw.network) + "/24"
    else:
        netmask = str(ipnw.netmask)

    networkv6 = server.get('univentionOpenvpnNetIPv6', [None])[0]

    if networkv6 is None:
        networkv6 = "2001:db8:0:123::/64"
    netmaskv6 = str(netaddr.IPNetwork(networkv6).netmask)

    if port:
        ccd = '/etc/openvpn/ccd-' + port + '/'
        ips = '/etc/openvpn/ips-' + port
        ipsv6 = '/etc/openvpn/ipsv6-' + port

        if not os.path.exists(ccd):
        listener.setuid(0)
        try:
            os.makedirs(ccd)
        finally:
            listener.unsetuid()
        ip_map = univention_openvpn_common.load_ip_map(4, fn_ips)
        for (name, ip) in ip_map:
            line = "ifconfig-push " + ip + " " + netmask
            univention_openvpn_common.write_rc(4, line, ccd + name + ".openvpn")

        if not os.path.exists(fn_ips):
            listener.setuid(0)
            try:
                open(fn_ips, 'a').close()
            finally:
                listener.unsetuid()

        if not os.path.exists(fn_ipsv6):
            listener.setuid(0)
            try:
                open(fn_ipsv6, 'a').close()
            finally:
                listener.unsetuid()

        lines = []
        ip = write_entry(uid, ips, network)
        ipv6 = write_entry(uid, ipsv6, networkv6)

        lines.append("ifconfig-push " + ip + " " + netmask + "\n")
        lines.append("ifconfig-ipv6-push " + ipv6 + "/" + networkv6.split('/')[1] + "\n")

        univention_openvpn_common.write_rc(4, lines, ccd + client_cn + ".openvpn")


# -----------


def server_disable(dn, obj):
    lilog(ud.INFO, 'server disable')


def server_enable(dn, obj):
    lilog(ud.INFO, 'server enable')

    if not univention_openvpn_common.check_user_count(2):
        return          # do nothing

    listener.setuid(0)
    lo = ul.getMachineConnection()
    listener.unsetuid()


        # server config, ccd/addrs, start/stop

              # ....
              # ....
              # ....




    #
    # create/update bundles for users
    #

    name = obj.get('cn', [None])[0]
    port = obj.get('univentionOpenvpnPort', [None])[0]
    addr = obj.get('univentionOpenvpnAddress', [None])[0]

    ### ***** OBSOLETE?
    if not name or not port or not addr:
        return # do nothing 

    vpnusers = lo.search('(univentionOpenvpnAccount=1)')

    listener.setuid(0)

    for dn, user in vpnusers:
        uid = user.get('uid', [None])[0]
	if not uid:
            lilog(ud.ERROR, 'no uid on %s' % dn)
            continue

        lilog(ud.INFO, 'create new certificate for %s' % uid)

        proto = 'udp6' if addr and addr.count(':') else 'udp'
        # update bundle for this openvpn server with new config
        try:
            listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', uid, name, addr, port, proto], uid=0)
        except:
            lilog(ud.ERROR, 'create-bundle failed for %s' % uid)

    listener.unsetuid()








def server_modify(dn, obj, changes):
    lilog(ud.INFO, 'server modify')


# -----------


def sitetosite_disable(dn, obj):
    lilog(ud.INFO, 'sitetosite disable')


def sitetosite_enable(dn, obj):
    lilog(ud.INFO, 'sitetosite enable')


def sitetosite_modify(dn, obj, changes):
    lilog(ud.INFO, 'sitetosite modify')


# -----------


# -----------------------------------------------------------------------------



# generate and write entry for given user and return generated ip
def write_entry(client_cn, fn_ips, network):
    ip_map = univention_openvpn_common.load_ip_map(4, fn_ips)
    ip = generate_ip(network, ip_map)
    ip_map.append((client_cn, ip))
    univention_openvpn_common.write_ip_map(4, ip_map, fn_ips)
    return ip

# delete entry of given user in corresponding ip_map
def delete_entry(client_cn, fn_ips):
    ip_map_old = univention_openvpn_common.load_ip_map(4, fn_ips)
    ip_map_new = []
    for (name, ip) in ip_map_old:
        if name != client_cn:
            ip_map_new.append((name, ip))
    univention_openvpn_common.write_ip_map(4, ip_map_new, fn_ips)

# generate ip for given network which does not exist in ip_map
def generate_ip(network, ip_map):
    ips = netaddr.IPNetwork(network)
    first = ips[0]
    second = ips[1]
    for newip in ips.iter_hosts():
        if newip == first or newip == second:
            continue
        use = True
        for (name, ip) in ip_map:
            if str(newip) == ip:
                use = False
                break
        if use:
            return str(newip)




# ===================================================================================================


### end ###
