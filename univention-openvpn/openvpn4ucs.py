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
filter      = '(|(objectClass=univentionOpenvpn)(objectClass=univentionOpenvpnUser)(objectClass=univentionOpenvpnSitetoSite))'
modrdn      = 1


# handle changes wrt. openvpn4ucs
def handler(dn, new, old, cmd):
  global action, action_s2s

  lilog(ud.INFO, 'openvpn4ucs handler')
  try:
    action = None
    action_s2s = None

    # determine sets of changed (incl. new/del) attributes
    usr_chgd = changed(old, new, usr_attrs)
    srv_chgd = changed(old, new, srv_attrs)
    s2s_chgd = changed(old, new, s2s_attrs)

    obj = {'n': new, 'a': new, 'm': old, 'd': old, 'r': old}[cmd]

    if usr_chgd:
        handle_user(dn, obj, usr_chgd)

    if srv_chgd:
        handle_server(dn, old, new, srv_chgd)

    if s2s_chgd:
        handle_sitetosite(dn, old, new, s2s_chgd)

    if not (usr_chgd or srv_chgd or s2s_chgd):
        lilog(ud.INFO, 'nothing to do')
  except Exception as e:
    lilog(ud.INFO, traceback.format_exc())


# perform any restarts necessary
def postrun():
    global action, action_s2s

    lilog(ud.INFO, 'postrun action = %s, action_s2s = %s' % (action, action_s2s))

    try:
        listener.setuid(0)

        if action == 'stop':
            # stop openvpn, display_users and deactivate config
            listener.run('/etc/init.d/display_users', ['display_users', 'stop'], uid=0)
            listener.run('/bin/systemctl', ['systemctl', 'stop', 'openvpn@server.service'], uid=0)
            os.rename (fn_serverconf, fn_serverconf + '-disabled')

        elif action == 'start':
            # (re)start
            listener.setuid(0)
            listener.run('/bin/systemctl', ['systemctl', 'restart', 'openvpn@server.service'], uid=0)
            listener.run('/etc/init.d/display_users', ['display_users', 'start'], uid=0)

        if action_s2s == 'stop':
            # stop openvon, deactivate config
            listener.run('/bin/systemctl', ['systemctl', 'restart', 'openvpn@sitetosite.service'], uid=0)
            os.rename (fn_sitetositeconf, fn_sitetositeconf + '-disabled')

        elif action_s2s == 'start':
            # (re)start
            listener.run('/bin/systemctl', ['systemctl', 'restart', 'openvpn@sitetosite.service'], uid=0)

        if action or action_s2s:
            # activate possible fw changes
            listener.run('/etc/init.d/univention-firewall', ['univention-firewall', 'restart'], uid=0)

    except Exception as e:
        lilog(ud.ERROR, 'postrun (%s/%s) failed: %s' % (action, action_s2s, str(e)))

    finally:
        listener.unsetuid()


# -----------------------------------------------------------------------------


usr_attrs  = [
    'univentionOpenvpnAccount',
]

srv_attrs = [
    'univentionOpenvpnActive',
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
    'univentionOpenvpnMasquerade',
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
        old_a = old.get(a, [b''])[0] if old else None
        new_a = new.get(a, [b''])[0] if new else None
        if new_a != old_a:
            c[a] = new_a.decode('utf8')
    return c

isin_and = lambda k, d, o, v: k in d and o(d[k], v)

lilog = lambda l, s: ud.debug(ud.LISTENER, l, 'openvpn4ucs - ' + s)

fn_serverconf = '/etc/openvpn/server.conf'
fn_sitetositeconf = '/etc/openvpn/sitetosite.conf'
fn_secret = '/etc/openvpn/sitetosite.key'
fn_masqrule = '/etc/security/packetfilter.d/51_openvpn4ucs.sh'

action = None
action_s2s = None


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

    active = new.get('univentionOpenvpnActive', [None])[0]

    if isin_and('univentionOpenvpnActive', changes, op.eq, '1'):
        return server_enable(dn, new)

    if isin_and('univentionOpenvpnActive', changes, op.ne, '1'):
        return server_disable(dn, old)

    if active == b'1':
        return server_modify(dn, old, new, changes)

    lilog(ud.INFO, 'nothing to do')


def handle_sitetosite(dn, old, new, changes):
    lilog(ud.INFO, 'sitetosite handler')

    # check if the change is on this host
    cn = old.get('cn', [None])[0]
    myname = listener.configRegistry['hostname']
    if cn and cn.decode('utf8') != myname:
        lilog(ud.INFO, 'not this host')
        action = None
        return

    active = new.get('univentionOpenvpnSitetoSiteActive', [None])[0]

    if isin_and('univentionOpenvpnSitetoSiteActive', changes, op.eq, b'1'):
        return sitetosite_enable(dn, new)

    if isin_and('univentionOpenvpnSitetoSiteActive', changes, op.ne, b'1'):
        return sitetosite_disable(dn, old)

    if active == b'1':
        return sitetosite_modify(dn, old, new, changes)

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
        listener.run('/usr/lib/openvpn-int/remove-bundle', ['remove-bundle', uid, myname], uid=0)
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

    myname = listener.configRegistry['hostname']
    tmp, server = lo.search('(cn=' + myname + ')')[0]
    port = server.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
    if port:
        ccd = '/etc/openvpn/ccd-' + port + '/'
        ips = '/etc/openvpn/ips-' + port
        ipsv6 = '/etc/openvpn/ipsv6-' + port
        filnam = ccd + uid + '.openvpn'

        listener.setuid(0)
        try:
            os.remove(filnam)
            delete_entry(uid, ips)
            delete_entry(uid, ipsv6)
        except Exception as e:
            lilog(ud.ERROR, 'failed to write file "{}": {}'.format(filnam, str(e)))
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
        listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', uid, name, addr, port, proto], uid=0)
    except:
            lilog(ud.ERROR, 'create-bundle failed')
    finally:
        listener.unsetuid()

    # ccd config for user

    network           = server.get('univentionOpenvpnNet', [b''])[0].decode('utf8')
    networkv6         = server.get('univentionOpenvpnNetIPv6', ['2001:db8:0:123::/64'])[0].decode('utf8')

    netmask, netmaskv6 = network2netmask(network, networkv6)

    ccd = '/etc/openvpn/ccd-' + port + '/'
    ips = '/etc/openvpn/ips-' + port
    ipsv6 = '/etc/openvpn/ipsv6-' + port

    ensure_exists(ccd, True)
    ensure_exists(ips)
    ensure_exists(ipsv6)

    lines = []
    ip = write_entry(uid, ips, network)
    ipv6 = write_entry(uid, ipsv6, networkv6)

    lines.append("ifconfig-push " + ip + " " + netmask + "\n")
    lines.append("ifconfig-ipv6-push " + ipv6 + "/" + networkv6.split('/')[1] + "\n")

    write_rc(lines, ccd + uid + ".openvpn")


# -----------


def server_disable(dn, obj):
    lilog(ud.INFO, 'server disable')

    global action
    action = 'stop'

    port = obj.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
    masq = obj.get('univentionOpenvpnMasquerade', [b''])[0].decode('utf8')
    adjust_firewall(port, {})
    adjust_ccd(obj, {})
    if masq:
        adjust_masq(False, '')


def server_enable(dn, obj):
    lilog(ud.INFO, 'server enable')

    global action
    action = None

    if not check_user_count():
        return          # do nothing

    if not update_config(obj):
        lilog(ud.INFO, 'config update failed, skipping actions')
        return

    action = 'start'

    port = obj.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
    name = obj.get('cn', [b''])[0].decode('utf8')
    addr = obj.get('univentionOpenvpnAddress', [b''])[0].decode('utf8')
    masq = obj.get('univentionOpenvpnMasquerade', [b''])[0].decode('utf8')
    network = obj.get('univentionOpenvpnNet', [b''])[0].decode('utf8')

    if port:
        adjust_firewall({}, port)
        adjust_ccd({}, obj)
        if masq:
            adjust_masq(masq, network)

        # create/update bundles for users
        if name and addr:
            update_bundles(name, port, addr)


def server_modify(dn, old, new, changes):
    lilog(ud.INFO, 'server modify')

    if not check_user_count():
        return          # do nothing

    global action
    action = None

    if not update_config(new):
        lilog(ud.INFO, 'config update failed, skipping actions')
        return

    action = 'start'

    if 'univentionOpenvpnPort' in changes:
        portold = old.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
        portnew = new.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
        adjust_firewall(portold, portnew)
        adjust_ccd(old, new)

    masq = new.get('univentionOpenvpnMasquerade', [b''])[0].decode('utf8')
    if 'univentionOpenvpnMasquerade' in changes or 'univentionOpenvpnNet' in changes and masq:
        network = new.get('univentionOpenvpnNet', [b''])[0].decode('utf8')
        adjust_masq(masq, network)

    if 'cn' in changes or 'univentionOpenvpnPort' in changes or 'univentionOpenvpnAddress' in changes:
        # create/update bundles for users
        name = new.get('cn', [b''])[0].decode('utf8')
        port = new.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
        addr = new.get('univentionOpenvpnAddress', [b''])[0].decode('utf8')
        if name and port and addr:
            update_bundles(name, port, addr)


# -----------


def sitetosite_disable(dn, obj):
    lilog(ud.INFO, 'sitetosite disable')

    global action
    action = None


def sitetosite_enable(dn, obj):
    lilog(ud.INFO, 'sitetosite enable')

    global action
    action = None

    if not check_sitetosite():
        return		# do nothing

    if not update_config_s2s(obj):
        lilog(ud.INFO, 'config update failed, skipping actions')
        return

    action = start

    portnew = new.get('univentionOpenvpnSitetoSitePort', [None])[0]
    adjust_firewall({}, portnew)



def sitetosite_modify(dn, old, new, changes):
    lilog(ud.INFO, 'sitetosite modify')

    global action
    action = None

    if not check_sitetosite():
        return		# do nothing

    if not update_config_s2s(new):
        lilog(ud.INFO, 'config update failed, skipping actions')
        return

    action = start

    if 'univentionOpenvpnSitetoSitePort' in changes:
        portold = old.get('univentionOpenvpnSitetoSitePort', [b''])[0].decode('utf8')
        portnew = new.get('univentionOpenvpnSitetoSitePort', [b''])[0].decode('utf8')
        adjust_firewall(portold, portnew)


# -----------------------------------------------------------------------------



# initial config, to be updated with actual values before use
def create_default_config():

    config = """### Constant values

proto udp
dh /etc/openvpn/dh2048.pem
ca /etc/openvpn/o4uCA/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
crl-verify /etc/openvpn/o4uCA/crl.pem
cipher AES-256-CBC
ifconfig-pool-persist ipp.txt
{routes}{donamC}push "dhcp-option DNS {nameserver1}"
{dodomC}push "dhcp-option DOMAIN {dodom}"
keepalive 10 120
comp-lzo
persist-key
persist-tun
verb 1
mute 5
status /var/log/openvpn/openvpn-status.log
management /var/run/management-udp unix
dev tun
topology subnet

### Values which can be changed through UDM

plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so /etc/pam.d/vpncheckpass
server 10.0.1.0 255.255.255.0
port 443
push "redirect-gateway def1"
"""

    r = ''
    for n, i in ucr.interfaces.Interfaces().all_interfaces:
        try:
            r += 'push "route {} {}"\n'.format(i['network'], i['netmask'])
        except:
            ud.debug(ud.LISTENER, ud.INFO, '3 ignoring interface ' + n)

    myname = listener.configRegistry['hostname']
    nameserver1 = listener.configRegistry['nameserver1']
    domain_domainname = listener.configRegistry['domain/domainname']
    domainname = listener.configRegistry['domainname']

    if domain_domainname is not None:
        dodom = domain_domainname
    else:
        dodom = domainname

    if nameserver1 == '':
        donamC = '#'
    else:
        donamC = ''

    if dodom == '':
        dodomC = '#'
    else:
        dodomC = ''

    context = {
        'hostname' : myname,
        'routes' : r,
        'donamC' : donamC,
        'dodomC' : dodomC,
        'nameserver1' : nameserver1,
        'dodom' : dodom
    }

    write_rc(config.format(**context), fn_serverconf)
    return


# initial sitetosite config, to be updated with actual values before use
def create_default_config_s2s():

    config = """### Constant values

proto udp
ifconfig-pool-persist ipp.txt
{routes}{donamC}push "dhcp-option DNS {nameserver1}"
{dodomC}push "dhcp-option DOMAIN {dodom}"
keepalive 10 120
comp-lzo
persist-key
persist-tun
verb 1
mute 5
status /var/log/openvpn/openvpn-sitetosite-status.log
management /var/run/management-udp-sitetosite unix
dev tun
secret {fn_secret}
cipher AES-256-CBC

### Values which can be changed through UDM

remote 10.0.1.0
port 444
ifconfig 10.0.0.1 10.0.0.2
"""

    r = ''
    for n, i in ucr.interfaces.Interfaces().all_interfaces:
        try:
            r += 'push "route {} {}"\n'.format(i['network'], i['netmask'])
        except:
            ud.debug(ud.LISTENER, ud.INFO, '3 ignoring interface ' + n)

    myname = listener.configRegistry['hostname']
    nameserver1 = listener.configRegistry['nameserver1']
    domain_domainname = listener.configRegistry['domain/domainname']
    domainname = listener.configRegistry['domainname']

    if domain_domainname is not None:
        dodom = domain_domainname
    else:
        dodom = domainname

    if nameserver1 == '':
        donamC = '#'
    else:
        donamC = ''

    if dodom == '':
        dodomC = '#'
    else:
        dodomC = ''

    context = {
        'hostname' : myname,
        'routes' : r,
        'donamC' : donamC,
        'dodomC' : dodomC,
        'nameserver1' : nameserver1,
        'dodom' : dodom,
        'fn_secret' : fn_secret
    }

    write_rc(config.format(**context), fn_sitetositeconf)
    return



# adjust univention-firewall settings
def adjust_firewall(portold, portnew):
    try:
        listener.setuid(0)
        if portold:
            ucr.handler_unset(['security/packetfilter/package/openvpn4ucs/udp/'+portold+'/all'])
        if portnew:
            ucr.handler_set(['security/packetfilter/package/openvpn4ucs/udp/'+portnew+'/all=ACCEPT'])
    finally:
        listener.unsetuid()


# create / update ccd path and contents (never remove)
def adjust_ccd(old, new):
    portold = old.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
    portnew = new.get('univentionOpenvpnPort', [b''])[0].decode('utf8')

    po = portold if portold else 'disabled'
    pn = portnew if portnew else 'disabled'

    ccd = '/etc/openvpn/ccd-' + pn + '/'
    ips = '/etc/openvpn/ips-' + pn
    ipsv6 = '/etc/openvpn/ipsv6-' + pn

    try:
        listener.setuid(0)
        if pn != po:
            occd = '/etc/openvpn/ccd-' + po
            oips = '/etc/openvpn/ips-' + po
            oipsv6 = '/etc/openvpn/ipsv6-' + po
            if os.path.exists(occd):
                os.rename(occd, ccd)
            if os.path.exists(oips):
                os.rename(oips, ips)
            if os.path.exists(oipsv6):
                os.rename(oipsv6, ipsv6)

        ensure_exists(ccd)
        ensure_exists(ips)
        ensure_exists(ipsv6)

    finally:
        listener.unsetuid()

    if not new:
        return

    network           = new.get('univentionOpenvpnNet', [b''])[0].decode('utf8')
    networkv6         = new.get('univentionOpenvpnNetIPv6', [b'2001:db8:0:123::/64'])[0].decode('utf8')
    useraddresses_raw = new.get('univentionOpenvpnUserAddress', [b''])

    netmask, netmaskv6 = network2netmask(network, networkv6)

    # adapt ip_maps and ccd
    if network != old.get('univentionOpenvpnNet', [b''])[0].decode('utf8'):
        change_net(network, netmask, ccd, ips, False)

    if networkv6 != old.get('univentionOpenvpnNetIPv6', [b''])[0].decode('utf8'):
        change_net(networkv6, netmaskv6, ccd, ipsv6, True)

    if useraddresses_raw != old.get('univentionOpenvpnUserAddress', [b'']):
        useraddresses_clean = [x.decode('utf8') for x in useraddresses_raw if x]
        useraddresses = map(lambda x: tuple(x.split(":", 1)), useraddresses_clean)

        useraddressesv4 = []
        useraddressesv6 = []

        for useraddress in useraddresses:
            if netaddr.IPAddress(useraddress[1]).version == 4:
                useraddressesv4.append(useraddress)
            elif netaddr.IPAddress(useraddress[1]).version == 6:
                useraddressesv6.append(useraddress)

        assign_addresses(ips, useraddressesv4, network, netmask, ccd, False)
        assign_addresses(ipsv6, useraddressesv6, networkv6, netmaskv6, ccd, True)

    return


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
            listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', uid, name, addr, port, proto], uid=0)
        except Exception as e:
            lilog(ud.ERROR, 'create-bundle failed for %s: %s' % (uid, e))
        finally:
            listener.unsetuid()

    return


# update/create config with current values
def update_config(obj):
    port      = obj.get('univentionOpenvpnPort', [b''])[0].decode('utf8')
    addr      = obj.get('univentionOpenvpnAddress', [b''])[0].decode('utf8')
    network   = obj.get('univentionOpenvpnNet', [b''])[0].decode('utf8')

    if not port or not addr or not network:
        lilog(ud.ERROR, 'missing params, not updating config')
        return False

    # activate disabled config or create default
    # (or reuse existing config, )
    if not os.path.exists(fn_serverconf):
        if os.path.exists(fn_serverconf + '-disabled'):
            listener.setuid(0)
            try:
                os.rename (fn_serverconf + '-disabled', fn_serverconf)
            except Exception as e:
                lilog(ud.ERROR, 'failed to activate server config: %s' % str(e))
                return False
            finally:
                listener.unsetuid()
        else:
            create_default_config()

    # optional params
    networkv6      = obj.get('univentionOpenvpnNetIPv6', [b''])[0].decode('utf8')
    redirect       = obj.get('univentionOpenvpnRedirect', [b''])[0].decode('utf8')
    duplicate      = obj.get('univentionOpenvpnDuplicate', [b''])[0].decode('utf8')
    dualfactorauth = obj.get('univentionOpenvpnDualfactorauth', [b''])[0].decode('utf8')
    fixedaddresses = obj.get('univentionOpenvpnFixedAddresses', [b''])[0].decode('utf8')

    # derived values
    ip6conn = bool(addr and addr.count(':'))
    ccd = '/etc/openvpn/ccd-' + port + '/'
    ipnw = netaddr.IPNetwork(network)
    if ipnw.size == 1:
        netmask = '255.255.255.0'
        network = str(ipnw.network) + "/24"
    else:
        netmask = str(ipnw.netmask)
    network_pure = str(ipnw.network)

    # config lines for params
    options = []
    options.append("port %s\n" % port)
    options.append('proto udp%s\n' % ('6' if ip6conn else ''))
    options.append("server %s %s\n" % (network_pure, netmask))
    if networkv6:
        options.append("server-ipv6 %s\n" % (networkv6))
    else:
        networkv6 = "2001:db8:0:123::/64"
    netmaskv6 = str(netaddr.IPNetwork(networkv6).netmask)
    if redirect == '1':
        options.append('push "redirect-gateway def1"\n')
    if duplicate == '1':
        options.append('duplicate-cn\n')
    if fixedaddresses == '1':
        options.append('client-config-dir %s\n' % ccd)
    if dualfactorauth == '1':
        options.append('plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /etc/pam.d/openvpn\n')
    else:
        options.append('plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /etc/pam.d/vpncheckpass\n')

    # read, update & write server config
    flist = load_rc(fn_serverconf)
    flist = [x for x in flist if not re.search("^\s*port\s", x) and not re.search('^\s*push "redirect-gateway', x) and not re.search("^\s*duplicate-cn", x) and not re.search("^\s*server\s", x) and not re.search("^\s*server-ipv6\s", x) and not re.search("^\s*client-config-dir\s", x) and not re.search("^\s*proto\s", x) and not re.search("^\s*plugin\s", x)]
    flist += options

    write_rc(flist, fn_serverconf)
    return True


# update/create sitetosite config with current values
def update_config_s2s(obj):
    peer = obj.get('univentionOpenvpnRemote', [b''])[0].decode('utf8')
    port = obj.get('univentionOpenvpnSitetoSitePort', [b''])[0].decode('utf8')
    tloc = obj.get('univentionOpenvpnLocalAddress', [b''])[0].decode('utf8')
    trem = obj.get('univentionOpenvpnRemoteAddress', [b''])[0].decode('utf8')

    if not (peer and port and tloc and trem):
        lilog(ud.ERROR, 'missing params, not updating config')
        return False

    # activate disabled config or create default
    # (or reuse existing config, )
    if not os.path.exists(fn_sitetositeconf):
        if os.path.exists(fn_sitetositeconf + '-disabled'):
            listener.setuid(0)
            try:
                os.rename (fn_sitetositeconf + '-disabled', fn_sitetositeconf)
            except Exception as e:
                lilog(ud.ERROR, 'failed to activate sitetosite config: %s' % str(e))
                return False
            finally:
                listener.unsetuid()
        else:
            create_default_config()

    # config lines for params
    options = [
        'port %s\n' % port,
        'remote %s\n' % peer,
        'ifconfig %s %s\n' % (localaddress, remoteaddress)
    ]

    # read, update & write server config
    flist = load_rc(fn_sitetositeconf)
    flist = [x for x in flist if not re.search("remote", x) and not re.search("port", x) and not re.search("ifconfig", x)]
    flist += options

    secret = new.get('univentionOpenvpnSecret', [b''])[0].decode('utf8')
    #ud.debug(ud.LISTENER, ud.INFO, '5 secret: %s' % (secret))
    write_rc([secret] if secret else [b''], fn_secret)
    listener.setuid(0)
    os.chmod(fn_secret, 0o600)
    listener.unsetuid()

    write_rc(flist, fn_sitetositeconf)
    return True


# extract netmasks from network strings
def network2netmask(net, net6):
    ipnw = netaddr.IPNetwork(net)
    if ipnw.size == 1:
        mask = '255.255.255.0'
        network = str(ipnw.network) + "/24"
    else:
        mask = str(ipnw.netmask)
    mask6 = str(netaddr.IPNetwork(net6).netmask)
    return mask, mask6


# ensure file or directory exists
def ensure_exists(path, dir=False):
    listener.setuid(0)
    try:
        if not os.path.exists(path):
            if dir:
                os.makedirs(path)
            else:
                open(path, 'a').close()
    except:
        lilog(ud.ERROR, 'failed to create ' + path)
    finally:
        listener.unsetuid()


# generate and write entry for given user and return generated ip
def write_entry(uid, ips, network):
    ip_map = load_ip_map(ips)
    ip = generate_ip(network, ip_map)
    ip_map.append((uid, ip))
    write_ip_map(ip_map, ips)
    return ip


# delete entry of given user in corresponding ip_map
def delete_entry(uid, ips):
    ip_map_old = load_ip_map(ips)
    ip_map_new = []
    for (name, ip) in ip_map_old:
        if name != uid:
            ip_map_new.append((name, ip))
    write_ip_map(ip_map_new, ips)


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


# enable/disable and adjust network in masquerading rule
def adjust_masq(masq, network):
    lilog(ud.INFO, 'adjust_masq({}, {})'.format(masq, network))
    listener.setuid(0)
    if masq:
        try:
            with open(fn_masqrule, "w") as f:
                os.chmod(fn_masqrule, 0o755)
                tmpl = '#!/bin/sh\niptables --wait -t nat -A POSTROUTING -s {} ! -d {} -j MASQUERADE\n'
                f.write(tmpl.format(network, network))
        except Exception as e:
            lilog(ud.ERROR, 'failed to write masqerade rule: {}'.format(e))
    else:
        try:
            os.remove(fn_masqrule)
        except Exception as e:
            lilog(ud.ERROR, 'failed to remove masqerade rule: {}'.format(e))
    listener.unsetuid()


# adapt all stored addresses to new network
def change_net(network, netmask, ccd, fn_ips, ipv6):
    if ipv6:
        option = "ifconfig-ipv6-push"
        appendix = "/" + network.split('/')[1] + "\n"
    else:
        option = "ifconfig-push"
        appendix = " " + netmask + "\n"

    ip_map_new = []
    listener.setuid(0)
    try:
        lo = ul.getMachineConnection()
    finally:
        listener.unsetuid()

    users = lo.search('univentionOpenvpnAccount=1')
    users = map(lambda user: user[1].get('uid', [b''])[0].decode('utf8'), users)

    for name in users:
        ip_new = generate_ip(network, ip_map_new)
        ip_map_new.append((name, ip_new))

        # write entry in ccd
        cc = load_rc(ccd + name + ".openvpn")
        if cc is None:
            cc = []
        else:
            cc = [x for x in cc if not re.search(option, x)]
        cc.append(option + " " + ip_new + appendix)
        write_rc(cc, ccd + name + ".openvpn")

    write_ip_map(ip_map_new, fn_ips)


# store explicitly assigned addresses and resolve arising conlicts
def assign_addresses(fn_ips, useraddresses, network, netmask, ccd, ipv6):
    ip_map_old = load_ip_map(fn_ips)

    if ipv6:
        option = "ifconfig-ipv6-push"
        appendix = "/" + network.split('/')[1] + "\n"
        ip_map_new = useraddresses
    else:
        option = "ifconfig-push"
        appendix = " " + netmask + "\n"
        ip_map_new = useraddresses

    conflict_users = []

    # keep old entries if no conflict arises, otherwise store name in conflict_users
    for (name, ip) in ip_map_old:
        if not name in map(lambda u, i: u, ip_map_new):
            if not ip in map(lambda u, i: i, ip_map_new):
                ip_map_new.append((name, ip))
            else:
                conflict_users.append(name)

    # generate ips for conflict_users
    for name in conflict_users:
        ip_new = generate_ip(network, ip_map_new)
        ip_map_new.append((name, ip_new))

    # write entries in ccd
    for (name, ip) in ip_map_new:
        cc = load_rc(ccd + name + ".openvpn")
        if cc is None:
            cc = []
        else:
            cc = [x for x in cc if not re.search(option, x)]
        cc.append(option + " " + ip + appendix)
        write_rc(cc, ccd + name + ".openvpn")

    write_ip_map(ip_map_new, fn_ips)



# ===================================================================================================

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
        return None			# invalid license

def maxvpnusers(key):
    mnlu = 5
    try:
        return max(int(license(key)['u']), mnlu)
    except:
        lilog(ud.ERROR, 'invalid license')
        return mnlu			# invalid license


# function to open a textfile with setuid(0) for root-action
def load_rc(ofile):
    l = None
    listener.setuid(0)
    try:
        f = open(ofile,"r")
        l = f.readlines()
        f.close()
    except Exception as e:
        lilog(ud.ERROR, 'failed to read file "{}": {}'.format(ofile, str(e)))
    listener.unsetuid()
    return l

# function to write to a textfile with setuid(0) for root-action
def write_rc(flist, wfile):
    listener.setuid(0)
    try:
        f = open(wfile,"w")
        f.writelines(flist)
        f.close()
    except Exception as e:
        lilog(ud.ERROR, 'failed to write file "{}": {}'.format(wfile, str(e)))
    listener.unsetuid()

# function to open an ip map with setuid(0) for root-action
def load_ip_map(path):
    ip_map = []
    listener.setuid(0)
    try:
        with open(path, 'r') as f:
            r = csv.reader(f, delimiter=' ', quotechar='|')
            for row in r:
                ip_map.append(row)
    except Exception as e:
        lilog(ud.ERROR, 'failed to load ip map: {}'.format(str(e)))
    listener.unsetuid()
    return ip_map

# function to write an ip map with setuid(0) for root-action
def write_ip_map(ip_map, path):
    listener.setuid(0)
    try:
        with open(path, 'w') as f:
            w = csv.writer(f, delimiter=' ', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for i in ip_map:
                w.writerow(i)
    except Exception as e:
        lilog(ud.ERROR, 'failed to write ip map: {}'.format(str(e)))
    listener.unsetuid()

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

def check_sitetosite():
    listener.setuid(0)
    lo = ul.getMachineConnection()
    listener.unsetuid()

    servers = lo.search('(univentionOpenvpnLicense=*)')
    sitetosite = False
    for server in servers:
        key = server[1].get('univentionOpenvpnLicense', [None])[0]
        try:
            l = license(key)
            if l.get('s2s'): sitetosite = True
            break
        except:
            pass
    if not sitetosite:
        lilog(ud.INFO, 'skipping actions')
        return False
    else:
        return True


# ===================================================================================================
