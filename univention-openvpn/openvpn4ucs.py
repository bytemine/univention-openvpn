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
    global action, action_s2s

    lilog(ud.INFO, 'openvpn4ucs handler')

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

    except Exception, e:
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
        old_a = old.get(a, [None])[0] if old else None
        new_a = new.get(a, [None])[0] if new else None
        if new_a != old_a:
            c[a] = new_a
    return c

isin_and = lambda k, d, o, v: k in d and o(d[k], v)

lilog = lambda l, s: ud.debug(ud.LISTENER, l, 'openvpn4ucs - ' + s)

fn_serverconf = '/etc/openvpn/server.conf'
fn_sitetositeconf = '/etc/openvpn/sitetosite.conf'
fn_secret = '/etc/openvpn/sitetosite.key'

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
    myname = listener.baseConfig['hostname']
    if cn != myname:
        lilog(ud.INFO, 'not this host')
        action = None
        return

    active = new.get('univentionOpenvpnActive', [None])[0]

    if isin_and('univentionOpenvpnActive', changes, op.eq, '1'):
        return server_enable(dn, new)

    if isin_and('univentionOpenvpnActive', changes, op.ne, '1'):
        return server_disable(dn, old)

    if active == '1':
        return server_modify(dn, old, new, changes)

    lilog(ud.INFO, 'nothing to do')


def handle_sitetosite(dn, old, new, changes):
    lilog(ud.INFO, 'sitetosite handler')

    # check if the change is on this host 
    cn = obj.get('cn', [None])[0]
    myname = listener.baseConfig['hostname']
    if cn != myname:
        lilog(ud.INFO, 'not this host')
        action = None
        return

    active = new.get('univentionOpenvpnSitetoSiteActive', [None])[0]

    if isin_and('univentionOpenvpnSitetoSiteActive', changes, op.eq, '1'):
        return sitetosite_enable(dn, new)

    if isin_and('univentionOpenvpnSitetoSiteActive', changes, op.ne, '1'):
        return sitetosite_disable(dn, old)

    if active == '1':
        return sitetosite_modify(dn, old, new, changes)

    lilog(ud.INFO, 'nothing to do')


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
    myname = listener.baseConfig['hostname']
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
            os.remove(ccd + uid + '.openvpn')
            delete_entry(uid, ips)
            delete_entry(uid, ipsv6)
        except Exception as e:
            lilog(ud.ERROR, '%d Failed to write file "%s": %s' % (no, wfile, str(e)))
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

    network           = server.get('univentionOpenvpnNet', [None])[0]
    networkv6         = server.get('univentionOpenvpnNetIPv6', ['2001:db8:0:123::/64'])[0]

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

    univention_openvpn_common.write_rc(4, lines, ccd + uid + ".openvpn")


# -----------


def server_disable(dn, obj):
    lilog(ud.INFO, 'server disable')

    global action
    action = 'stop'

    portnew = obj.get('univentionOpenvpnSitetoSitePort', [None])[0]
    adjust_firewall(portnew, {})
    adjust_ccd(obj, {})


def server_enable(dn, obj):
    lilog(ud.INFO, 'server enable')

    global action
    action = None

    if not univention_openvpn_common.check_user_count(2):
        return          # do nothing

    if not update_config(obj):
        lilog('config update failed, skipping actions')
        return

    action = 'start'

    port = obj.get('univentionOpenvpnPort', [None])[0]
    name = obj.get('cn', [None])[0]
    addr = obj.get('univentionOpenvpnAddress', [None])[0]

    if port:
        adjust_firewall({}, port)
        adjust_ccd({}, obj)

        # create/update bundles for users
        if name and addr:
            update_bundles(name, port, addr)


def server_modify(dn, old, new, changes):
    lilog(ud.INFO, 'server modify')

    if not univention_openvpn_common.check_user_count(2):
        return          # do nothing

    global action
    action = None

    if not update_config(new):
        lilog('config update failed, skipping actions')
        return

    action = 'start'

    if 'univentionOpenvpnPort' in changes:
        portold = old.get('univentionOpenvpnPort', [None])[0]
        portnew = new.get('univentionOpenvpnPort', [None])[0]
        adjust_firewall(portold, portnew)
        adjust_ccd(old, new)

    if 'cn' in changes or 'univentionOpenvpnPort' in changes or 'univentionOpenvpnAddress' in changes:
        # create/update bundles for users
        name = new.get('cn', [None])[0]
        port = new.get('univentionOpenvpnPort', [None])[0]
        addr = new.get('univentionOpenvpnAddress', [None])[0]
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

    if not univention_openvpn_common.check_sitetosite(5):
        return		# do nothing

    if not update_config_s2s(obj):
        lilog('config update failed, skipping actions')
        return

    action = start

    portnew = new.get('univentionOpenvpnSitetoSitePort', [None])[0]
    adjust_firewall({}, portnew)



def sitetosite_modify(dn, old, new, changes):
    lilog(ud.INFO, 'sitetosite modify')

    global action
    action = None

    if not univention_openvpn_common.check_sitetosite(5):
        return		# do nothing

    if not update_config_s2s(new):
        lilog('config update failed, skipping actions')
        return

    action = start

    if 'univentionOpenvpnSitetoSitePort' in changes:
        portold = old.get('univentionOpenvpnSitetoSitePort', [None])[0]
        portnew = new.get('univentionOpenvpnSitetoSitePort', [None])[0]
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
{dorouC}push "route {interfaces_eth0_network} {interfaces_eth0_netmask}"
{donamC}push "dhcp-option DNS {nameserver1}"
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

    interfaces_eth0_network = listener.baseConfig['interfaces/eth0/network']
    interfaces_eth0_netmask = listener.baseConfig['interfaces/eth0/netmask']
    nameserver1 = listener.baseConfig['nameserver1']
    domain_domainname = listener.baseConfig['domain/domainname']
    domainname = listener.baseConfig['domainname']

    if domain_domainname is not None:
        dodom = domain_domainname
    else:
        dodom = domainname

    if interfaces_eth0_network == '' or interfaces_eth0_netmask == '':
        dorouC = '#'
    else:
        dorouC = ''

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
        'dorouC' : dorouC,
        'donamC' : donamC,
        'dodomC' : dodomC,
        'interfaces_eth0_network' : interfaces_eth0_network,
        'interfaces_eth0_netmask' : interfaces_eth0_netmask,
        'nameserver1' : nameserver1,
        'dodom' : dodom
    }

    univention_openvpn_common.write_rc(3, config.format(**context), fn_serverconf) 
    return


# initial sitetosite config, to be updated with actual values before use
def create_default_config_s2s():

    config = """### Constant values

proto udp
ifconfig-pool-persist ipp.txt
{dorouC}push "route {interfaces_eth0_network} {interfaces_eth0_netmask}"
{donamC}push "dhcp-option DNS {nameserver1}"
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

    interfaces_eth0_network = listener.baseConfig['interfaces/eth0/network']
    interfaces_eth0_netmask = listener.baseConfig['interfaces/eth0/netmask']
    nameserver1 = listener.baseConfig['nameserver1']
    domain_domainname = listener.baseConfig['domain/domainname']
    domainname = listener.baseConfig['domainname']

    if domain_domainname is not None:
        dodom = domain_domainname
    else:
        dodom = domainname

    if interfaces_eth0_network == '' or interfaces_eth0_netmask == '':
        dorouC = '#'
    else:
        dorouC = ''

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
        'dorouC' : dorouC,
        'donamC' : donamC,
        'dodomC' : dodomC,
        'interfaces_eth0_network' : interfaces_eth0_network,
        'interfaces_eth0_netmask' : interfaces_eth0_netmask,
        'nameserver1' : nameserver1,
        'dodom' : dodom,
        'fn_secret' : fn_secret
    }

    univention_openvpn_common.write_rc(5, config.format(**context), fn_sitetositeconf)
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
    portold = old.get('univentionOpenvpnPort', [None])[0]
    portnew = new.get('univentionOpenvpnPort', [None])[0]

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

    network           = new.get('univentionOpenvpnNet', [None])[0]
    networkv6         = new.get('univentionOpenvpnNetIPv6', ['2001:db8:0:123::/64'])[0]
    useraddresses_raw = new.get('univentionOpenvpnUserAddress', [None])

    netmask, netmaskv6 = network2netmask(network, networkv6)

    # adapt ip_maps and ccd
    if network != old.get('univentionOpenvpnNet', [None])[0]:
        change_net(network, netmask, ccd, ips, False)

    if networkv6 != old.get('univentionOpenvpnNetIPv6', [None])[0]:
        change_net(networkv6, netmaskv6, ccd, ipsv6, True)

    if useraddresses_raw != old.get('univentionOpenvpnUserAddress', [None]):
        useraddresses_clean = [x for x in useraddresses_raw if x is not None]
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
        uid = user.get('uid', [None])[0]
	if not uid:
            lilog(ud.ERROR, 'no uid on %s' % dn)
            continue

        lilog(ud.INFO, 'create new certificate for %s' % uid)

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
    port      = obj.get('univentionOpenvpnPort', [None])[0]
    addr      = obj.get('univentionOpenvpnAddress', [None])[0]
    network   = obj.get('univentionOpenvpnNet', [None])[0]

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
    networkv6      = obj.get('univentionOpenvpnNetIPv6', [None])[0]
    redirect       = obj.get('univentionOpenvpnRedirect', [None])[0]
    duplicate      = obj.get('univentionOpenvpnDuplicate', [None])[0]
    dualfactorauth = obj.get('univentionOpenvpnDualfactorauth', [None])[0]
    fixedaddresses = obj.get('univentionOpenvpnFixedAddresses', [None])[0]

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
        options.append('plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so /etc/pam.d/openvpn\n')
    else:
        options.append('plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so /etc/pam.d/vpncheckpass\n')

    # read, update & write server config
    flist = univention_openvpn_common.load_rc(3, fn_serverconf)
    flist = [x for x in flist if not re.search("^\s*port\s", x) and not re.search('^\s*push "redirect-gateway', x) and not re.search("^\s*duplicate-cn", x) and not re.search("^\s*server\s", x) and not re.search("^\s*server-ipv6\s", x) and not re.search("^\s*client-config-dir\s", x) and not re.search("^\s*proto\s", x) and not re.search("^\s*plugin\s", x)]
    flist += options

    univention_openvpn_common.write_rc(3, flist, fn_serverconf)
    return True


# update/create sitetosite config with current values
def update_config_s2s(obj):
    peer = obj.get('univentionOpenvpnRemote', [None])[0]
    port = obj.get('univentionOpenvpnSitetoSitePort', [None])[0]
    tloc = obj.get('univentionOpenvpnLocalAddress', [None])[0]
    trem = obj.get('univentionOpenvpnRemoteAddress', [None])[0]

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
    flist = univention_openvpn_common.load_rc(5, fn_sitetositeconf)
    flist = [x for x in flist if not re.search("remote", x) and not re.search("port", x) and not re.search("ifconfig", x)]
    flist += options

    secret = new.get('univentionOpenvpnSecret', [None])[0]
    #ud.debug(ud.LISTENER, ud.INFO, '5 secret: %s' % (secret))
    univention_openvpn_common.write_rc(5, [secret] if secret else [''], fn_secret)
    listener.setuid(0)
    os.chmod(fn_secret, 0600)
    listener.unsetuid()

    univention_openvpn_common.write_rc(5, flist, fn_sitetositeconf)
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
                open(ips, 'a').close()
    except:
	lilog(ud.ERROR, 'failed to create ' + path)
    finally:
        listener.unsetuid()


# generate and write entry for given user and return generated ip
def write_entry(uid, ips, network):
    ip_map = univention_openvpn_common.load_ip_map(4, ips)
    ip = generate_ip(network, ip_map)
    ip_map.append((uid, ip))
    univention_openvpn_common.write_ip_map(4, ip_map, ips)
    return ip


# delete entry of given user in corresponding ip_map
def delete_entry(uid, ips):
    ip_map_old = univention_openvpn_common.load_ip_map(4, ips)
    ip_map_new = []
    for (name, ip) in ip_map_old:
        if name != uid:
            ip_map_new.append((name, ip))
    univention_openvpn_common.write_ip_map(4, ip_map_new, ips)


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
    users = map(lambda user: user[1].get('uid', [None])[0], users)

    for name in users:
        ip_new = generate_ip(network, ip_map_new)
        ip_map_new.append((name, ip_new))

        # write entry in ccd
        cc = univention_openvpn_common.load_rc(3, ccd + name + ".openvpn")
        if cc is None:
            cc = []
        else:
            cc = [x for x in cc if not re.search(option, x)]
        cc.append(option + " " + ip_new + appendix)
        univention_openvpn_common.write_rc(3, cc, ccd + name + ".openvpn")

    univention_openvpn_common.write_ip_map(3, ip_map_new, fn_ips)


# store explicitly assigned addresses and resolve arising conlicts
def assign_addresses(fn_ips, useraddresses, network, netmask, ccd, ipv6):
    ip_map_old = univention_openvpn_common.load_ip_map(3, fn_ips)

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
        if not name in map(lambda (u, i): u, ip_map_new):
            if not ip in map(lambda (u, i): i, ip_map_new):
                ip_map_new.append((name, ip))
            else:
                conflict_users.append(name)

    # generate ips for conflict_users
    for name in conflict_users:
        ip_new = generate_ip(network, ip_map_new)
        ip_map_new.append((name, ip_new))

    # write entries in ccd
    for (name, ip) in ip_map_new:
        cc = univention_openvpn_common.load_rc(3, ccd + name + ".openvpn")
        if cc is None:
            cc = []
        else:
            cc = [x for x in cc if not re.search(option, x)]
        cc.append(option + " " + ip + appendix)
        univention_openvpn_common.write_rc(3, cc, ccd + name + ".openvpn")

    univention_openvpn_common.write_ip_map(3, ip_map_new, fn_ips)



# ===================================================================================================
