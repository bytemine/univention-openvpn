#
#       Univention OpenVPN integration -- openvpn-server.py
#

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


__package__ = ''  # workaround for PEP 366

import listener
import univention.debug as ud
import re
import os
import univention.uldap as ul
import univention.config_registry as ucr
import netaddr

from datetime import date

import univention_openvpn_common


name        = 'openvpn-server'
description = 'write server-configuration to server.conf and handle address assignment'
filter      = '(objectClass=univentionOpenvpn)'
attributes   = [
    'univentionOpenvpnActive', 'univentionOpenvpnLicense', 'univentionOpenvpnAddress',
    'univentionOpenvpnPort', 'univentionOpenvpnNet', 'univentionOpenvpnNetIPv6',
    'univentionOpenvpnRedirect', 'univentionOpenvpnDuplicate',
    'univentionOpenvpnFixedAddresses', 'univentionOpenvpnUserAddress',
    'univentionOpenvpnDualfactorauth' ]
modrdn      = 1

action = None

fn_serverconf = '/etc/openvpn/server.conf'


def handler(dn, new, old, command):
    ud.debug(ud.LISTENER, ud.INFO, '3 server handler')
    global action
    if command == 'n':
        action = None
        return

    if 'univentionOpenvpnActive' in new:
        action = 'restart'
    else:
        action = 'stop'

    cn = new.get('cn', [None])[0]
    myname = listener.baseConfig['hostname']
    if cn != myname:
        action = None
        return

    if not univention_openvpn_common.check_user_count(3):
        listener.unsetuid()
        if action == 'stop':
            ud.debug(ud.LISTENER, ud.INFO, '3 Allowing stop action')
        else:
            action = None
            return			# do nothing

    #### UCS 3 ('Borgfeld') uses openvpn 2.1 - no explicit ip6 support, later version are ok
    relnam = listener.baseConfig.get('version/releasename')
    ip6ok = relnam and relnam != 'Borgfeld'
    if not ip6ok:
        ud.debug(ud.LISTENER, ud.INFO, '3 IPv6 support DISABLED due to version')

    cnaddr = new.get('univentionOpenvpnAddress', [None])[0]
    ip6conn = True if cnaddr and cnaddr.count(':') else False

    # activate config
    if not 'univentionOpenvpnActive' in old and os.path.exists(fn_serverconf + '-disabled'):
        listener.setuid(0)
        try:
            os.rename (fn_serverconf + '-disabled', fn_serverconf)
        except Exception, e:
            listener.unsetuid()
            ud.debug(ud.LISTENER, ud.ERROR, '3 Failed to activate server config: %s' % str(e))
            return
        listener.unsetuid()

    if not os.path.exists(fn_serverconf):
        config = """### Constant values

proto udp
dh /etc/openvpn/dh2048.pem
ca /etc/univention/ssl/ucsCA/CAcert.pem
cert /etc/univention/ssl/{hostname}/cert.pem
key /etc/univention/ssl/{hostname}/private.key
crl-verify /etc/openvpn/crl.pem
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

plugin /usr/lib/openvpn/openvpn-auth-pam.so /etc/pam.d/vpncheckpass
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


    portold = old.get('univentionOpenvpnPort', [None])[0]
    portnew = new.get('univentionOpenvpnPort', [None])[0]

    if portold is not portnew:
        listener.setuid(0)
        #ucr = ConfigRegistry()
        #ucr.load()
        if portold:
            ucr.handler_unset(['security/packetfilter/package/univention-openvpn-server/udp/'+portold+'/all'])
        if portnew and 'univentionOpenvpnActive' in new:
            ucr.handler_set(['security/packetfilter/package/univention-openvpn-server/udp/'+portnew+'/all=ACCEPT'])
        listener.unsetuid()


    ccd = '/etc/openvpn/ccd-' + portnew + '/'
    fn_ips = '/etc/openvpn/ips-' + portnew
    fn_ipsv6 = '/etc/openvpn/ipsv6-' + portnew

    # write new server config
    flist = univention_openvpn_common.load_rc(3, fn_serverconf)

    flist = [x for x in flist if not re.search("port", x) and not re.search('push "redirect-gateway', x) and not re.search("duplicate-cn", x) and not re.search("server", x) and not re.search("server-ipv6", x) and not re.search("client-config-dir", x) and not re.search("proto", x) and not re.search("plugin", x)]

    flist.append("port %s\n" % portnew)

    network = new.get('univentionOpenvpnNet', [None])[0]
    if not network:
        ud.debug(ud.LISTENER, ud.INFO, '3 Missing params, skipping actions')
        action = None
        return                  # invalid config, skip 
    ipnw = netaddr.IPNetwork(network)
    if ipnw.size == 1:
        netmask = '255.255.255.0'
        network = str(ipnw.network) + "/24"
    else:
        netmask = str(ipnw.netmask)
    network_pure = str(ipnw.network)
    flist.append("server %s %s\n" % (network_pure, netmask))

    if ip6ok:
        networkv6 = new.get('univentionOpenvpnNetIPv6', [None])[0]
        if networkv6 is not None:
            flist.append("server-ipv6 %s\n" % (networkv6))
        else:
            networkv6 = "2001:db8:0:123::/64"
        netmaskv6 = str(netaddr.IPNetwork(networkv6).netmask)

    if ip6conn:
        flist.append("proto udp6\n")
    else:
        flist.append("proto udp\n")

    redirect = new.get('univentionOpenvpnRedirect', [None])[0]
    if redirect == '1':
        flist.append('push "redirect-gateway def1"\n')

    duplicate = new.get('univentionOpenvpnDuplicate', [None])[0]
    if duplicate == '1':
        flist.append('duplicate-cn\n')

    fixedaddresses = new.get('univentionOpenvpnFixedAddresses', [None])[0]
    if fixedaddresses == '1':
        flist.append('client-config-dir %s\n' % ccd)

    dualfactorauth = new.get('univentionOpenvpnDualfactorauth', [None])[0]
    if dualfactorauth == '1':
        flist.append('plugin /usr/lib/openvpn/openvpn-auth-pam.so /etc/pam.d/openvpn\n')
    else:
        flist.append('plugin /usr/lib/openvpn/openvpn-auth-pam.so /etc/pam.d/vpncheckpass\n')

    univention_openvpn_common.write_rc(3, flist, fn_serverconf)

    if not os.path.exists(ccd):
        if not os.path.exists('/etc/openvpn/ccd-%s' % portold):
            univention_openvpn_common.create_dir(3, ccd)
        else:
            univention_openvpn_common.rename_dir(3, '/etc/openvpn/ccd-%s' % portold, '/etc/openvpn/ccd-%s' % portnew)

    if not os.path.exists(fn_ips):
        listener.setuid(0)
        open(fn_ips, 'a').close()
        listener.unsetuid()

    if ip6ok:
        if not os.path.exists(fn_ipsv6):
            listener.setuid(0)
            open(fn_ipsv6, 'a').close()
            listener.unsetuid()

    # adapt ip_maps and ccd
    if new.get('univentionOpenvpnNet', [None])[0] != old.get('univentionOpenvpnNet', [None])[0]:
        change_net(network, netmask, ccd, fn_ips, False)

    if ip6ok:
        if new.get('univentionOpenvpnNetIPv6', [None])[0] != old.get('univentionOpenvpnNetIPv6', [None])[0]:
            change_net(networkv6, netmaskv6, ccd, fn_ipsv6, True)

    if new.get('univentionOpenvpnUserAddress', [None]) != old.get('univentionOpenvpnUserAddress', [None]):
        useraddresses_raw = new.get('univentionOpenvpnUserAddress', [None])
        useraddresses_clean = [x for x in useraddresses_raw if x is not None]
        useraddresses = map(lambda x: tuple(x.split(":", 1)), useraddresses_clean)

        useraddressesv4 = []
        useraddressesv6 = []

        for useraddress in useraddresses:
            if netaddr.IPAddress(useraddress[1]).version == 4:
                useraddressesv4.append(useraddress)
            elif netaddr.IPAddress(useraddress[1]).version == 6:
                useraddressesv6.append(useraddress)

        assign_addresses(fn_ips, useraddressesv4, network, netmask, ccd, False)
        if ip6ok:
            assign_addresses(fn_ipsv6, useraddressesv6, networkv6, netmaskv6, ccd, True)

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
    lo = ul.getMachineConnection()
    users = lo.search('univentionOpenvpnAccount=1')
    listener.unsetuid()

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

def initialize():
    pass

def postrun():
    global action
    if not action:
        return
    ud.debug(ud.LISTENER, ud.INFO, '3 OpenVPN-Server %s' % (action))

    if action == 'stop':
        # deactivate config
        try:
            listener.setuid(0)
            os.rename (fn_serverconf, fn_serverconf + '-disabled')
            listener.run('/etc/init.d/display_users', ['display_users', 'stop'], uid=0)
        except Exception, e:
            listener.unsetuid()
            ud.debug(ud.LISTENER, ud.ERROR, '3 Failed to deactivate server config: %s' % str(e))
            return

    try:
        listener.setuid(0)
        listener.run('/etc/init.d/openvpn', ['openvpn', 'restart', 'server'], uid=0)
        listener.run('/etc/init.d/univention-firewall', ['univention-firewall', 'restart'], uid=0)
        if action == 'restart':
            listener.run('/etc/init.d/display_users', ['display_users', 'restart'], uid=0)
    finally:
        listener.unsetuid()

    listener.unsetuid()


### end ###
