#
#       Univention OpenVPN integration -- openvpn-server2.py
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
import os
import univention.uldap as ul
import netaddr

from datetime import date

import univention_openvpn_common


name        = 'openvpn-server2'
description = 'manage fixed ip addresses on user actions'
filter      = '(objectClass=univentionOpenvpnUser)'
attributes  = ['univentionOpenvpnAccount']
modrdn      = 1

action = None

fn_serverconf = '/etc/openvpn/server.conf'


def handler(dn, new, old, command):
    ud.debug(ud.LISTENER, ud.INFO, '4 server2 handler')
    global action
    if command == 'n':
        action = None
        return

    myname = listener.baseConfig['hostname']

    listener.setuid(0)
    lo = ul.getMachineConnection()
    server = lo.search('(cn=' + myname + ')')[0]
    listener.unsetuid()

    if not univention_openvpn_common.check_user_count(4):
        return          # do nothing


    #### UCS 3 ('Borgfeld') uses openvpn 2.1 - no explicit ip6 support, later version are ok
    relnam = listener.baseConfig.get('version/releasename')
    ip6ok = relnam and relnam != 'Borgfeld'
    if not ip6ok:
        ud.debug(ud.LISTENER, ud.INFO, '4 IPv6 support DISABLED due to version')
    
    port = server[1].get('univentionOpenvpnPort', [None])[0]
    network = server[1].get('univentionOpenvpnNet', [None])[0]
    if not port or not network:
        ud.debug(ud.LISTENER, ud.INFO, '4 Missing params, skipping actions')
        action = None
        return			# invalid config, skip
    ipnw = netaddr.IPNetwork(network)
    if ipnw.size == 1:
        netmask = '255.255.255.0'
        network = str(ipnw.network) + "/24"
    else:
        netmask = str(ipnw.netmask)

    if ip6ok:
        networkv6 = server[1].get('univentionOpenvpnNetIPv6', [None])[0]
        if networkv6 is None:
            networkv6 = "2001:db8:0:123::/64"
        netmaskv6 = str(netaddr.IPNetwork(networkv6).netmask)

    ccd = '/etc/openvpn/ccd-' + port + '/'
    fn_ips = '/etc/openvpn/ips-' + port
    fn_ipsv6 = '/etc/openvpn/ipsv6-' + port

    if not os.path.exists(ccd):
        os.makedirs(ccd)
        ip_map = univention_openvpn_common.load_ip_map(4, fn_ips)
        for (name, ip) in ip_map:
            line = "ifconfig-push " + ip + " " + netmask
            univention_openvpn_common.write_rc(4, line, ccd + name + ".openvpn")

    if not os.path.exists(fn_ips):
        listener.setuid(0)
        open(fn_ips, 'a').close()
        listener.unsetuid()

    if ip6ok:
        if not os.path.exists(fn_ipsv6):
            listener.setuid(0)
            open(fn_ipsv6, 'a').close()
            listener.unsetuid()

    # delete entries on user deletion
    if command == 'd':
        client_cn = old.get('uid', [None])[0]
        univention_openvpn_common.delete_file(4, ccd + client_cn + ".openvpn")
        delete_entry(client_cn, fn_ips)
        if ip6ok:
            delete_entry(client_cn, fn_ipsv6)
        return

    client_cn = new.get('uid', [None])[0]

    # generate and write entries on account activation
    if 'univentionOpenvpnAccount' in new and not 'univentionOpenvpnAccount' in old:
        lines = []

        ip = write_entry(client_cn, fn_ips, network)
        if ip6ok:
            ipv6 = write_entry(client_cn, fn_ipsv6, networkv6)

        lines.append("ifconfig-push " + ip + " " + netmask + "\n")
        if ip6ok:
            lines.append("ifconfig-ipv6-push " + ipv6 + "/" + networkv6.split('/')[1] + "\n")

        univention_openvpn_common.write_rc(4, lines, ccd + client_cn + ".openvpn")

        return

    # delete entries on account deactiviation
    elif not 'univentionOpenvpnAccount' in new and 'univentionOpenvpnAccount' in old:
        univention_openvpn_common.delete_file(4, ccd + client_cn + ".openvpn")
        delete_entry(client_cn, fn_ips)
        if ip6ok: 
            delete_entry(client_cn, fn_ipsv6)

        return

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

def initialize():
    pass

def postrun():
    global action
    if not action:
        return
    ud.debug(ud.LISTENER, ud.INFO, '4 OpenVPN-Server %s' % (action))

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
        listener.run('/etc/init.d/openvpn', ['openvpn', 'restart', 'server'], uid=0)
    finally:
        listener.unsetuid()

    listener.unsetuid()


### end ###
