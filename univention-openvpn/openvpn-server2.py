#
#       Univention OpenVPN integration -- openvpn-server2.py
#


__package__ = ''  # workaround for PEP 366

import listener
import univention.debug
import re
import univention_baseconfig
import os
import csv
import univention.uldap as ul
from netaddr import *

name        = 'openvpn-server2'
description = 'manage fixed ip addresses'
filter = "(objectClass=univentionOpenvpnUser)"
attribute = []
modrdn = "1" # first rewrite whole config

action = None

# ----- function to open an textfile with setuid(0) for root-action
def load_rc(ofile):
    l = None
    listener.setuid(0)
    try:
        f = open(ofile,"r")
        l = f.readlines()
        f.close()
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to open "%s": %s' % (ofile, str(e)) )
    listener.unsetuid()
    return l

# ----- function to write to an textfile with setuid(0) for root-action
def write_rc(flist, wfile):
    listener.setuid(0)
    try:
        f = open(wfile,"w")
        f.writelines(flist)
        f.close()
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to write to file "%s": %s' % (wfile, str(e)))
    listener.unsetuid()

def delete_file(fn):
    listener.setuid(0)
    try:
        os.remove(fn)
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to remove file "%s": %s' % (fn, str(e)))
    listener.unsetuid()

def delete_dir(fn):
    listener.setuid(0)
    try:
        os.rmdir(fn)
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to remove file "%s": %s' % (fn, str(e)))
    listener.unsetuid()

# ----- function to open the ip map with setuid(0) for root-action
def load_ip_map(path):
    ip_map = []
    listener.setuid(0)
    try:
        with open(path, 'rb') as f:
            r = csv.reader(f, delimiter=' ', quotechar='|')
            for row in r:
                ip_map.append(row)
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to load ip map: %s' % str(e))
    listener.unsetuid()
    return ip_map

# ----- function to write the ip map with setuid(0) for root-action
def write_ip_map(ip_map, path):
    listener.setuid(0)
    try:
        with open(path, 'wb') as f:
            w = csv.writer(f, delimiter=' ', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for i in ip_map:
                w.writerow(i)
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to write ip map: %s' % str(e))
    listener.unsetuid()

def handler(dn, new, old, command):
    univention.debug.debug(univention.debug.LISTENER, univention.debug.INFO, 'openvpn-server2.handler() invoked')
    global action
    if command == 'n':
        action = None
        return

    myname = listener.baseConfig['hostname']

    listener.setuid(0)
    lo = ul.getBackupConnection()
    server = lo.search('(cn=' + myname + ')')[0]
    listener.unsetuid()
    port = server[1].get('univentionOpenvpnPort', [None])[0]
    network = server[1].get('univentionOpenvpnNet', [None])[0]
    netmask = str(IPNetwork(network).netmask)
    networkv6 = server[1].get('univentionOpenvpnNetIPv6', [None])[0]
    if networkv6 is None:
        networkv6 = "2001:db8:0:123::/64"
    netmaskv6 = str(IPNetwork(networkv6).netmask)

    ccd = '/etc/openvpn/ccd-' + port + '/'
    fn_ips = '/etc/openvpn/ips-' + port
    fn_ipsv6 = '/etc/openvpn/ipsv6-' + port

    if not os.path.exists(ccd):
        os.makedirs(ccd)
        ip_map = load_ip_map(fn_ips)
        for (name, ip) in ip_map:
            line = "ifconfig-push " + ip + " " + netmask
            write_rc(line, ccd + name + ".openvpn")

    if not os.path.exists(fn_ips):
        listener.setuid(0)
        open(fn_ips, 'a').close()
        listener.unsetuid()

    if not os.path.exists(fn_ipsv6):
        listener.setuid(0)
        open(fn_ipsv6, 'a').close()
        listener.unsetuid()

    if command == 'd':
        action = 'restart'
        client_cn = old.get('uid', [None])[0]

        delete_file(ccd + client_cn + ".openvpn")
        delete_file("/var/www/" + client_cn + "/.htaccess")
        delete_file("/var/www/" + client_cn + "/openvpn-" + myname + "-" + client_cn + ".zip")
        delete_dir("/var/www/" + client_cn + "/")

        ip_map_old = load_ip_map(fn_ips)
        ip_map_new = []
        for (name, ip) in ip_map_old:
            if name != client_cn:
                ip_map_new.append((name, ip))
        write_ip_map(ip_map_new, fn_ips)

        ip_map_old = load_ip_map(fn_ipsv6)
        ip_map_new = []
        for (name, ip) in ip_map_old:
            if name != client_cn:
                ip_map_new.append((name, ip))
        write_ip_map(ip_map_new, fn_ipsv6)

        return

    client_cn = new.get('uid', [None])[0]

    if 'univentionOpenvpnAccount' in new and not 'univentionOpenvpnAccount' in old:
        action = 'restart'

        lines = []

        ip_map = load_ip_map(fn_ips)
        ip = generate_ip(network, ip_map)
        ip_map.append((client_cn, ip))
        write_ip_map(ip_map, fn_ips)
        lines.append("ifconfig-push " + ip + " " + netmask + "\n")

        ip_mapv6 = load_ip_map(fn_ipsv6)
        ipv6 = generate_ip(networkv6, ip_mapv6)
        ip_mapv6.append((client_cn, ipv6))
        write_ip_map(ip_mapv6, fn_ipsv6)
        lines.append("ifconfig-ipv6-push " + ipv6 + "/" + networkv6.split('/')[1] + "\n") # TODO: only, if ipv6 enabled?

        write_rc(lines, ccd + client_cn + ".openvpn")

        return

    elif not 'univentionOpenvpnAccount' in new and 'univentionOpenvpnAccount' in old:
        action = 'restart'

        delete_file(ccd + client_cn + ".openvpn")

        ip_map_old = load_ip_map(fn_ips)
        ip_map_new = []
        for (name, ip) in ip_map_old:
            if name != client_cn:
                ip_map_new.append((name, ip))
        write_ip_map(ip_map_new, fn_ips)

        ip_map_old = load_ip_map(fn_ipsv6)
        ip_map_new = []
        for (name, ip) in ip_map_old:
            if name != client_cn:
                ip_map_new.append((name, ip))
        write_ip_map(ip_map_new, fn_ipsv6)

        return

def generate_ip(network, ip_map):
    ips = IPNetwork(network)
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
    univention.debug.debug(univention.debug.LISTENER, univention.debug.INFO, 'OpenVPN-Server %s' % (action))

    try:
        listener.setuid(0)
        listener.run('/etc/init.d/openvpn', ['openvpn', action], uid=0)
    finally:
        listener.unsetuid()

    if action == 'stop':
        # deactivate config
        try:
            listener.setuid(0)
            os.rename (fn_serverconf, fn_serverconf + '-disabled');
        except Exception, e:
            listener.unsetuid()
            univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to deactivate server config: %s' % str(e))
            return

    listener.unsetuid()
