#
#       Univention OpenVPN integration -- openvpn-server.py
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

name = "openvpn-server"
description = "write server-configuration to server.conf"
filter = "(objectClass=univentionOpenvpn)"
attribute = ['univentionOpenvpnActive']
modrdn = "1" # first rewrite whole config

fn_serverconf = '/etc/openvpn/server.conf'

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

def create_dir(path):
    listener.setuid(0)
    try:
        os.makedirs(path)
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to make directory "%s"' % path)
    listener.unsetuid()

def rename_dir(pathold, pathnew):
    listener.setuid(0)
    try:
        os.rename(pathold, pathnew)
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to rename directory "%s" to "%s"' % (pathold, pathnew))
    listener.unsetuid()

def delete_file(fn):
        listener.setuid(0)
        try:
                os.remove(fn)
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
    univention.debug.debug(univention.debug.LISTENER, univention.debug.INFO, 'openvpn-server.handler() invoked')
    global action
    if command == 'n':
        action = None
        return

    cn = new.get('cn', [None])[0]
    myname = listener.baseConfig['hostname']
    if cn != myname:
        action = None
        return;

    if 'univentionOpenvpnActive' in new:
        action = 'restart'

                # activate config
        if not 'univentionOpenvpnActive' in old:
            listener.setuid(0)
            try:
                os.rename (fn_serverconf + '-disabled', fn_serverconf);
            except Exception, e:
                listener.unsetuid()
                univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to activate server config: %s' % str(e))
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
plugin /usr/lib/openvpn/openvpn-auth-pam.so /etc/pam.d/kcheckpass
dev tun
topology subnet

### Values which can be changed through UDM

server 10.0.1.0 255.255.255.0
port 443
push "redirect-gateway"
"""

            interfaces_eth0_network = listener.baseConfig['interfaces/eth0/network']
            interfaces_eth0_netmask = listener.baseConfig['interfaces/eth0/netmask']
            nameserver1 = listener.baseConfig['nameserver1']
            domain_domainname = listener.baseConfig['domain/domainname']
            domainname = listener.baseConfig['domainname']

            if domain_domainname != None:
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

            write_rc(config.format(**context), fn_serverconf) 


        portold = old.get('univentionOpenvpnPort', [None])[0]
        portnew = new.get('univentionOpenvpnPort', [None])[0]

        ccd = '/etc/openvpn/ccd-' + portnew + '/'
        fn_ips = '/etc/openvpn/ips-' + portnew
        fn_ipsv6 = '/etc/openvpn/ipsv6-' + portnew

        flist = load_rc(fn_serverconf)

        flist = [x for x in flist if not re.search("port", x) and not re.search("push \"redirect-gateway\"", x) and not re.search("duplicate-cn", x) and not re.search("server", x) and not re.search("server-ipv6", x) and not re.search("client-config-dir", x)]

        flist.append("port %s\n" % new.get('univentionOpenvpnPort', [None])[0])

        network = new.get('univentionOpenvpnNet', [None])[0]
        network_pure = str(IPNetwork(network).network)
        netmask = str(IPNetwork(network).netmask)
        flist.append("server %s %s\n" % (network_pure, netmask))

        networkv6 = new.get('univentionOpenvpnNetIPv6', [None])[0]
        if networkv6 is not None:
            flist.append("server-ipv6 %s\n" % (networkv6))
        else:
            networkv6 = "2001:db8:0:123::/64"
        netmaskv6 = str(IPNetwork(networkv6).netmask)

        redirect = new.get('univentionOpenvpnRedirect', [None])[0]
        if redirect == '1':
            flist.append('push "redirect-gateway"\n')

        duplicate = new.get('univentionOpenvpnDuplicate', [None])[0]
        if duplicate == '1':
            flist.append('duplicate-cn\n')

        fixedaddresses = new.get('univentionOpenvpnFixedAddresses', [None])[0]
        if fixedaddresses == '1':
            flist.append('client-config-dir %s\n' % ccd)

        write_rc(flist, fn_serverconf)

        if not os.path.exists(ccd):
            if not os.path.exists('/etc/openvpn/ccd-%s' % portold):
                create_dir(ccd)
            else:
                rename_dir('/etc/openvpn/ccd-%s' % portold, '/etc/openvpn/ccd-%s' % portnew)

        if not os.path.exists(fn_ips):
            listener.setuid(0)
            open(fn_ips, 'a').close()
            listener.unsetuid()

        if not os.path.exists(fn_ipsv6):
            listener.setuid(0)
            open(fn_ipsv6, 'a').close()
            listener.unsetuid()


        if new.get('univentionOpenvpnNet', [None])[0] != old.get('univentionOpenvpnNet', [None])[0]:
            ip_map_new = []
            listener.setuid(0)
            lo = ul.getBackupConnection()
            users = lo.search('univentionOpenvpnAccount=1')
            listener.unsetuid()

            users = map(lambda user: user[1].get('uid', [None])[0], users)

            for name in users:
                ip_new = generate_ip(network, ip_map_new)
                ip_map_new.append((name, ip_new))

                cc = load_rc(ccd + name + ".openvpn")
                if cc is None:
                    cc = []
                else:
                    cc = [x for x in cc if not re.search("ifconfig-push", x)]
                cc.append("ifconfig-push " + ip_new + " " + netmask + "\n")
                write_rc(cc, ccd + name + ".openvpn")

            write_ip_map(ip_map_new, fn_ips)

        if new.get('univentionOpenvpnNetIPv6', [None])[0] != old.get('univentionOpenvpnNetIPv6', [None])[0] and networkv6 is not None:
            ip_map_new = []
            listener.setuid(0)
            lo = ul.getBackupConnection()
            users = lo.search('univentionOpenvpnAccount=1')
            listener.unsetuid()

            users = map(lambda user: user[1].get('uid', [None])[0], users)

            for name in users:
                ip_new = generate_ip(networkv6, ip_map_new)
                ip_map_new.append((name, ip_new))

                cc = load_rc(ccd + name + ".openvpn")
                if cc is None:
                    cc = []
                else:
                    cc = [x for x in cc if not re.search("ifconfig-ipv6-push", x)]
                cc.append("ifconfig-ipv6-push " + ip_new + "/" + networkv6.split('/')[1] + "\n")
                write_rc(cc, ccd + name + ".openvpn")

            write_ip_map(ip_map_new, fn_ipsv6)

        if new.get('univentionOpenvpnUserAddress', [None]) != old.get('univentionOpenvpnUserAddress', [None]):

            ip_map_old = load_ip_map(fn_ips)
            ipv6_map_old = load_ip_map(fn_ipsv6)

            useraddresses_raw = new.get('univentionOpenvpnUserAddress', [None])
            useraddresses_clean = [x for x in useraddresses_raw if x is not None]
            useraddresses = map(lambda x: tuple(x.split(":", 2)), useraddresses_clean)

            ip_map_new = map(lambda (name, ipv4, ipv6): (name, ipv4), useraddresses)
            ipv6_map_new = map(lambda (name, ipv4, ipv6): (name, ipv6), useraddresses)

            # ipv4

            lost_users = []

            for (name, ip) in ip_map_old:
                if not name in map(lambda (u,i): u, ip_map_new):
                    if not ip in map(lambda (u,i): i, ip_map_new):
                        ip_map_new.append((name, ip))
                    else:
                        lost_users.append(name)

            for name in lost_users:
                ip_new = generate_ip(network, ip_map_new)
                ip_map_new.append((name, ip_new))

            for (name, ip) in ip_map_new:
                cc = load_rc(ccd + name + ".openvpn")
                if cc is None:
                    cc = []
                else:
                    cc = [x for x in cc if not re.search("ifconfig-push", x)]
                cc.append("ifconfig-push " + ip + " " + netmask + "\n")
                write_rc(cc, ccd + name + ".openvpn")

            write_ip_map(ip_map_new, fn_ips)

            # ipv6

            lost_users = []

            for (name, ip) in ipv6_map_old:
                if not name in map(lambda (u,i): u, ipv6_map_new):
                    if not ip in map(lambda (u,i): i, ipv6_map_new):
                        ipv6_map_new.append((name, ip))
                    else:
                        lost_users.append(name)

            for name in lost_users:
                ip_new = generate_ip(networkv6, ipv6_map_new)
                ipv6_map_new.append((name, ip_new))

            for (name, ip) in ipv6_map_new:
                cc = load_rc(ccd + name + ".openvpn")
                if cc is None:
                    cc = []
                else:
                    cc = [x for x in cc if not re.search("ifconfig-ipv6-push", x)]
                cc.append("ifconfig-ipv6-push " + ip + "/" + networkv6.split('/')[1] + "\n")
                write_rc(cc, ccd + name + ".openvpn")

            write_ip_map(ipv6_map_new, fn_ipsv6)

    else:

        if 'univentionOpenvpnActive' in old:
            action = 'stop'
        else:
            action = None

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




