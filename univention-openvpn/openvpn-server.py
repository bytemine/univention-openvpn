#
#       Univention OpenVPN integration -- openvpn-server.py
#


__package__ = ''  # workaround for PEP 366

import listener
import univention.debug as ud
import re
import univention_baseconfig
import os
import csv
import univention.uldap as ul
from netaddr import *
from univention.config_registry import ConfigRegistry

from datetime import date
from M2Crypto import RSA, BIO
from base64 import b64decode


name        = 'openvpn-server'
description = 'write server-configuration to server.conf and handle address assignment'
filter      = '(objectClass=univentionOpenvpn)'
attribute   = [
    'univentionOpenvpnActive', 'univentionOpenvpnLicense',
    'univentionOpenvpnPort', 'univentionOpenvpnNet', 'univentionOpenvpnNetIPv6',
    'univentionOpenvpnRedirect', 'univentionOpenvpnDuplicate',
    'univentionOpenvpnFixedAddresses', 'univentionOpenvpnUserAddress' ]
modrdn      = 1

action = None

fn_serverconf = '/etc/openvpn/server.conf'


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
      return None		# invalid license
    raw = raw + pub.public_decrypt(enc, 1)
    #
    items = raw.rstrip().split('\n')
    if not items:
      return None		# invalid license
    vdate = int(items.pop(0))
    if date.today().toordinal() > vdate:
      ud.debug(ud.LISTENER, ud.ERROR, '3 License has expired')
      return None		# expired
    l = {'valid': True}		# at least one feature returned
    while items:
      kv = items.pop(0).split('=', 1)
      kv.append(True)
      l[kv[0]] = kv[1]
    return l			# valid license
  except:
    return None			# invalid license

def maxvpnusers(key):
  mnlu = 5
  try:
    return max(int(license(key)['u']), mnlu)
  except:
    ud.debug(ud.LISTENER, ud.ERROR, '3 Invalid license')
    return mnlu			# invalid license


# function to open a textfile with setuid(0) for root-action
def load_rc(ofile):
    l = None
    listener.setuid(0)
    try:
        f = open(ofile,"r")
        l = f.readlines()
        f.close()
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, '3 Failed to open "%s": %s' % (ofile, str(e)) )
    listener.unsetuid()
    return l

# function to write to a textfile with setuid(0) for root-action
def write_rc(flist, wfile):
    listener.setuid(0)
    try:
        f = open(wfile,"w")
        f.writelines(flist)
        f.close()
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, '3 Failed to write to file "%s": %s' % (wfile, str(e)))
    listener.unsetuid()

# function to create a directory with setuid(0) for root-action
def create_dir(path):
    listener.setuid(0)
    try:
        os.makedirs(path)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, '3 Failed to make directory "%s": %s' % (path, str(e)))
    listener.unsetuid()

# function to rename a directory with setuid(0) for root-action
def rename_dir(pathold, pathnew):
    listener.setuid(0)
    try:
        os.rename(pathold, pathnew)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, '3 Failed to rename directory "%s" to "%s": %s' % (pathold, pathnew, str(e)))
    listener.unsetuid()

# function to delete a textfile with setuid(0) for root-action
def delete_file(fn):
    listener.setuid(0)
    try:
        os.remove(fn)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, '3 Failed to remove file "%s": %s' % (fn, str(e)))
    listener.unsetuid()

# function to open an ip map with setuid(0) for root-action
def load_ip_map(path):
    ip_map = []
    listener.setuid(0)
    try:
        with open(path, 'rb') as f:
            r = csv.reader(f, delimiter=' ', quotechar='|')
            for row in r:
                ip_map.append(row)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, '3 Failed to load ip map: %s' % str(e))
    listener.unsetuid()
    return ip_map

# function to write an ip map with setuid(0) for root-action
def write_ip_map(ip_map, path):
    listener.setuid(0)
    try:
        with open(path, 'wb') as f:
            w = csv.writer(f, delimiter=' ', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for i in ip_map:
                w.writerow(i)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, '3 Failed to write ip map: %s' % str(e))
    listener.unsetuid()

def handler(dn, new, old, command):
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

    listener.setuid(0)
    lo = ul.getAdminConnection()

    vpnusers = lo.search('(univentionOpenvpnAccount=1)')
    vpnuc = len(vpnusers)
    maxu = maxvpnusers(new.get('univentionOpenvpnLicense', [None])[0])
    ud.debug(ud.LISTENER, ud.INFO, '3 found %u active openvpn users (%u allowed)' % (vpnuc, maxu))
    if vpnuc > maxu:
        listener.unsetuid()
        action = None
        ud.debug(ud.LISTENER, ud.INFO, '3 skipping actions')
        return			# do nothing


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

    if portold is not portnew:
        listener.setuid(0)
        ucr = ConfigRegistry()
        ucr.load()
        if portold:
            ucr.update({'security/packetfilter/package/univention-openvpn-server/udp/'+portold+'/all': None})
        if portnew and 'univentionOpenvpnActive' in new:
            ucr.update({'security/packetfilter/package/univention-openvpn-server/udp/'+portnew+'/all': 'ACCEPT'})
        ucr.save()
        listener.unsetuid()

    ccd = '/etc/openvpn/ccd-' + portnew + '/'
    fn_ips = '/etc/openvpn/ips-' + portnew
    fn_ipsv6 = '/etc/openvpn/ipsv6-' + portnew

    # write new server config
    flist = load_rc(fn_serverconf)

    flist = [x for x in flist if not re.search("port", x) and not re.search("push \"redirect-gateway\"", x) and not re.search("duplicate-cn", x) and not re.search("server", x) and not re.search("server-ipv6", x) and not re.search("client-config-dir", x)]

    flist.append("port %s\n" % portnew)

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

    # adapt ip_maps and ccd
    if new.get('univentionOpenvpnNet', [None])[0] != old.get('univentionOpenvpnNet', [None])[0]:
        change_net(network, netmask, ccd, fn_ips, False)

    if new.get('univentionOpenvpnNetIPv6', [None])[0] != old.get('univentionOpenvpnNetIPv6', [None])[0]:
        change_net(networkv6, netmaskv6, ccd, fn_ipsv6, True)

    if new.get('univentionOpenvpnUserAddress', [None]) != old.get('univentionOpenvpnUserAddress', [None]):
        useraddresses_raw = new.get('univentionOpenvpnUserAddress', [None])
        useraddresses_clean = [x for x in useraddresses_raw if x is not None]
        useraddresses = map(lambda x: tuple(x.split(":", 1)), useraddresses_clean)

        useraddressesv4 = []
        useraddressesv6 = []

        for useraddress in useraddresses:
            if IPAddress(useraddress[1]).version == 4:
                useraddressesv4.append(useraddress)
            elif IPAddress(useraddress[1]).version == 6:
                useraddressesv6.append(useraddress)

        assign_addresses(fn_ips, useraddressesv4, network, netmask, ccd, False)
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
    lo = ul.getBackupConnection()
    users = lo.search('univentionOpenvpnAccount=1')
    listener.unsetuid()

    users = map(lambda user: user[1].get('uid', [None])[0], users)

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
        cc = load_rc(ccd + name + ".openvpn")
        if cc is None:
            cc = []
        else:
            cc = [x for x in cc if not re.search(option, x)]
        cc.append(option + " " + ip + appendix)
        write_rc(cc, ccd + name + ".openvpn")

    write_ip_map(ip_map_new, fn_ips)

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
        listener.run('/etc/init.d/openvpn', ['openvpn', 'restart'], uid=0)
        listener.run('/etc/init.d/univention-firewall', ['univention-firewall', 'restart'], uid=0)
        if action == 'restart':
            listener.run('/etc/init.d/display_users', ['display_users', 'restart'], uid=0)
    finally:
        listener.unsetuid()

    listener.unsetuid()


### end ###
