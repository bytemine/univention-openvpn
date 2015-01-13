#
#       Univention OpenVPN integration -- openvpn-sitetosite.py
#


__package__ = ''  # workaround for PEP 366

import listener
import univention.debug
import re
import univention_baseconfig
import os
import csv
import univention.uldap as ul
from univention.config_registry import handler_set, handler_unset

from datetime import date
from M2Crypto import RSA, BIO
from base64 import b64decode


name        = 'openvpn-sitetosite'
description = 'write configuration to sitetosite.conf'
filter      = '(objectClass=univentionOpenvpnSitetoSite)'
attribute   = ['univentionOpenvpnSitetoSiteActive']
modrdn      = 1

action = None

fn_sitetositeconf = '/etc/openvpn/sitetosite.conf'
fn_secret = '/etc/openvpn/sitetosite.key'


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
      return None		# expired 
    l = {'valid': True}
    while items:
      kv = items.pop(0).split('=', 1)
      kv.append(True)
      l[kv[0]] = kv[1]
    return l
  except:
    return None			# invalid license



# function to open a textfile with setuid(0) for root-action
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

# function to write to a textfile with setuid(0) for root-action
def write_rc(flist, wfile):
    listener.setuid(0)
    try:
        f = open(wfile,"w")
        f.writelines(flist)
        f.close()
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to write to file "%s": %s' % (wfile, str(e)))
    listener.unsetuid()

# function to create a directory with setuid(0) for root-action
def create_dir(path):
    listener.setuid(0)
    try:
        os.makedirs(path)
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to make directory "%s": %s' % (path, str(e)))
    listener.unsetuid()

# function to rename a directory with setuid(0) for root-action
def rename_dir(pathold, pathnew):
    listener.setuid(0)
    try:
        os.rename(pathold, pathnew)
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to rename directory "%s" to "%s": %s' % (pathold, pathnew, str(e)))
    listener.unsetuid()

# function to delete a textfile with setuid(0) for root-action
def delete_file(fn):
    listener.setuid(0)
    try:
        os.remove(fn)
    except Exception, e:
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to remove file "%s": %s' % (fn, str(e)))
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
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to load ip map: %s' % str(e))
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
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to write ip map: %s' % str(e))
    listener.unsetuid()

def handler(dn, new, old, command):
    global action
    if command == 'n':
        action = None
        return

    cn = new.get('cn', [None])[0]
    myname = listener.baseConfig['hostname']
    if cn != myname:
        action = None
        return

    univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'new: %s' % str(new))
    # check if license is valid whenever 'active' is set
    if 'univentionOpenvpnSitetoSiteActive' in new:
        key = new.get('univentionOpenvpnLicense', [None])[0]
	if not key:
            univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'No license key.')
            action = None
            return
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Key = %s' % key)
        lic = license(key)
        if not lic:
            univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Invalid license.')
            action = None
            return
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'LIC: %s' % str(lic))
        if not lic['valid']:
            univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'License has expired.')
            action = None
            return
        if not lic['s2s']:
            univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'License does not contain site-to-site.')
            action = None
            return
        univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, '** LICENSE VALID, WITH S2S FEATRUE, OK')

    if 'univentionOpenvpnSitetoSiteActive' in new:
        action = 'restart'
    else:
        action = 'stop'

    # activate config
    if not 'univentionOpenvpnSitetoSiteActive' in old and os.path.exists(fn_sitetositeconf + '-disabled'):
        listener.setuid(0)
        try:
            os.rename (fn_sitetositeconf + '-disabled', fn_sitetositeconf)
        except Exception, e:
            listener.unsetuid()
            univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to activate site-to-site config: %s' % str(e))
            return
        listener.unsetuid()

    if not os.path.exists(fn_sitetositeconf):
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
plugin /usr/lib/openvpn/openvpn-auth-pam.so /etc/pam.d/kcheckpass
dev tun
secret {fn_secret}

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
            'dodom' : dodom,
            'fn_secret' : fn_secret
        }

        write_rc(config.format(**context), fn_sitetositeconf)


    portold = old.get('univentionOpenvpnSitetoSitePort', [None])[0]
    portnew = new.get('univentionOpenvpnSitetoSitePort', [None])[0]

    if portold is not portnew:
        listener.setuid(0)
        if portold:
            handler_unset(["security/packetfilter/package/univention-openvpn-sitetosite/udp/" + portold + "/all"])
        if portnew and 'univentionOpenvpnSitetoSiteActive' in new:
            handler_set(["security/packetfilter/package/univention-openvpn-sitetosite/udp/" + portnew + "/all=ACCEPT"])
        listener.unsetuid()

    # write new sitetosite config
    flist = load_rc(fn_sitetositeconf)

    flist = [x for x in flist if not re.search("remote", x) and not re.search("port", x) and not re.search("ifconfig", x)]

    flist.append("port %s\n" % portnew)

    remote = new.get('univentionOpenvpnRemote', [None])[0]
    flist.append("remote %s\n" % remote)

    localaddress = new.get('univentionOpenvpnLocalAddress', [None])[0]
    remoteaddress = new.get('univentionOpenvpnRemoteAddress', [None])[0]
    flist.append("ifconfig %s %s\n" % (localaddress, remoteaddress))

    secret = new.get('univentionOpenvpnSecret', [None])[0]
    univention.debug.debug(univention.debug.LISTENER, univention.debug.INFO, 'secret: %s' % (secret))
    write_rc([secret], fn_secret)

    write_rc(flist, fn_sitetositeconf)

def initialize():
    pass

def postrun():
    global action
    if not action:
        return
    univention.debug.debug(univention.debug.LISTENER, univention.debug.INFO, 'OpenVPN-Server Site-to-Site %s' % (action))

    if action == 'stop':
        # deactivate config
        try:
            listener.setuid(0)
            os.rename (fn_sitetositeconf, fn_sitetositeconf + '-disabled')
        except Exception, e:
            listener.unsetuid()
            univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to deactivate site-to-site config: %s' % str(e))
            return

    try:
        listener.setuid(0)
        listener.run('/etc/init.d/openvpn', ['openvpn', 'restart'], uid=0)
        listener.run('/etc/init.d/univention-firewall', ['univention-firewall', 'restart'], uid=0)
    finally:
        listener.unsetuid()

    listener.unsetuid()


### end ###
