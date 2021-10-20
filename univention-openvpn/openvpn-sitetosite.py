#
#       Univention OpenVPN integration -- openvpn-sitetosite.py
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

from datetime import date

import univention_openvpn_common


name        = 'openvpn-sitetosite'
description = 'write configuration to sitetosite.conf'
filter      = '(objectClass=univentionOpenvpnSitetoSite)'
attributes  = [
    'univentionOpenvpnSitetoSiteActive', 'univentionOpenvpnLicense',
    'univentionOpenvpnSitetoSitePort', 'univentionOpenvpnRemote',
    'univentionOpenvpnLocalAddress', 'univentionOpenvpnRemoteAddress',
    'univentionOpenvpnSecret']
modrdn      = 1

action = None

fn_sitetositeconf = '/etc/openvpn/sitetosite.conf'
fn_secret = '/etc/openvpn/sitetosite.key'


def handler(dn, new, old, command):
    ud.debug(ud.LISTENER, ud.INFO, '5 site2site handler')
    global action
    if command == 'n':
        action = None
        return

    if 'univentionOpenvpnSitetoSiteActive' in new:
        action = 'restart'
    else:
        action = 'stop'

    cn = new.get('cn', [None])[0]
    myname = listener.baseConfig['hostname']
    if cn != myname:
        action = None
        return

    # check if license is valid whenever 'active' is set
    if not univention_openvpn_common.check_sitetosite(5):
        if action == 'stop':
            ud.debug(ud.LISTENER, ud.INFO, '5 Allowing stop action')
        else:
            action = None
            return

    # activate config
    if not 'univentionOpenvpnSitetoSiteActive' in old and os.path.exists(fn_sitetositeconf + '-disabled'):
        listener.setuid(0)
        try:
            os.rename (fn_sitetositeconf + '-disabled', fn_sitetositeconf)
        except Exception as e:
            listener.unsetuid()
            ud.debug(ud.LISTENER, ud.ERROR, '5 Failed to activate site-to-site config: %s' % str(e))
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


    portold = old.get('univentionOpenvpnSitetoSitePort', [None])[0]
    portnew = new.get('univentionOpenvpnSitetoSitePort', [None])[0]

    if portold is not portnew:
        listener.setuid(0)
        #ucr.ConfigRegistry().load()
        #ucr.load()
        if portold:
            ucr.handler_unset(['security/packetfilter/package/univention-openvpn-sitetosite/udp/'+portold+'/all'])
        if portnew and 'univentionOpenvpnSitetoSiteActive' in new:
            ucr.handler_set(['security/packetfilter/package/univention-openvpn-sitetosite/udp/'+portnew+'/all=ACCEPT'])
        listener.unsetuid()

    # write new sitetosite config
    flist = univention_openvpn_common.load_rc(5, fn_sitetositeconf)

    flist = [x for x in flist if not re.search("remote", x) and not re.search("port", x) and not re.search("ifconfig", x)]

    flist.append("port %s\n" % portnew)

    remote = new.get('univentionOpenvpnRemote', [None])[0]
    flist.append("remote %s\n" % remote)

    localaddress = new.get('univentionOpenvpnLocalAddress', [None])[0]
    remoteaddress = new.get('univentionOpenvpnRemoteAddress', [None])[0]
    flist.append("ifconfig %s %s\n" % (localaddress, remoteaddress))

    secret = new.get('univentionOpenvpnSecret', [None])[0]
    #ud.debug(ud.LISTENER, ud.INFO, '5 secret: %s' % (secret))
    univention_openvpn_common.write_rc(5, [secret] if secret else [''], fn_secret)
    listener.setuid(0)
    os.chmod(fn_secret, 0o600)
    listener.unsetuid()

    univention_openvpn_common.write_rc(5, flist, fn_sitetositeconf)

def initialize():
    pass

def postrun():
    global action
    if not action:
        return
    ud.debug(ud.LISTENER, ud.INFO, '5 OpenVPN-Server Site-to-Site %s' % (action))

    if action == 'stop':
        # deactivate config
        try:
            listener.setuid(0)
            os.rename (fn_sitetositeconf, fn_sitetositeconf + '-disabled')
        except Exception as e:
            listener.unsetuid()
            ud.debug(ud.LISTENER, ud.ERROR, '5 Failed to deactivate site-to-site config: %s' % str(e))
            return

    if os.path.exists(fn_sitetositeconf):
        try:
            listener.setuid(0)
            listener.run('/bin/systemctl', ['systemctl', 'restart', 'openvpn@sitetosite.service'], uid=0)
            listener.run('/etc/init.d/univention-firewall', ['univention-firewall', 'restart'], uid=0)
        finally:
            listener.unsetuid()

    listener.unsetuid()


### end ###
