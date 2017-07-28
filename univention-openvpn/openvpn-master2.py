#
#       Univention OpenVPN integration -- openvpn-master2.py
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
from univention import debug as ud
import univention.uldap as ul

from datetime import date

import univention_openvpn_common


name        = 'openvpn-master2'
description = 'create user openvpn package with updated config'
filter      = '(&(objectClass=univentionOpenvpn)(univentionOpenvpnActive=1))'
attributes  = ['univentionOpenvpnPort', 'univentionOpenvpnAddress', 'univentionOpenvpnActive']
modrdn      = 1


# called to create (update) bundle for user when openvpn is activated
def handler(dn, new, old, cmd):
    ud.debug(ud.LISTENER, ud.INFO, '2 master2 handler')

    if cmd == 'n':
        return

    name = new.get('cn', [None])[0]
    port = new.get('univentionOpenvpnPort', [None])[0]
    addr = new.get('univentionOpenvpnAddress', [None])[0]

    if not name or not port or not addr:
        return

    listener.setuid(0)
    lo = ul.getMachineConnection()
    vpnusers = lo.search('(univentionOpenvpnAccount=1)')

    if not univention_openvpn_common.check_user_count(2):                                                                                                                                                                                 
        return          # do nothing

    for user in vpnusers:
        uid = user[1].get('uid', [None])[0]
        ud.debug(ud.LISTENER, ud.INFO, '2 Create new certificate for %s' % uid)

        proto = 'udp6' if addr and addr.count(':') else 'udp'

        if uid:
        # update bundle for this openvpn server with new config
            try:
                listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', uid, name, addr, port, proto], uid=0)
            finally:
                listener.unsetuid()

    listener.unsetuid()


### end ###
