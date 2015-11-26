#
#       Univention OpenVPN integration -- openvpn-master.py
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

name        = 'openvpn-master'
description = 'create user openvpn package'
filter      = '(objectClass=univentionOpenvpnUser)'
attributes  = ['univentionOpenvpnAccount']
modrdn      = 1


# called to create (update) bundle for user when openvpn is activated
def handler(dn, new, old, cmd):
    ud.debug(ud.LISTENER, ud.INFO, '1 master handler')

    if cmd == 'n':
        return

    uid = new.get('uid', [None])[0]
    uid_old = old.get('uid', [None])[0]
    home = new.get('homeDirectory', ['/dev/null'])[0]
    home_old = old.get('homeDirectory', ['/dev/null'])[0]
    trigger = 'univentionOpenvpnAccount'

    listener.setuid(0)
    lo = ul.getMachineConnection()
    servers = lo.search('(univentionOpenvpnActive=1)')

    if not univention_openvpn_common.check_user_count():
        listener.unsetuid()
        return			# do nothing

    if trigger in new and not trigger in old and uid and home:
        ud.debug(ud.LISTENER, ud.INFO, '1 create new certificate for %s in %s' % (uid, home))

        # create a bundle for each openvpn server
        for server in servers:
            name = server[1].get('cn', [None])[0]
            port = server[1].get('univentionOpenvpnPort', [None])[0]
            addr = server[1].get('univentionOpenvpnAddress', [None])[0]

            proto = 'udp6' if addr and addr.count(':') else 'udp'

            if not name or not port or not addr:
                continue
            try:
                listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', 'yes', uid, home, name, addr, port, proto], uid=0)
            finally:
                listener.unsetuid()


    if (trigger in old and not trigger in new and uid_old and home_old) or (cmd == 'd' and uid_old and home_old):
        ud.debug(ud.LISTENER, ud.INFO, '1 revoke certificate for %s' % (uid_old))
        listener.setuid(0)
        try:
            listener.run('/usr/sbin/univention-certificate', ['univention-certificate', 'revoke', '-name', uid_old + '.openvpn'], uid=0)
        finally:
            listener.unsetuid()

        # remove bundle for each openvpn server
        for server in servers:
            name = server[1].get('cn', [None])[0]
            if not name:
                continue
            try:
                listener.run('/usr/lib/openvpn-int/remove-bundle', ['remove-bundle', uid_old, home_old, name], uid=0)
            finally:
                listener.unsetuid()

    listener.unsetuid()


### end ###
