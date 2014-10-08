#
#       Univention OpenVPN integration -- openvpn-master.py
#


__package__ = ''  # workaround for PEP 366

import listener
from univention import debug as ud
import univention.uldap as ul

name        = 'openvpn-master'
description = 'create user openvpn package'
filter      = '(objectClass=univentionOpenvpnUser)'
attributes  = ['univentionOpenvpnAccount']
modrdn      = 1

# called to create (update) bundle for user when openvpn is activated
def handler(dn, new, old, cmd):
    ud.debug(ud.LISTENER, ud.INFO, 'openvpn-master.handler() invoked')

    if cmd == 'n':
        return

    uid = new.get('uid', [None])[0]
    home = new.get('homeDirectory', [None])[0]
    trigger = 'univentionOpenvpnAccount'

    if trigger in new and not trigger in old and uid and home:
        ud.debug(ud.LISTENER, ud.INFO, 'openvpn/handler: create new certificate for %s in %s' % (uid, home))

        listener.setuid(0)
        lo = ul.getAdminConnection()

    # create a bundle for each openvpn server
        for server in lo.search('(univentionOpenvpnActive=1)'):
            name = server[1].get('cn', [None])[0]
            port = server[1].get('univentionOpenvpnPort', [None])[0]
            addr = server[1].get('univentionOpenvpnAddress', [None])[0]

            if not name or not port or not addr:
                continue
            try:
                listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', 'yes', uid, home, name, addr, port], uid=0)
            finally:
                listener.unsetuid()

    if trigger in old and not trigger in new and uid:
        ud.debug(ud.LISTENER, ud.INFO, 'openvpn/handler: revoke certificate for %s' % (uid))
        listener.setuid(0)
        try:
            listener.run('/usr/sbin/univention-certificate', ['univention-certificate', 'revoke', '-name', uid + '.openvpn'], uid=0)
        finally:
            listener.unsetuid()

    listener.unsetuid()


### end ###
