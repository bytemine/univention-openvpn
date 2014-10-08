#
#       Univention OpenVPN integration -- openvpn-master2.py
#


__package__ = ''  # workaround for PEP 366

import listener
from univention import debug as ud
import univention.uldap as ul

name        = 'openvpn-master2'
description = 'create user openvpn package with updated config'
filter      = '(&(objectClass=univentionOpenvpn)(univentionOpenvpnActive=1))'
attributes  = ['univentionOpenvpnPort', 'univentionOpenvpnAddress']
modrdn      = 1

# called to create (update) bundle for user when openvpn is activated
def handler(dn, new, old, cmd):
    ud.debug(ud.LISTENER, ud.INFO, 'openvpn-master2.handler() invoked')

    if cmd == 'n':
        return

    name = new.get('cn', [None])[0]
    port = new.get('univentionOpenvpnPort', [None])[0]
    addr = new.get('univentionOpenvpnAddress', [None])[0]

    if not name or not port or not addr:
        return

    listener.setuid(0)
    lo = ul.getAdminConnection()

    for user in lo.search('(univentionOpenvpnAccount=1)'):
        uid = user[1].get('uid', [None])[0]
        home = user[1].get('homeDirectory', [None])[0]
        ud.debug(ud.LISTENER, ud.INFO, 'openvpn/handler: create new certificate for %s in %s' % (uid, home))

        if uid and home:
        # update bundle for this openvpn server with new config
            try:
                listener.run('/usr/lib/openvpn-int/create-bundle', ['create-bundle', 'no', uid, home, name, addr, port], uid=0)
            finally:
                listener.unsetuid()

    listener.unsetuid()


### end ###
