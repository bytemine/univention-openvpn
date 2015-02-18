#
#       Univention OpenVPN integration -- openvpn-master.py
#


__package__ = ''  # workaround for PEP 366

import listener
from univention import debug as ud
import univention.uldap as ul

from datetime import date
from M2Crypto import RSA, BIO
from base64 import b64decode


name        = 'openvpn-master'
description = 'create user openvpn package'
filter      = '(objectClass=univentionOpenvpnUser)'
attributes  = ['univentionOpenvpnAccount']
modrdn      = 1


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
      ud.debug(ud.LISTENER, ud.ERROR, '1 License has expired')
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
    ud.debug(ud.LISTENER, ud.ERROR, '1 Invalid license')
    return mnlu			# invalid license


# called to create (update) bundle for user when openvpn is activated
def handler(dn, new, old, cmd):
    ud.debug(ud.LISTENER, ud.INFO, '1 master handler')

    if cmd == 'n':
        return

    uid = new.get('uid', [None])[0]
    home = new.get('homeDirectory', ['/dev/null'])[0]
    trigger = 'univentionOpenvpnAccount'

    listener.setuid(0)
    lo = ul.getAdminConnection()

    servers = lo.search('(univentionOpenvpnActive=1)'):

    vpnusers = lo.search('(univentionOpenvpnAccount=1)')
    vpnuc = len(vpnusers)
    maxu = 0
    for server in servers:
        mu = maxvpnusers(new.get('univentionOpenvpnLicense', [None])[0])
        if mu > maxu: maxu = mu
    ud.debug(ud.LISTENER, ud.INFO, '1 found %u active openvpn users (%u allowed)' % (vpnuc, maxu))
    if vpnuc > maxu:
        listener.unsetuid()
        ud.debug(ud.LISTENER, ud.INFO, '1 skipping actions')
        return			# do nothing

    if trigger in new and not trigger in old and uid and home:
        ud.debug(ud.LISTENER, ud.INFO, '1 create new certificate for %s in %s' % (uid, home))

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
        ud.debug(ud.LISTENER, ud.INFO, '1 revoke certificate for %s' % (uid))
        listener.setuid(0)
        try:
            listener.run('/usr/sbin/univention-certificate', ['univention-certificate', 'revoke', '-name', uid + '.openvpn'], uid=0)
        finally:
            listener.unsetuid()

    listener.unsetuid()


### end ###
