#
#       Univention OpenVPN integration -- refresh-bundles.py
#

# Copyright (c) 2016, bytemine GmbH
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



from os import system
import univention.uldap as ul

from datetime import date
from M2Crypto import RSA, BIO
from base64 import b64decode

MAX_UNLIC_USERS = 5


def maxvpnusers(key):
    try:
        return max(int(license(key)['u']), MAX_UNLIC_USERS)
    except:
        return MAX_UNLIC_USERS


def main():
    lo = ul.getMachineConnection()

    lobs = lo.search('(univentionOpenvpnLicense=*)')
    lul = [MAX_UNLIC_USERS]
    for lob in lobs:
        key = lob[1].get('univentionOpenvpnLicense', [b''])[0]
        lul.append(maxvpnusers(key))

    vpnusers = lo.search('(univentionOpenvpnAccount=1)')
    if len(vpnusers) > max(lul):
        exit()

    for user in vpnusers:
        uid = user[1].get('uid', [b''])[0]
        totp = user[1].get('univentionOpenvpnTOTP', [b''])[0]
        if totp and totp !='0':


    vpnservers = lo.search('(&(objectClass=univentionOpenvpn)(univentionOpenvpnActive=1))')
    for (tmp, server) in vpnservers:
        name = server.get('cn', [b''])[0]
        port = server.get('univentionOpenvpnPort', [b''])[0]
        addr = server.get('univentionOpenvpnAddress', [b''])[0]
        if not name or not port or not addr:
            continue
        for user in vpnusers:
            uid = user[1].get('uid', [b''])[0]
            proto = b'udp6' if addr and addr.count(b':') else b'udp'
            if uid:
                system(b'/usr/lib/openvpn-int/create-bundle %s %s %s %s %s' % (uid, name, addr, port, proto))


def license(key):
    enc = b64decode(key)
    raw = ''
    while len(enc) > pbs:
        d, key = (enc[:pbs], enc[pbs:])
        raw = raw + pub.public_decrypt(d, 1).decode('utf8')
    if len(enc) != pbs:
        return None
    raw = raw + pub.public_decrypt(enc, 1).decode('utf8')
    #
    items = raw.rstrip().split('\n')
    if not items:
        return None
    vdate = int(items.pop(0))
    if date.today().toordinal() > vdate:
        return None
    l = {'valid': True, 'vdate': vdate} # at least one feature returned
    while items:
        kv = items.pop(0).split('=', 1)
        kv.append(True)
        l[kv[0]] = kv[1]
    return l


pubbio = BIO.MemoryBuffer(b'''
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAN0VVx22Oou8UTDsrug/UnZLiX2UcXeE
GvQ6kWcXBhqvSUl0cVavYL5Su45RXz7CeoImotwUzrVB8JnsIcrPYw8CAwEAAQ==
-----END PUBLIC KEY-----
''')

if __name__ == '__main__':
    pub = RSA.load_pub_key_bio(pubbio)
    pbs = pub.__len__() / 8
    main()


### end ###
