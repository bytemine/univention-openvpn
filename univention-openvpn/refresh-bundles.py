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
from univention_openvpn_common import maxvpnusers


lo = ul.getMachineConnection()

maxu = 5
lobs = lo.search('(univentionOpenvpnLicense=*)')
for lob in lobs:
    key = lob[1].get('univentionOpenvpnLicense', [b''])[0]
    mu = maxvpnusers(0, key)
    if mu > maxu: maxu = mu

vpnusers = lo.search('(univentionOpenvpnAccount=1)')
if len(vpnusers) > maxu:
    exit()

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

### end ###
