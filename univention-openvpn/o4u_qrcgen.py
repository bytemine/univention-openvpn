#!/usr/bin/env python

import base64
import qrcode

f = open('/etc/openvpn/mfa/secrets')
for l in f:
    try:
        u, s = l.rstrip().split(':')[:2]
        x = qrcode.make('otpauth://totp/bytemine.net:{}?secret={}&issuer=bytemine.net&digits=6'.format(u, s))
        x.save('/var/www/readytogo/{}/qrcode.png'.format(u))
    except:
        print('ignoring line \'{}\''.format(l))
        continue


