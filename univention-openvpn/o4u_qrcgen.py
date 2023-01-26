#!/usr/bin/env python

import os
import pwd
import grp
import base64
import qrcode
import traceback

f = open('/etc/openvpn/mfa/secrets')
for l in f:
    try:
        u, s = l.rstrip().split(':')[:2]
        q = qrcode.QRCode(box_size=4)
        q.add_data('otpauth://totp/bytemine.net:{}?secret={}&issuer=bytemine.net&digits=6'.format(u, s))
        q.make (fit=True)
        pngpath = '/var/www/readytogo/{}/qrcode.png'.format(u)
        x = q.make_image()
        x.save(pngpath)
        os.chmod(pngpath, 0640)
        uid = pwd.getpwnam(u).pw_uid
        gid = grp.getgrnam('www-data').gr_gid
        os.chown(pngpath, uid, gid)
    except:
        traceback.print_exc()
        print('ignoring line \'{}\''.format(l))
        continue


