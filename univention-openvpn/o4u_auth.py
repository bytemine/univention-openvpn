#!/usr/bin/env python

import sys
import syslog
import os
import pam
import pyotp
import base64


def mfaauth(user, pwstr, secret):
    if pwstr.startswith('SCRV1:'):
        # client config uses 'static-challenge'
        pwd, otp = pwstr.split(':')[1:]
        pwd = base64.b64decode(pwd)
        otp = base64.b64decode(otp)
    else:
        # user appends totp digits to password
        pwd = pwstr[:-6]
        otp = pwstr[-6:]

    # check totp first, since pam auth may take several seconds
    totp = pyotp.TOTP(secret)
    ores = totp.verify(otp)
    pres = pamauth(user, pwd)

    if pres and not ores:
        syslog.syslog(syslog.LOG_NOTICE, 'user \'{}\' TOTP mismatch'.format(user))

    return ores and pres


def pamauth(user, pwstr):
    a = pam.pam()
    r = a.authenticate(user, pwstr)
    if not r:
        syslog.syslog(syslog.LOG_NOTICE, 'user \'{}\' password mismatch'.format(user))
    return r


def main():
    user = ''
    try:
        f = open(sys.argv[1])
        creds = f.read()
        f.close()

        lines = creds.split('\n')
        user = lines[0]
        pwstr = lines[1]

        cn = os.environ.get('common_name')
        if user != cn:
            syslog.syslog(syslog.LOG_NOTICE, 'user \'{}\' cert mismatch ({})'.format(user, cn))
            return 1

        # check if user has totp configured
        secret = None
        try:
            f = open('/etc/openvpn/mfa/secrets')
            for l in f:
                try:
                    u, s = l.rstrip().split(':')[:2]
                except:
                    u = ''
                    pass
                if user == u:
                    secret = s
        except:
            pass

        ares = mfaauth(user, pwstr, secret) if secret else pamauth(user, pwstr)

        return 0 if ares else 1
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, 'user {:.32} {}'.format(repr(user), e))
        return 1


if __name__ == '__main__':
    syslog.openlog('openvpn4ucs/auth', 0, syslog.LOG_AUTH)
    exit(main())
