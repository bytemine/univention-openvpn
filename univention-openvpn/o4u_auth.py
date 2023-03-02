#!/usr/bin/env python

import sys
import syslog
import os
import pam
import pyotp
import base64
from time import sleep

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

    if not ores:
        syslog.syslog(syslog.LOG_NOTICE, 'user \'{}\' TOTP mismatch'.format(repr(user)))

    return ores and pres


def pamauth(user, pwstr):
    a = pam.pam()
    r = a.authenticate(user, pwstr)
    if not r:
        syslog.syslog(syslog.LOG_NOTICE, 'user \'{}\' password mismatch'.format(repr(user)))
    return r


def main():
    user = ''
    try:
        with open(sys.argv[1]) as f:
            creds = f.read()

        lines = creds.split('\n')
        user = lines[0][:64]
        pwstr = lines[1][:64]

        cn = os.environ.get('common_name')
        if user + '.openvpn' != cn:
            syslog.syslog(syslog.LOG_NOTICE, 'user \'{}\' cert mismatch ({})'.format(repr(user), cn))
            sleep(3)
            return 1

        # check if user has totp configured
        secret = None
        try:
            with open('/etc/openvpn/mfa/secrets') as f:
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
        syslog.syslog(syslog.LOG_ERR, 'user {} {}'.format(repr(user), e))
        sleep(3)
        return 1


if __name__ == '__main__':
    syslog.openlog('openvpn4ucs/auth', 0, syslog.LOG_AUTH)
    exit(main())
