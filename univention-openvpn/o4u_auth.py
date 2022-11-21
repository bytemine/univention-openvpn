#!/usr/bin/env python

import sys
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

    return ores and pres


def pamauth(user, pwstr):
    a = pam.pam()
    return a.authenticate(user, pwstr)


def main():
    try:
        f = open(sys.argv[1])
        creds = f.read()
        f.close()

        lines = creds.split('\n')
        user = lines[0]
        pwstr = lines[1]

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

        exit(0 if ares else 1)
    except:
        exit(1)


if __name__ == '__main__':
    main()
