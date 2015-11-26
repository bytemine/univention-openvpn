from univention import debug as ud
import univention.uldap as ul
import listener
import os
import csv

from datetime import date
from M2Crypto import RSA, BIO
from base64 import b64decode

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
            ud.debug(ud.LISTENER, ud.ERROR, 'License has expired')
            return None		# expired
        l = {'valid': True, 'vdate': vdate} # at least one feature returned
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
        ud.debug(ud.LISTENER, ud.ERROR, 'Invalid license')
        return mnlu			# invalid license


# function to open a textfile with setuid(0) for root-action
def load_rc(ofile):
    l = None
    listener.setuid(0)
    try:
        f = open(ofile,"r")
        l = f.readlines()
        f.close()
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, 'Failed to open "%s": %s' % (ofile, str(e)) )
    listener.unsetuid()
    return l

# function to write to a textfile with setuid(0) for root-action
def write_rc(flist, wfile):
    listener.setuid(0)
    try:
        f = open(wfile,"w")
        f.writelines(flist)
        f.close()
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, 'Failed to write to file "%s": %s' % (wfile, str(e)))
    listener.unsetuid()

# function to create a directory with setuid(0) for root-action
def create_dir(path):
    listener.setuid(0)
    try:
        os.makedirs(path)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, 'Failed to make directory "%s": %s' % (path, str(e)))
    listener.unsetuid()

# function to rename a directory with setuid(0) for root-action
def rename_dir(pathold, pathnew):
    listener.setuid(0)
    try:
        os.rename(pathold, pathnew)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, 'Failed to rename directory "%s" to "%s": %s' % (pathold, pathnew, str(e)))
    listener.unsetuid()

# function to delete a directory with setuid(0) for root-action
def delete_dir(fn):
    listener.setuid(0)
    try:
        os.rmdir(fn)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, 'Failed to remove file "%s": %s' % (fn, str(e)))
    listener.unsetuid()

# function to delete a textfile with setuid(0) for root-action
def delete_file(fn):
    listener.setuid(0)
    try:
        os.remove(fn)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, 'Failed to remove file "%s": %s' % (fn, str(e)))
    listener.unsetuid()

# function to open an ip map with setuid(0) for root-action
def load_ip_map(path):
    ip_map = []
    listener.setuid(0)
    try:
        with open(path, 'rb') as f:
            r = csv.reader(f, delimiter=' ', quotechar='|')
            for row in r:
                ip_map.append(row)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, 'Failed to load ip map: %s' % str(e))
    listener.unsetuid()
    return ip_map

# function to write an ip map with setuid(0) for root-action
def write_ip_map(ip_map, path):
    listener.setuid(0)
    try:
        with open(path, 'wb') as f:
            w = csv.writer(f, delimiter=' ', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for i in ip_map:
                w.writerow(i)
    except Exception, e:
        ud.debug(ud.LISTENER, ud.ERROR, 'Failed to write ip map: %s' % str(e))
    listener.unsetuid()

def check_user_count():
    listener.setuid(0)
    lo = ul.getMachineConnection()

    servers = lo.search('(univentionOpenvpnActive=1)')

    vpnusers = lo.search('(univentionOpenvpnAccount=1)')
    vpnuc = len(vpnusers)
    maxu = 0
    for server in servers:
        key = server[1].get('univentionOpenvpnLicense', [None])[0]
        try:
            l = license(key)
            ud.debug(ud.LISTENER, ud.INFO, 'Processing license with ID %s:' % l['id'])
            ud.debug(ud.LISTENER, ud.INFO, 'Valid until: %s' % date.fromordinal(l['vdate']))
            ud.debug(ud.LISTENER, ud.INFO, 'Users: %s' % l['u'])
            ud.debug(ud.LISTENER, ud.INFO, 'Site-2-Site: %s' % l['s2s'])
        except:
            pass
        mu = maxvpnusers(key)
        if mu > maxu: maxu = mu
    ud.debug(ud.LISTENER, ud.INFO, 'found %u active openvpn users (%u allowed)' % (vpnuc, maxu))
    listener.unsetuid()
    if vpnuc > maxu:
        ud.debug(ud.LISTENER, ud.INFO, 'skipping actions')
        return False
    else:
        return True
