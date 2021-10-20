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

def license(no, key):
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
            ud.debug(ud.LISTENER, ud.ERROR, '%d License has expired' % no)
            return None		# expired
        l = {'valid': True, 'vdate': vdate} # at least one feature returned
        while items:
            kv = items.pop(0).split('=', 1)
            kv.append(True)
            l[kv[0]] = kv[1]
        return l			# valid license
    except:
        return None			# invalid license

def maxvpnusers(no, key):
    mnlu = 5
    try:
        return max(int(license(no, key)['u']), mnlu)
    except:
        ud.debug(ud.LISTENER, ud.ERROR, '%d Invalid license' % no)
        return mnlu			# invalid license


# function to open a textfile with setuid(0) for root-action
def load_rc(no, ofile):
    l = None
    listener.setuid(0)
    try:
        f = open(ofile,"r")
        l = f.readlines()
        f.close()
    except Exception as e:
        ud.debug(ud.LISTENER, ud.ERROR, '%d Failed to read file "%s": %s' % (no, ofile, str(e)) )
    listener.unsetuid()
    return l

# function to write to a textfile with setuid(0) for root-action
def write_rc(no, flist, wfile):
    listener.setuid(0)
    try:
        f = open(wfile,"w")
        f.writelines(flist)
        f.close()
    except Exception as e:
        ud.debug(ud.LISTENER, ud.ERROR, '%d Failed to write file "%s": %s' % (no, wfile, str(e)))
    listener.unsetuid()

# function to create a directory with setuid(0) for root-action
def create_dir(no, path):
    listener.setuid(0)
    try:
        os.makedirs(path)
    except Exception as e:
        ud.debug(ud.LISTENER, ud.ERROR, '%d Failed to make directory "%s": %s' % (no, path, str(e)))
    listener.unsetuid()

# function to rename a directory with setuid(0) for root-action
def rename_dir(no, pathold, pathnew):
    listener.setuid(0)
    try:
        os.rename(pathold, pathnew)
    except Exception as e:
        ud.debug(ud.LISTENER, ud.ERROR, '%d Failed to rename directory "%s" to "%s": %s' % (no, pathold, pathnew, str(e)))
    listener.unsetuid()

# function to delete a directory with setuid(0) for root-action
def delete_dir(no, fn):
    listener.setuid(0)
    try:
        os.rmdir(fn)
    except Exception as e:
        ud.debug(ud.LISTENER, ud.ERROR, '%d Failed to remove directory "%s": %s' % (no, fn, str(e)))
    listener.unsetuid()

# function to delete a textfile with setuid(0) for root-action
def delete_file(no, fn):
    listener.setuid(0)
    try:
        os.remove(fn)
    except Exception as e:
        ud.debug(ud.LISTENER, ud.ERROR, '%d Failed to remove file "%s": %s' % (no, fn, str(e)))
    listener.unsetuid()

# function to open an ip map with setuid(0) for root-action
def load_ip_map(no, path):
    ip_map = []
    listener.setuid(0)
    try:
        with open(path, 'rb') as f:
            r = csv.reader(f, delimiter=' ', quotechar='|')
            for row in r:
                ip_map.append(row)
    except Exception as e:
        ud.debug(ud.LISTENER, ud.ERROR, '%d Failed to load ip map: %s' % (no, str(e)))
    listener.unsetuid()
    return ip_map

# function to write an ip map with setuid(0) for root-action
def write_ip_map(no, ip_map, path):
    listener.setuid(0)
    try:
        with open(path, 'wb') as f:
            w = csv.writer(f, delimiter=' ', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for i in ip_map:
                w.writerow(i)
    except Exception as e:
        ud.debug(ud.LISTENER, ud.ERROR, '%d Failed to write ip map: %s' % (no, str(e)))
    listener.unsetuid()

def check_user_count(no):
    listener.setuid(0)
    lo = ul.getMachineConnection()

    servers = lo.search('(univentionOpenvpnLicense=*)')

    vpnusers = lo.search('(univentionOpenvpnAccount=1)')
    vpnuc = len(vpnusers)
    maxu = 5
    for server in servers:
        key = server[1].get('univentionOpenvpnLicense', [None])[0]
        try:
            l = license(no, key)
            ud.debug(ud.LISTENER, ud.INFO, '%d Processing license with ID %s:' % (no, l['id']))
            ud.debug(ud.LISTENER, ud.INFO, '%d Valid until: %s' % (no, date.fromordinal(l['vdate'])))
            ud.debug(ud.LISTENER, ud.INFO, '%d Users: %s' % (no, l['u']))
            ud.debug(ud.LISTENER, ud.INFO, '%d Site-2-Site: %s' % (no, l['s2s']))
        except:
            pass
        mu = maxvpnusers(no, key)
        if mu > maxu: maxu = mu
    ud.debug(ud.LISTENER, ud.INFO, '%d Found %u active openvpn users (%u allowed)' % (no, vpnuc, maxu))
    listener.unsetuid()
    if vpnuc > maxu:
        ud.debug(ud.LISTENER, ud.INFO, '%d Skipping actions' % no)
        return False
    else:
        return True

def check_sitetosite(no):
    listener.setuid(0)
    lo = ul.getMachineConnection()

    servers = lo.search('(univentionOpenvpnLicense=*)')

    sitetosite = False
    for server in servers:
        key = server[1].get('univentionOpenvpnLicense', [None])[0]
        try:
            l = license(no, key)
            ud.debug(ud.LISTENER, ud.INFO, '%d Processing license with ID %s:' % (no, l['id']))
            ud.debug(ud.LISTENER, ud.INFO, '%d Valid until: %s' % (no, date.fromordinal(l['vdate'])))
            ud.debug(ud.LISTENER, ud.INFO, '%d Users: %s' % (no, l['u']))
            ud.debug(ud.LISTENER, ud.INFO, '%d Site-2-Site: %s' % (no, l['s2s']))
            if l.get('s2s'): sitetosite = True
            break
        except:
            pass
    listener.unsetuid()
    if not sitetosite:
        ud.debug(ud.LISTENER, ud.INFO, '%d Skipping actions' % no)
        return False
    else:
        return True
