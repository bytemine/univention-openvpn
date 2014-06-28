#!/usr/bin/python2.6

name = "openvpn-server"
description = "write server-configuration to server.conf"
filter = "(objectClass=univentionOpenvpn)"
attribute = ['univentionOpenvpnActive']
modrdn = "1" # first rewrite whole config

__package__='' 	# workaround for PEP 366
import listener
import univention.debug
import re
import univention_baseconfig
import os
import csv
from netaddr import *

fn_serverconf = '/etc/openvpn/server.conf'
fn_ips = '/etc/openvpn/ips'

action = None

# ----- function to open an textfile with setuid(0) for root-action
def load_rc(ofile):
	l = None
	listener.setuid(0)
	try:
		f = open(ofile,"r")
		l = f.readlines()
		f.close()
	except Exception, e:
		univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to open "%s": %s' % (ofile, str(e)) )
	listener.unsetuid()
	return l

# ----- function to write to an textfile with setuid(0) for root-action
def write_rc(flist, wfile):
	listener.setuid(0)
	try:
		f = open(wfile,"w")
		f.writelines(flist)
		f.close()
	except Exception, e:
		univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to write to file "%s": %s' % (wfile, str(e)))
	listener.unsetuid()

def create_dir(path):
	listener.setuid(0)
	try:
		os.makedirs(path)
	except Exception, e:
		univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to make directory "%s"' % path)
	listener.unsetuid()

def rename_dir(pathold, pathnew):
	listener.setuid(0)
	try:
		os.rename(pathold, pathnew)
	except Exception, e:
		univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to rename directory "%s" to "%s"' % (pathold, pathnew))
	listener.unsetuid()

def delete_file(fn):
        listener.setuid(0)
        try:
                os.remove(fn)
        except Exception, e:
                univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to remove file "%s": %s' % (fn, str(e)))
        listener.unsetuid()

# ----- function to open the ip map with setuid(0) for root-action
def load_ip_map():
        ip_map = []
        listener.setuid(0)
        try:
                with open(fn_ips, 'rb') as f:
                        r = csv.reader(f, delimiter=' ', quotechar='|')
                        for row in r:
                                ip_map.append(row)
        except Exception, e:
                univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to load ip map: %s' % str(e))
        listener.unsetuid()
        return ip_map

# ----- function to write the ip map with setuid(0) for root-action
def write_ip_map(ip_map):
        listener.setuid(0)
        try:
                with open(fn_ips, 'wb') as f:
                        w = csv.writer(f, delimiter=' ', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                        for i in ip_map:
                                w.writerow(i)
        except Exception, e:
                univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to write ip map: %s' % str(e))
        listener.unsetuid()

def handler(dn, new, old, command):
	global action
	univention.debug.debug(univention.debug.LISTENER, univention.debug.INFO, '### OpenVPN handler invoked' )
	if command == 'n':
		action = None
		return

	cn = new.get('cn', [None])[0]
	myname = listener.baseConfig['hostname']
	if cn != myname:
		action = None
		return;

	if 'univentionOpenvpnActive' in new:
		action = 'restart'

                # activate config
		if not 'univentionOpenvpnActive' in old:
			listener.setuid(0)
			try:
				os.rename (fn_serverconf + '-disabled', fn_serverconf);
			except Exception, e:
				listener.unsetuid()
				univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to activate server config: %s' % str(e))
				return
			listener.unsetuid()

		flist = load_rc(fn_serverconf)

		flist = [x for x in flist if not re.search("port", x) and not re.search("push \"redirect-gateway\"", x) and not re.search("duplicate-cn", x) and not re.search("server", x) and not re.search("client-config-dir", x)]

		flist.append("port %s\n" % new.get('univentionOpenvpnPort', [None])[0])
		flist.append("server %s 255.255.255.0\n" % new.get('univentionOpenvpnNet', [None])[0])

		redirect = new.get('univentionOpenvpnRedirect', [None])[0]
		if redirect == '1':
			flist.append('push "redirect-gateway"\n')

		duplicate = new.get('univentionOpenvpnDuplicate', [None])[0]
		if duplicate == '1':
			flist.append('duplicate-cn\n')

		portold = old.get('univentionOpenvpnPort', [None])[0]
		portnew = new.get('univentionOpenvpnPort', [None])[0]

		fixedaddresses = new.get('univentionOpenvpnFixedAddresses', [None])[0]
		if fixedaddresses == '1':
			flist.append('client-config-dir /etc/openvpn/ccd-%s\n' % portnew)
			if not os.path.exists('/etc/openvpn/ccd-%s' % portnew):
				if not os.path.exists('/etc/openvpn/ccd-%s' % portold):
					create_dir('/etc/openvpn/ccd-%s' % portnew)
				else:
					rename_dir('/etc/openvpn/ccd-%s' % portold, '/etc/openvpn/ccd-%s' % portnew)

		write_rc(flist, fn_serverconf)

		if new.get('univentionOpenvpnNet', [None])[0] != old.get('univentionOpenvpnNet', [None])[0]:
			ccd = '/etc/openvpn/ccd-' + portnew + '/'
		        network = new.get('univentionOpenvpnNet', [None])[0] + '/24'
		        netmask = '255.255.255.0'
		
		        if not os.path.exists(ccd):
		                os.makedirs(ccd)

		        if not os.path.exists(fn_ips):
		                open(fn_ips, 'a').close()

			ip_map_old = load_ip_map()
			ip_map_new = []
			for (name, _) in ip_map_old:
				ip_new = generate_ip(network, ip_map_new)	
		                ip_map_new.append((name, ip_new))
				delete_file(ccd + name + ".openvpn")
		                line = "ifconfig-push " + ip_new + " " + netmask
		                write_rc(line, ccd + name + ".openvpn")
			write_ip_map(ip_map_new)

	else:

		if 'univentionOpenvpnActive' in old:
			action = 'stop'
		else:
			action = None

def generate_ip(network, ip_map):
        ips = list(IPNetwork(network))
        length = len(ips)
        del ips[length - 1]
        del ips[0]
        del ips[0]
        for newip in list(ips):
                use = True
                for (name, ip) in ip_map:
                        if str(newip) == ip:
                                use = False
                                break
                if use:
                        return str(newip)

def initialize():
	pass

def postrun():
	global action
	if not action:
		return
	univention.debug.debug(univention.debug.LISTENER, univention.debug.INFO, 'OpenVPN-Server %s' % (action))

	try:
		listener.setuid(0)
		listener.run('/etc/init.d/openvpn', ['openvpn', action], uid=0)
	finally:
		listener.unsetuid()

	if action == 'stop':
		# deactivate config
		try:
			listener.setuid(0)
			os.rename (fn_serverconf, fn_serverconf + '-disabled');
		except Exception, e:
			listener.unsetuid()
			univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to deactivate server config: %s' % str(e))
			return

	listener.unsetuid()




