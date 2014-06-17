#!/usr/bin/python2.6

name = "openvpn-server2"
description = "manage fixed addresses"
filter = "(objectClass=univentionOpenvpnUser)"
attribute = ['univentionOpenvpnAccount']
modrdn = "1" # first rewrite whole config

__package__='' 	# workaround for PEP 366
import listener
import univention.debug
import re
import univention_baseconfig
import os
import json

fn_ips = '/etc/openvpn/ips'
ccd = # TODO

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

def delete_file(fn):
	listener.setuid(0)
	try:
		os.remove(fn)
	except Exception, e:
		univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to remove file "%s": %s' % (fn, str(e)))
	listener.unsetuid()

# ----- function to open the ip map with setuid(0) for root-action
def load_ip_map
	listener.setuid(0)
	try:
		with open(fn_ips) as f:
    			ips = json.load(f)
	except Exception, e:
		univention.debug.debug(univention.debug.LISTENER, univention.debug.ERROR, 'Failed to load ip map: %s' % str(e))
	listener.unsetuid()
	return ips

# ----- function to write the ip map with setuid(0) for root-action
def write_ip_map(ips)
	listener.setuid(0)
	try:
		with open(fn_ips, 'w') as f:
    			json.dump(ips, f)
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

	client_cn = new.get('uid', [None])[0] + ".openvpn"

	if 'univentionOpenvpnAccount' in new and not 'univentionOpenvpnAccount' in old:
		action = 'restart'

		network = # TODO
		netmask = # TODO
		ip = generate_ip(network)

		ip_map = load_ip_map
		ip_map.append((client_cn, ip))
		write_ip_map(ip_map)
		
		line = "ifconfig-push " + ip + netmask
		write_rc(line, ccd + client_cn)

	else if not 'univentionOpenvpnAccount' in new and 'univentionOpenvpnAccount' in old:
		action = 'restart'

		# TODO: delete users entries in ccd and ip map

def generate_ip(network):
	l = load_rc(fn_ips)
	# TODO: use IPy: ip = IP(network), iterate and take first address which is not in l

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
