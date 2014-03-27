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

fn_serverconf = '/etc/openvpn/server.conf'

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

		flist = [x for x in flist if not re.search("port", x) and not re.search("push \"redirect-gateway\"", x) and not re.search("duplicate-cn", x) and not re.search("server", x)]

		flist.append("port %s\n" % new.get('univentionOpenvpnPort', [None])[0])
		flist.append("server %s 255.255.255.0\n" % new.get('univentionOpenvpnNet', [None])[0])

		redirect = new.get('univentionOpenvpnRedirect',[None])[0]
		if redirect == '1':
			flist.append('push "redirect-gateway"\n')

		duplicate = new.get('univentionOpenvpnDuplicate', [None])[0]
		if duplicate == '1':
			flist.append('duplicate-cn\n')

		write_rc(flist, fn_serverconf)
	else:
		if 'univentionOpenvpnActive' in old:
			action = 'stop'
		else:
			action = None



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




