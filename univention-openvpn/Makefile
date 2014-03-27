
all:
	@echo 'targets: build, clean, tidy'

clean:
	rm -f ../univention-openvpn_*.dsc
	rm -f ../univention-openvpn_*.tar.gz
	rm -f ../univention-openvpn_*.changes
	rm -f debian/files
	rm -f debian/univention-openvpn-*.debhelper.log
	rm -f debian/univention-openvpn-*.substvars
	rm -rf debian/univention-openvpn-master
	rm -rf debian/univention-openvpn-schema
	rm -rf debian/univention-openvpn-server

tidy: clean
	rm -f ../univention-openvpn-*.deb

build:
	dpkg-buildpackage -us -uc

