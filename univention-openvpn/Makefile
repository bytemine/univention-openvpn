
all:
	@echo 'targets: build, clean, tidy'

clean:
	rm -f ../openvpn4ucs.dsc
	rm -f ../openvpn4ucs.tar.gz
	rm -f ../openvpn4ucs.changes
	rm -f debian/files
	rm -f debian/openvpn4ucs.debhelper.log
	rm -f debian/openvpn4ucs.debhelper.substvars

tidy: clean
	rm -f ../openvpn4ucs*.deb

build:
	dpkg-buildpackage -us -uc
