
all:
	@echo 'targets: build, clean, tidy'

clean:
	rm -f ../openvpn4ucs.dsc
	rm -f ../openvpn4ucs.tar.gz
	rm -f ../openvpn4ucs.changes
	rm -f debian/files
	rm -f debian/openvpn4ucs.debhelper.log
	rm -f debian/openvpn4ucs.debhelper.substvars
	rm -rf common/deb_dist
	rm -rf common/univention_openvpn_common.egg-info

tidy: clean
	rm -f ../openvpn4ucs*.deb
	rm -f ../python-univention-openvpn-*.deb

build:
	dpkg-buildpackage -us -uc
	(cd common; python3 setup.py --command-packages=stdeb.command bdist_deb)
	mv common/deb_dist/python3-univention-openvpn-common_*.deb ..
