
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
	rm -rf debian/univention-openvpn-sitetosite
	rm -rf common/deb_dist
	rm -rf common/univention_openvpn_common.egg-info

tidy: clean
	rm -f ../univention-openvpn-*.deb
	rm -f ../python-univention-openvpn-*.deb

build:
	dpkg-buildpackage -us -uc
	(cd common; python setup.py --command-packages=stdeb.command bdist_deb)
	mv common/deb_dist/python-univention-openvpn-common_*.deb ..
