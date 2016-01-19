#!/usr/bin/python2.7
#
# Univention Management Console
#  Manage credentials for OpenVPN
#
# Copyright 2012-2015 Univention GmbH
#
# http://www.univention.de/
#
# All rights reserved.
#
# The source code of this program is made available
# under the terms of the GNU Affero General Public License version 3
# (GNU AGPL V3) as published by the Free Software Foundation.
#
# Binary versions of this program provided by Univention to you as
# well as other copyrighted, protected or trademarked materials like
# Logos, graphics, fonts, specific documentations and configurations,
# cryptographic keys etc. are subject to a license agreement between
# you and Univention and not subject to the GNU AGPL V3.
#
# In the case you use this program under the terms of the GNU AGPL V3,
# the program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <http://www.gnu.org/licenses/>.

from univention.management.console.modules import Base
from univention.management.console.base import UMC_Error
from univention.management.console.log import MODULE
from univention.management.console.modules.decorators import simple_response

from univention.lib.i18n import Translation

import os

_ = Translation('univention-management-console-modules-openvpn4ucs').translate


class Instance(Base):

	def init(self):
		# this initialization method is called when the
		# module process is started and the configuration from the
		# UMC server is completed
#		self._first_attempt_form = True
#		self._first_attempt_button = True
		return

#	@simple_response
#	def process_form(self, password):
#		if self._first_attempt_form:
#			self._first_attempt_form = False
#			raise UMC_Error(_('First try failed. Try again.'))
#		return {'username': self.username, 'password': password}

	@simple_response
	def process_button(self):
#		if self._first_attempt_button:
#			self._first_attempt_button = False
#			raise UMC_Error(_('First try failed. Try again.'))
		MODULE.process('Generating new secret...')
		newkey_path = "/etc/openvpn/sitetosite.newkey"
		os.popen("openvpn --genkey --secret %s" % newkey_path)
		with open(newkey_path, 'r') as newkey_file:
			newkey=newkey_file.read().replace('\n', '<br />')
		return newkey
