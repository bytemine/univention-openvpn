from univention.admin.hook import simpleHook

class univentionOpenVpn(simpleHook):
	type = 'univentionOpenVpn'
	delimiter = ':'
	ldapAttribute = 'univentionOpenvpnUserAddress'
	udmAtribute = 'openvpnuseraddress'

	def __convert(self, obj):

		changed = False
		new = []
		if type(obj) == type([]) and len(obj) >= 1:
			for i in obj:
				if type(i) == type([]) and len(i) == 3:
					new.append(self.delimiter.join(i))
					changed = True
				else:
					new.append(self.delimiter.join(i) + ':')
		if changed:
			return new

		return obj


	def __mapOpenVpnUserAddress(self, module, ml):

		newMl = []
		mlChanged = False
		if module.hasChanged(self.udmAtribute):
			for i in ml:
				if len(i) > 1 and i[0] == self.ldapAttribute:
					if len(i) == 3:
						old = i[1]
						new = i[2]
					else:
						old = ''
						new = i [1]
					old = self.__convert(old)
					new = self.__convert(new)
					newMl.append((self.ldapAttribute, old, new))
					mlChanged = True
				else:
					newMl.append(i)
		if mlChanged:
			return newMl

		return ml

	def hook_ldap_post_modify(self, module):
		pass

	def hook_open(self, module):

		if module.get(self.udmAtribute):
			if type(module[self.udmAtribute]) == type([]) and len(module[self.udmAtribute]) >= 1:
				newValue = []
				for i in module[self.udmAtribute]:
					if type(i) == type('') and self.delimiter in i:
                                                new = i.split(self.delimiter, 2)
                                                if len(new) == 2:
                                                        new.append('')
                                                newValue.append(new)
					else:
						newValue.append(i)
				module[self.udmAtribute] = newValue
		pass

	def hook_ldap_pre_create(self, module):
		pass

	def hook_ldap_addlist(self, module, al=[]):
		al = self.__mapOpenVpnUserAddress(module, al)
		return al

	def hook_ldap_post_create(self, module):
		pass

	def hook_ldap_modlist(self, module, ml=[]):
		ml = self.__mapOpenVpnUserAddress(module, ml)
		return ml

	def hook_ldap_pre_remove(self, module):
		pass

	def hook_ldap_post_remove(self, module):
		pass
