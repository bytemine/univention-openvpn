class OpenvpnUser(UDM_Attribute):
	udm_module = 'users/user'
	attribute = 'cn'
        label_format = '%($attribute$)s'

class OpenvpnUser_and_Address(complex):
        delimiter = ': '
        subsyntaxes = [ ( _( 'Openvpn user' ), OpenvpnUser ), ( _( 'IP address' ), ipv4Address ) ]
        all_required = True

