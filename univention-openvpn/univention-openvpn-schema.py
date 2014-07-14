class openvpnUser( UDM_Attribute ):
        udm_module = 'users/user'
        attribute = 'cn'
        label_format = '%(displayName)s: %($attribute$)s'

class openvpnUser_and_Address( complex ):
        description=_('Openvpn user')
        subsyntaxes = ( ( _( 'Openvpn user' ), UserID ), ( _( 'IP address' ), ipv4Address ) )
