class openvpnUser( UDM_Objects ):
        udm_modules = ( 'users/user', )
        key = '%(username)s'
        label = '%(username)s'
        regex = re.compile( '^[a-zA-Z0-9_-]+$' )
        use_objects = False

class openvpnUserandAddress( complex ):
        delimiter = ':'
        all_required = 1
        description=_('Openvpn user')
        subsyntaxes = ( ( _( 'Openvpn user' ), openvpnUser ), ( _( 'IP address' ), ipv4Address ), )
