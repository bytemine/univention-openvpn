class openvpnUser( UDM_Objects ):
        udm_modules = ( 'users/user', )
        key = '%(username)s'
        label = '%(username)s'
        regex = re.compile( '^[a-zA-Z0-9_-]+$' )
        use_objects = False
        udm_filter = 'openvpnAccount=1'

class openvpnUserandAddress( complex ):
        delimiter = ':'
        all_required = False
        min_elements = 2
        description=_('Openvpn user')
        subsyntaxes = [ ( _( 'Openvpn user' ), openvpnUser ), ( _( 'IPv4 address' ), string ), ( _( 'IPv6 address' ), string ) ]
