class openvpnUser( UDM_Objects ):
        udm_modules = ( 'users/user', )
        key = '%(username)s'
        label = '%(username)s'
        regex = re.compile( '^[a-zA-Z0-9_-]+$' )
        use_objects = False
        udm_filter = 'openvpnAccount=1'

class openvpnUserandAddress( complex ):
        delimiter = ':'
        all_required = True
        description=_('Openvpn user')
        subsyntaxes = [ ( _( 'OpenVPN user' ), openvpnUser ), ( _( 'IP address' ), ipAddress ) ]
