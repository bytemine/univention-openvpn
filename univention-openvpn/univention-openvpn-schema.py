class openvpnUser( UDM_Objects ):
        udm_modules = ( 'users/user', )
        key = '%(username)s'
        label = '%(username)s'
        regex = re.compile( '^[a-zA-Z0-9_-]+$' )
        use_objects = False
        udm_filter = 'openvpnAccount=1'

class openvpnUserandAddress( complex ):
        delimiter = ':'
        all_required = 0
        description=_('Openvpn user')
        subsyntaxes = [ ( _( 'Openvpn user' ), openvpnUser ), ( _( 'IPv4 address' ), ipv4Address ), ( _( 'IPv6 address' ), ipAddress ) ]

class IPTuple( complex ):
        delimiter = ':'
        all_required = 0
        description=_('Openvpn ifconfig')
        subsyntaxes = [ ( _( 'Local IP address' ), ipAddress ), ( _( 'Remote IP address' ), ipAddress ) ]
