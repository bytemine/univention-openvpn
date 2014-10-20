import json
import web
import listener
import univention.uldap as ul
from socket_handler import *

urls = (
    '/(.*)', 'test'
)
app = web.application(urls, globals())

class test:
    def GET(self, name):
        name = name.encode('ascii','ignore')
	name_pieces = name.split('/')

        if 'connected_users' == name_pieces[0]:

            listener.setuid(0)
            lo = ul.getBackupConnection()
            users = lo.search('univentionOpenvpnAccount=1')
	    users = map(lambda user: "%s.openvpn" % user[1].get('uid', [None])[0], users)
	    print users
            listener.unsetuid()
            connected_users = userlist()
	    print connected_users

            

	    # nicht verbundene user anhaengen
            for user in users:
                if not any(u['name'] == user for u in connected_users):
                    connected_users.append({'name': user, 'connected': 'False', 'realip': '', 'virtips': '', 'recv': '', 'sent': '', 'cons': '', 'cont': ''})

            return 'jsonCallback(' + json.dumps(connected_users) + ');'

        elif 'kill_user' == name_pieces[0]:
            id = name_pieces[1]
            kill_answer = killuser(id)
            return "{'message': kill_answer}"
        else:
            return "{'message': 'unknown command'}"

if __name__ == "__main__":
    app.run()
