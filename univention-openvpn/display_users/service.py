#!/usr/bin/env python

import json
import web
import listener
import univention.uldap as ul
from socket_handler import *

# turn off debug mode (exceptions as html pages)
web.config.debug = False

class MyApplication(web.application):
    def run(self, port=8080, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, ('127.0.0.1', port))

urls = (
    '/display_users/cmd/(.*)', 'display_users'
)
app = MyApplication(urls, globals())


def connected_users(name):
    listener.setuid(0)
    lo = ul.getBackupConnection()
    users = lo.search('univentionOpenvpnAccount=1')
    users = map(lambda user: "%s.openvpn" % user[1].get('uid', [None])[0], users)
    listener.unsetuid()
    connected_users = userlist()

    # append not connected users
    for user in users:
        if not any(u['name'] == user for u in connected_users):
            connected_users.append({'name': user, 'connected': 0, 'type': 0, 'realip': '', 'virtips': '', 'cons': '', 'conr': '', 'recv': 0, 'sent': 0})
    count = str(len(connected_users))

    query = web.ctx.query
    if query:
        # jsonp
        queries = query.split('&')
        callback = queries[0].split('=')[1]
        return '%s({"draw": 1, "recordsTotal": %s, "recordsFiltered": %s, "data": %s});' % (callback, count, count, json.dumps(connected_users))
    else:
        return '{"data": %s}' % json.dumps(connected_users)


class display_users:
    def GET(self, name):

        name = name.encode('ascii','ignore')
        name_pieces = name.split('/')

        if 'connected_users' == name_pieces[0]:
            return connected_users(name)

        elif 'kill_user' == name_pieces[0]:
            try:
                id = name_pieces[1]
                kill_answer = killuser(id)
            except:
                pass
            return ""

        else:
            return ""


if __name__ == "__main__":
    app.run(port=38081)

