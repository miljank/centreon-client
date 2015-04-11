import os
import json
import signal
import thread
import SocketServer
from centreond.centreon_objects import Host
from centreond.centreon_objects import HostGroup
from centreond.centreon_objects import Downtime
from centreond.centreon_objects import Contact
from centreond.centreon_objects import ContactGroup
from centreond.centreon_objects import Config


SocketServer.TCPServer.allow_reuse_address = True


class TCPHandler(SocketServer.BaseRequestHandler):
    def __parse(self, data, status):
        objects = ['host', 'hostgroup', 'downtime', 'contact', 'contactgroup', 'config', 'server']
        operations = ['add', 'info', 'update', 'list', 'test', 'deploy', 'stop']

        try:
            data = json.loads(data)
        except ValueError:
            status.set("error", "Request data is not a valid JSON")
            return False
        else:
            if not 'object' in data or not data['object']:
                status.set("error", "Object is not set")
                return False
            if data['object'] not in objects:
                status.set("error", "Not an valid object: '{0}'".format(data['object']))
                return False

            if not 'operation' in data or not data['operation']:
                status.set("error", "Operation is not set")
                return False
            if data['operation'] not in operations:
                status.set("error", "Not a valid operation: '{0}'".format(data['operation']))
                return False

            data['client'] = self.client_address[0]
            return data

    def handle(self):
        status = Status()

        d = self.request.recv(8192).strip()
        data = self.__parse(d, status)

        if data:
            self.server.logger.info("Client sent: ('{0}', {1})".format(data['client'], d))

            if data['object'] == 'host':
                cls = Host(self.server.config, status, data, logger=self.server.logger)
            elif data['object'] == 'hostgroup':
                cls = HostGroup(self.server.config, status, data, logger=self.server.logger)
            elif data['object'] == 'downtime':
                cls = Downtime(self.server.config, status, data, logger=self.server.logger)
            elif data['object'] == 'contact':
                cls = Contact(self.server.config, status, data, logger=self.server.logger)
            elif data['object'] == 'contactgroup':
                cls = ContactGroup(self.server.config, status, data, logger=self.server.logger)
            elif data['object'] == 'config':
                cls = Config(self.server.config, status, data, logger=self.server.logger)
            elif data['object'] == 'server':
                cls = Server(self.server, status, self.server.logger)
            else:
                status.set('error', "Object is not supported: '{0}'".format(data['object']))
                self.end(status)
                return False

            try:
                if data['operation'] == 'add':
                    cls.add()
                elif data['operation'] == 'update':
                    cls.update()
                elif data['operation'] == 'info':
                    cls.info()
                elif data['operation'] == 'list':
                    cls.list()
                elif data['operation'] == 'test':
                    cls.test()
                elif data['operation'] == 'deploy':
                    cls.deploy()
                elif data['operation'] == 'stop':
                    cls.stop()
                else:
                    status.set('error', "Operation is not supported: '{0}'".format(data['operation']))
            except NotImplementedError, error:
                status.set('error', error)

        self.end(status)

    def end(self, status):
        self.request.sendall("{0}\n".format(status.get()))
        self.request.close()


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    def set_env(self, config, debug=False):
        self.config = config
        self.config.timer = ReloadTimer()
        self.debug = debug
        self.logger = config.logger


class Server(object):
    def __init__(self, server, status, logger):
        self.server = server
        self.status = status
        self.logger = logger

    def _kill(self):
        self.logger.info("Server going down.")
        self.server.shutdown()
        os.kill(os.getpid(), signal.SIGTERM)

    def stop(self):
        self.status.set("ok", "Server is going down.")
        thread.start_new_thread(self._kill, ())


class Status(object):
    def __init__(self):
        self.status = {'status': 'error', 'msg': 'Client sent malformed data'}

    def set(self, status, msg):
        self.status = {'status': status, 'msg': msg}

    def get(self):
        return json.dumps(self.status)


class ReloadTimer(object):
    def __init__(self):
        self.timer = False

    def set(self, status):
        self.timer = status

    def get(self):
        return self.timer
