import os
import re
import sys
import json
import socket
import platform
from centreond.process import Process


class CentreonClient(object):
    def __init__(self, options):
        self.cls = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.options = options

    def __parse_response(self, response):
        try:
            data = json.loads(response)
        except ValueError:
            print("[error] Server sent malformed data: ('{0}')".format(response))
            sys.exit(1)
        else:
            return data

    def __print_response(self, response):
        response = self.__parse_response(response)

        if self.options.raw:
            print(json.dumps(response))
            if response['status'] == 'error':
                sys.exit(1)
        else:
            if response['status'] == 'error':
                print("[{0}] {1}".format(response['status'], response['msg']))
                sys.exit(1)
            self.cls.parse_response(response)

        sys.exit(0)

    def get_data(self):
        if self.options.object == 'host':
            self.cls = Host(self.options)
        elif self.options.object == 'downtime':
            self.cls = Downtime(self.options)
        elif self.options.object == 'hostgroup':
            self.cls = HostGroup(self.options)
        elif self.options.object == 'contact':
            self.cls = Contact(self.options)
        elif self.options.object == 'contactgroup':
            self.cls = ContactGroup(self.options)
        elif self.options.object == 'config':
            self.cls = Config(self.options)
        elif self.options.object == 'server':
            self.cls = Server(self.options)
        else:
            print("[error] Object is not supported.")
            sys.exit(1)

        try:
            if self.options.operation == 'add':
                return self.cls.add()
            elif self.options.operation == 'update':
                return self.cls.update()
            elif self.options.operation == 'info':
                return self.cls.info()
            elif self.options.operation == 'list':
                return self.cls.list()
            elif self.options.operation == 'test':
                return self.cls.test()
            elif self.options.operation == 'deploy':
                return self.cls.deploy()
            elif self.options.operation == 'values':
                return self.cls.values()
            elif self.options.operation == 'stop':
                return self.cls.stop()
        except NotImplementedError, error:
            print(error)
            sys.exit()

    def send(self):
        data = self.get_data()

        try:
            self.sock.connect((self.options.api_server, self.options.api_port))
            self.sock.sendall(json.dumps(data))
            response = ""

            while True:
                data = self.sock.recv(2048)
                if not data:
                    break
                response += data

        except socket.error:
            print("[error] Could not establish connection to the server ({0}:{1})".format(self.options.api_server,
                                                                                          self.options.api_port))
            sys.exit(1)
        finally:
            self.sock.close()

        self.__print_response(response)


class CentreonObject(object):
    def __parse_options(self, options):
        raise NotImplementedError('[error] Method not implemented: __parse_options')

    def __format_data(self):
        raise NotImplementedError('[error] Method not implemented: __format_data')

    def list(self):
        raise NotImplementedError('[error] Method not implemented: list')

    def info(self):
        raise NotImplementedError('[error] Method not implemented: info')

    def add(self):
        raise NotImplementedError('[error] Method not implemented: add')

    def update(self):
        raise NotImplementedError('[error] Method not implemented: update')

    def test(self):
        raise NotImplementedError('[error] Method not implemented: test')

    def deploy(self):
        raise NotImplementedError('[error] Method not implemented: deploy')

    def values(self):
        raise NotImplementedError('[error] Method not implemented: values')

    def stop(self):
        raise NotImplementedError('[error] Method not implemented: stop')

    def parse_add(self, response):
        print("[{0}] Object added '{1}'".format(response['status'], response['msg']['name']))

    def parse_update(self, response):
        print("[{0}] Object updated '{1}'".format(response['status'], response['msg']['name']))

    def parse_list(self, response):
        raise NotImplementedError('[error] Method not implemented: parse_list')

    def parse_info(self, response):
        raise NotImplementedError('[error] Method not implemented: parse_info')

    def parse_values(self, response):
        raise NotImplementedError('[error] Method not implemented: parse_values')

    def parse_test(self, response):
        print("[{0}] Poller configuration passed the test: '{1}'".format(response['status'],
                                                                         response['msg']['name']))

    def parse_deploy(self, response):
        print("[{0}] Poller configuration deployed: '{1}'".format(response['status'],
                                                                  response['msg']['name']))

    def parse_stop(self, response):
        print("[{0}] {1}".format(response['status'], response['msg']))


class Host(CentreonObject):
    def __init__(self, options):
        super(Host, self).__init__()
        self.options = self.__parse_options(options)

    def __set_env(self):
        # Hardware discovery
        self.lspci = ['/usr/sbin/lspci', '/usr/bin/lspci']
        self.lspci_output = ""
        self.md_raid_pattern = r'^md\d'
        self.md_raid_config = '/proc/mdstat'

    def __parse_options(self, options):
        if options.operation == 'add':
            if not options.poller:
                print("[error] Poller is not defined.")
                sys.exit(1)
            options.poller = options.poller.lower()

            if options.templates:
                options.templates = options.templates.lower()

        elif options.operation == 'update':
            if type(options.timezone) != int:
                print("[error] Timezone is not defined.")
                sys.exit(1)

        return options

    ############################
    # start: Platform discovery
    ############################
    def __get_platform(self, data):
        system = platform.system().lower()

        if system == 'linux':
            data['templates'] = "{0}:{1}".format(data['templates'], platform.linux_distribution(full_distribution_name=0)[0])

        data['templates'] = "{0}:{1}".format(data['templates'], system)

        return data
    ############################
    # end: Platform discovery
    ############################

    ############################
    # start: Hardware discovery
    ############################
    def __has_md_raid(self):
        if not os.path.isfile(self.md_raid_config):
            return False

        with open(self.md_raid_config, 'r') as f:
            for line in f:
                if re.search(self.md_raid_pattern, line):
                    return True
        return False

    def __find_command(self, command):
        for cmd in command:
            if os.path.isfile(cmd):
                return cmd

        return ''

    def __get_output(self, command):
        command = self.__find_command(command)
        p = Process(command)
        p.run()

        return ''.join(p.stdout).lower()

    def __get_hw_config(self, data):
        if self.__has_md_raid():
            data['templates'] = "{0}:md_raid".format(data['templates'])
        return data
    ############################
    # end: Hardware discovery
    ############################

    def __format_data(self):
        data = {"object":            self.options.object,
                "operation":         self.options.operation,
                "username":          self.options.username,
                "password":          self.options.password}

        if self.options.operation == 'add':
            data["poller"] = self.options.poller
            data["name"] = self.options.name
            data["timezone"] = self.options.timezone
            data["templates"] = self.options.templates
            data["reload_poller"] = self.options.reload_poller
            data["reload_poller_now"] = self.options.reload_poller_now

        elif self.options.operation == 'update':
            data["name"] = self.options.name
            data["timezone"] = self.options.timezone

        elif self.options.operation == 'info':
            data["name"] = self.options.name

        return data

    def parse_info(self, response):
        if response['msg']['info']['host']['active'] == "1":
            status = 'Yes'
        else:
            status = 'No'

        print("[{0}] Details for host {1}:".format(response['status'], response['msg']['name']))

        print("\nHost templates:")
        if not response['msg']['info']['templates']['host']:
            print("    None")
        else:
            for tpl in response['msg']['info']['templates']['host']:
                print("    {0}".format(tpl))

        print("\nContact templates:")
        if not response['msg']['info']['templates']['contact']:
            print("    None")
        else:
            for tpl in response['msg']['info']['templates']['contact']:
                print("    {0}".format(tpl))

        print("\nHost groups:")
        if not response['msg']['info']['hostgroups']:
            print("    None")
        else:
            for grp in response['msg']['info']['hostgroups']:
                print("    {0}".format(grp))

        print("\nHost aliases:")
        if not response['msg']['info']['host']['aliases']:
            print("    None")
        else:
            for alias in response['msg']['info']['host']['aliases']:
                print("    {0}".format(alias))

        print("\nIP Address: {0}".format(response['msg']['info']['host']['ip']))
        print("Active:     {0}\n".format(status))

    def parse_response(self, response):
        if self.options.operation == 'info':
            self.parse_info(response)
        elif self.options.operation == 'update':
            self.parse_update(response)
        elif self.options.operation == 'add':
            self.parse_add(response)

    def is_localhost(self, data):
        if 'name' not in data or not data['name']:
            return True
        return False

    def update(self):
        data = self.__format_data()
        return data

    def info(self):
        data = self.__format_data()
        return data

    def add(self):
        self.__set_env()
        data = self.__format_data()

        if self.is_localhost(data):
            self.lspci_output = self.__get_output(self.lspci)
            data = self.__get_hw_config(data)
            data = self.__get_platform(data)

        return data


class HostGroup(CentreonObject):
    def __init__(self, options):
        super(HostGroup, self).__init__()
        self.options = self.__parse_options(options)

    def __parse_options(self, options):
        if options.operation == 'info':
            if not options.name:
                print("[error] Hostgroup name is required.")
                sys.exit(1)

        if options.operation == 'update':
            if not options.name:
                print("[error] Hostgroup name is required.")
                sys.exit(1)

            if not options.timezone:
                print("[error] Timezone is required.")
                sys.exit(1)

        return options

    def __format_data(self):
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "username":  self.options.username,
                "password":  self.options.password}

        if self.options.operation == 'info':
            data['name'] = self.options.name

        if self.options.operation == 'update':
            data['name'] = self.options.name
            data['timezone'] = self.options.timezone

        return data

    def parse_info(self, response):
        print("[{0}] Hostgroup details:".format(response['status']))

        for host in response['msg']['hosts']:
            print("    {0}".format(host))
        print

    def parse_list(self, response):
        print("[{0}] Hostgroup list:".format(response['status']))

        for hg in response['msg']['hostgroups']:
                print("    {0}".format(hg))
        print

    def parse_response(self, response):
        if self.options.operation == 'list':
            self.parse_list(response)
        elif self.options.operation == 'info':
            self.parse_info(response)
        elif self.options.operation == 'update':
            self.parse_update(response)

    def list(self):
        data = self.__format_data()
        return data

    def info(self):
        data = self.__format_data()
        return data

    def update(self):
        data = self.__format_data()
        return data


class Contact(CentreonObject):
    def __init__(self, options):
        super(Contact, self).__init__()
        self.options = self.__parse_options(options)

    def __parse_options(self, options):
        if not options.name:
            print("[error] Contact name is required.")
            sys.exit(1)
        options.name = options.name.lower()

        if options.operation == 'update':
            if not options.timezone:
                print("[error] Timezone offset is required.")
                sys.exit(1)

        return options

    def parse_response(self, response):
        if self.options.operation == 'update':
            self.parse_update(response)

    def __format_data(self):
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "username":  self.options.username,
                "password":  self.options.password}

        if self.options.operation == 'update':
            data["name"] = self.options.name
            data["timezone"] = self.options.timezone

        return data

    def update(self):
        return self.__format_data()


class ContactGroup(CentreonObject):
    def __init__(self, options):
        super(ContactGroup, self).__init__()
        self.options = self.__parse_options(options)

    def __parse_options(self, options):
        if options.operation == 'info':
            if not options.name:
                print("[error] Contact group name is required.")
                sys.exit(1)

        if options.operation == 'update':
            if not options.name:
                print("[error] Contact group name is required.")
                sys.exit(1)

            if not options.timezone:
                print("[error] Timezone is required.")
                sys.exit(1)

        return options

    def parse_info(self, response):
        print("[{0}] Contact group details:".format(response['status']))

        for contact in response['msg']['contacts']:
            print("    {0}".format(contact))
        print

    def parse_list(self, response):
        print("[{0}] Contact group list:".format(response['status']))

        for cg in response['msg']['contactgroups']:
            print("    {0}".format(cg))
        print

    def parse_response(self, response):
        if self.options.operation == 'update':
            self.parse_update(response)
        elif self.options.operation == 'info':
            self.parse_info(response)
        elif self.options.operation == 'list':
            self.parse_list(response)

    def __format_data(self):
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "username":  self.options.username,
                "password":  self.options.password}

        if self.options.operation == 'info':
            data['name'] = self.options.name

        if self.options.operation == 'update':
            data['name'] = self.options.name
            data['timezone'] = self.options.timezone

        return data

    def list(self):
        data = self.__format_data()
        return data

    def info(self):
        data = self.__format_data()
        return data

    def update(self):
        data = self.__format_data()
        return data


class Downtime(CentreonObject):
    def __init__(self, options):
        super(Downtime, self).__init__()
        self.options = self.__parse_options(options)

    def __parse_options(self, options):
        if options.operation == 'add':
            if not options.message:
                print("[error] Downtime message is required.")
                sys.exit(1)

            if not options.duration:
                print("[error] Downtime duration is required.")
                sys.exit(1)

        return options

    def parse_add(self, response):
        print("[{0}] Added downtime for '{1}' with duration of '{2}' minutes.".format(response['status'],
                                                                                      response['msg']['name'],
                                                                                      response['msg']['duration']))

    def parse_response(self, response):
        if self.options.operation == 'add':
            self.parse_add(response)

    def __format_data(self):
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "username":  self.options.username,
                "password":  self.options.password}

        if self.options.operation == 'add':
            data["name"] = self.options.name
            data["message"] = self.options.message
            data["duration"] = self.options.duration

        return data

    def add(self):
        return self.__format_data()


class Config(CentreonObject):
    def __init__(self, options):
        super(Config, self).__init__()
        self.options = self.__parse_options(options)

    def __parse_options(self, options):
        if not options.poller:
            print("[error] Poller name is required.")
            sys.exit(1)
        options.name = options.poller.lower()

        return options

    def parse_response(self, response):
        if self.options.operation == 'test':
            self.parse_test(response)
        elif self.options.operation == 'deploy':
            self.parse_deploy(response)

    def __format_data(self):
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "poller":    self.options.poller,
                "username":  self.options.username,
                "password":  self.options.password}

        return data

    def test(self):
        return self.__format_data()

    def deploy(self):
        return self.__format_data()


class Server(CentreonObject):
    def __init__(self, options):
        super(Server, self).__init__()
        self.options = options

    def parse_response(self, response):
        if self.options.operation == 'stop':
            self.parse_stop(response)

    def __format_data(self):
        data = {"object":    self.options.object,
                "operation": self.options.operation}

        return data

    def stop(self):
        return self.__format_data()
