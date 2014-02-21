#!/usr/bin/env python

"""
Client part of Centreon automation.

Copyright 2013 Miljan Karadzic. (miljank@gmail.com)

This file is part of Centreon Client.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import re
import sys
import json
import socket
import platform
import subprocess
from   optparse import OptionGroup
from   optparse import OptionParser

usage = """%prog [object] [operation] [options]

Objects:
    host            Host actions.
    hostgroup       Host group actions.
    downtime        Downtime actions.
    contact         Contact actions.
    contactgroup    Contact group actions.
    config          Configuration management options.

Host operations:
    add             Add a host.
    info            Show host details.
    update          Update host timezone.

Host group operations:
    info            Show hostgroup members.
    update          Update timezone of hostgroup members.
    list            List all hostgroups.

Contact operations:
    update          Update contact timezone.

Contact group operations:
    info            Show contact group members.
    update          Update timezone of contact group members.
    list            List all contact groups.

Downtime operations:
    add             Add a downtime.

Config operations:
    test            Test configuration for sanity.
    deploy          Deploy configuration to a poller."""

def get_cmd_options():
    """Get user input.
    """
    objects    = ['host', 'hostgroup', 'downtime', 'contact', 'contactgroup', 'config']
    operations = ['add', 'info', 'update', 'list', 'test', 'deploy']
    parser = OptionParser(usage=usage)

    parser.add_option("-s", "--server",   dest="api_server", help="API server. Usually the central server running Centreon. Default: localhost", default="localhost")
    parser.add_option("--port",           dest="api_port",   help="Port of the API server. Default: 9995", default=9995, type="int")
    parser.add_option("-p", "--poller",   dest="poller",     help="Centreon poller to operate on. E.g. europe.")
    parser.add_option("-n", "--name",     dest="name",       help="Name to operate on. Required for add, info, update or remove operations.")
    parser.add_option("-z", "--timezone", dest="timezone",   help="Timezone offset from UTC time", type="int")
    parser.add_option('-r', '--raw',      dest="raw",        help="Do not format output, print raw JSON response instead.", action="store_true", default=False)

    host = OptionGroup(parser, "Host options", "These options can be used to register or remove a host.")
    parser.add_option("-t", "--template", dest="templates",         help="Colon delimited list of templates to use for this host.")
    parser.add_option("--reload-poller",  dest="reload_poller",     help="Sync configuration to the poller and reload. If not used with --now, reload will be scheduled to run in 30 minutes.", action="store_true", default=False)
    parser.add_option("--now",            dest="reload_poller_now", help="Used with --reload-poller in order to sync and reload configuration of a poller right away.", action="store_true", default=False)
    parser.add_option_group(host)

    downtime = OptionGroup(parser, "Downtime options", "These options can be used to set, list and remove host downtimes.")
    downtime.add_option("-m", "--message",  dest="message",  help="Reason for downtime.")
    downtime.add_option("-d", "--duration", dest="duration", help="Downtime duration in minutes.", type="int")
    parser.add_option_group(downtime)

    auth = OptionGroup(parser, "Authentication options", "These options can be used to set authentication parameters.")
    auth.add_option("-u", "--username", dest="username", default="username", help="Username to use to authenticate to Centreon.")
    auth.add_option("--password",       dest="password", default="password", help="Password to use to authenticate to Centreon.")
    parser.add_option_group(auth)

    (opts, args) = parser.parse_args()

    if not args:
        print("[error] No object specified")
        sys.exit(1)

    if len(args) > 2:
        print("[error] Please choose only one object.")
        sys.exit(1)

    if args[0] not in objects:
        print("[error] Object is not supported.")
        sys.exit(1)
    opts.object = args[0]

    if args[1] not in operations:
        print("[error] Operation is not supported.")
        sys.exit(1)
    opts.operation = args[1]

    if not opts.api_server:
        print("[error] API server is not defined.")
        sys.exit(1)

    return opts

class CentreonObject(object):
    """Prototype class defining all the methods for Centreon objects.
    Methods defined in this class should be implemented in classes
    that are subclassing CentreonObject class.
    """
    def parse_options(self, options):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        raise NotImplementedError('[error] Method not implemented: parse_options')

    def parse_response(self, response):
        """Decides how to parse the server response based on operation.
        """
        if self.options.operation == 'update':
            self.parse_update(response)
        elif self.options.operation == 'info':
            self.parse_info(response)
        elif self.options.operation == 'list':
            self.parse_list(response)
        elif self.options.operation == 'add':
            self.parse_add(response)
        elif self.options.operation == 'test':
            self.parse_add(response)
        elif self.options.operation == 'deploy':
            self.parse_deploy(response)

    def format_data(self):
        """format_data populates data structure to be sent to the server.
        """
        raise NotImplementedError('[error] Method not implemented: format_data')

    def list(self):
        """Lists all the objects of certain type.
        """
        raise NotImplementedError('[error] Method not implemented: list')

    def info(self):
        """Get the details of an object.
        """
        raise NotImplementedError('[error] Method not implemented: info')

    def add(self):
        """Adds a new object to Centreon.
        """
        raise NotImplementedError('[error] Method not implemented: add')

    def update(self):
        """Updates parameters of a certain object.
        """
        raise NotImplementedError('[error] Method not implemented: update')

    def test(self):
        """Tests the validity of configuration for specified Centreon poller.
        """
        raise NotImplementedError('[error] Method not implemented: test')

    def deploy(self):
        """Deploys configuration for a specified poller.
        """
        raise NotImplementedError('[error] Method not implemented: deploy')

    def parse_add(self, response):
        """Parse server response for ADD action.
        """
        print("[{0}] Object added '{1}'".format(response['status'], response['msg']['name']))

    def parse_update(self, response):
        """Parse server response for UPDATE action.
        """
        print("[{0}] Object updated '{1}'".format(response['status'], response['msg']['name']))

    def parse_list(self, response):
        """Parse server response for LIST action.
        """
        raise NotImplementedError('[error] Method not implemented: parse_list')

    def parse_info(self, response):
        """Parse server response for INFO action.
        """
        raise NotImplementedError('[error] Method not implemented: parse_info')

    def parse_test(self, response):
        """Parse server response for TEST action.
        """
        print("[{0}] Poller configuration passed the test: '{1}'".format(response['status'], response['msg']['name']))

    def parse_deploy(self, response):
        """Parse server response for DEPLOY action.
        """
        print("[{0}] Poller configuration deployed: '{1}'".format(response['status'], response['msg']['name']))

    def run(self):
        """Decides which operation to run
        """
        if self.options.operation   == 'add':
            return self.add()
        elif self.options.operation == 'update':
            return self.update()
        elif self.options.operation == 'info':
            return self.info()
        elif self.options.operation == 'list':
            return self.list()
        elif self.options.operation == 'test':
            return self.test()
        elif self.options.operation == 'deploy':
            return self.deploy()
        else:
            raise NotImplementedError("[error] Operation is not implemented: {0}".format(self.options.operation))

class Host(CentreonObject):
    """Manages HOST objects.
    """
    def __init__(self, options):
        super(Host, self).__init__()
        self.options = self.parse_options(options)
        self.md_raid_pattern = r'^md\d'
        self.md_raid_config  = '/proc/mdstat'

    def parse_options(self, options):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
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
        """This runs only when adding a host and the hostname is not specified on the command line.
        Discovers the operating system of the host and (in case it is linux) the distribution as well,
        and these to the list of templates that should be assigned to this host.
        """
        system = platform.system().lower()
        data['templates'] = "{0}:{1}".format(data['templates'], system)

        if system == 'linux':
            data['templates'] = "{0}:{1}".format(data['templates'], platform.linux_distribution(full_distribution_name=0)[0])

        return data
    ############################
    # end: Platform discovery
    ############################

    ############################
    # start: RAID discovery
    ############################
    def __has_md_raid(self):
        """Discovers if a Linux host has a software RAID configured and adds it to the
        list of templates that should be assigned to this host
        """
        if not os.path.isfile(self.md_raid_config):
            return False

        with open(self.md_raid_config, 'r') as f:
            for line in f:
                if re.search(self.md_raid_pattern, line):
                    return True
        return False

    def __get_hw_config(self, data):
        """This runs only when adding a host and the hostname is not specified on the command line.
        Discovers a hardware configuration of the host. At the moment this is only finding the
        software RAID. In the future it can extended to discover hardware templates that should be
        used for this host.
        """
        if self.__has_md_raid():
            data['templates'] = "{0}:md_raid".format(data['templates'])
        return data
    ############################
    # end: RAID discovery
    ############################

    def format_data(self):
        """format_data populates data structure to be sent to the server.
        """
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "username":  self.options.username,
                "password":  self.options.password}

        if self.options.operation == 'add':
            data["poller"]            = self.options.poller
            data["name"]              = self.options.name
            data["timezone"]          = self.options.timezone
            data["templates"]         = self.options.templates
            data["reload_poller"]     = self.options.reload_poller
            data["reload_poller_now"] = self.options.reload_poller_now

        elif self.options.operation == 'update':
            data["name"] = self.options.name
            data["timezone"] = self.options.timezone

        elif self.options.operation == 'info':
            data["name"] = self.options.name

        return data

    def parse_info(self, response):
        """Parse server response for INFO action.
        """
        if response['msg']['info']['host']['active'] == "1":
            status = 'Yes'
        else:
            status = 'No'

        print("[{0}] Details for host {1}:".format(response['status'], response['msg']['name']))

        print("\nHost templates:")
        if not response['msg']['info']['templates']:
            print("    None")
        else:
            for tpl in response['msg']['info']['templates']:
                print("    {0}".format(tpl))

        print("\nHost groups:")
        if not response['msg']['info']['hostgroups']:
            print("    None")
        else:
            for grp in response['msg']['info']['hostgroups']:
                print("    {0}".format(grp))

        print("\nIP Address: {0}".format(response['msg']['info']['host']['ip']))
        print("Active:     {0}\n".format(status))

    def is_localhost(self, data):
        """Are we working on a local host or remote server.
        If no hostname is specified on the command line we are running on a localhost.
        """
        if 'name' not in data or not data['name']:
            return True
        return False

    def update(self):
        """Updates parameters of a certain host.
        """
        return self.format_data()

    def info(self):
        """Get the details of a host.
        """
        return self.format_data()

    def add(self):
        """Adds a new host to Centreon.
        """
        data = self.format_data()

        if self.is_localhost(data):
            data = self.__get_platform(data)
            data = self.__get_hw_config(data)

        return data

class HostGroup(CentreonObject):
    """Manages HOSTGROUP objects.
    """
    def __init__(self, options):
        super(HostGroup, self).__init__()
        self.options = self.parse_options(options)

    def parse_options(self, options):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
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

    def format_data(self):
        """format_data populates data structure to be sent to the server.
        """
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "username":  self.options.username,
                "password":  self.options.password}

        if self.options.operation == 'info':
            data['name'] = self.options.name

        if self.options.operation == 'update':
            data['name']     = self.options.name
            data['timezone'] = self.options.timezone

        return data

    def parse_info(self, response):
        """Parse server response for INFO action.
        """
        print("[{0}] Hostgroup details:".format(response['status']))

        for host in response['msg']['hosts']:
            print("    {0}".format(host))
        print

    def parse_list(self, response):
        """Parse server response for LIST action.
        """
        print("[{0}] Hostgroup list:".format(response['status']))

        for hg in response['msg']['hostgroups']:
                print("    {0}".format(hg))
        print

    def list(self):
        """Lists all the hostgroups.
        """
        return self.format_data()

    def info(self):
        """Get the details of a hostroup.
        """
        return self.format_data()

    def update(self):
        """Updates parameters of a certain hostgroup.
        """
        return self.format_data()

class Contact(CentreonObject):
    """Manages CONTACT objects.
    """
    def __init__(self, options):
        super(Contact, self).__init__()
        self.options = self.parse_options(options)

    def parse_options(self, options):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        if not options.name:
            print("[error] Contact name is required.")
            sys.exit(1)
        options.name = options.name.lower()

        if options.operation == 'update':
            if not options.timezone:
                print("[error] Timezone offset is required.")
                sys.exit(1)

        return options

    def format_data(self):
        """format_data populates data structure to be sent to the server.
        """
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "username":  self.options.username,
                "password":  self.options.password}

        if self.options.operation == 'update':
            data["name"] = self.options.name
            data["timezone"]  = self.options.timezone

        return data

    def update(self):
        """Updates parameters of a certain contact.
        """
        return self.format_data()

class ContactGroup(CentreonObject):
    """Manages CONTACTGROUP objects.
    """
    def __init__(self, options):
        super(ContactGroup, self).__init__()
        self.options = self.parse_options(options)

    def parse_options(self, options):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
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
        """Parse server response for INFO action.
        """
        print("[{0}] Contact group details:".format(response['status']))

        for contact in response['msg']['contacts']:
            print("    {0}".format(contact))
        print

    def parse_list(self, response):
        """Parse server response for LIST action.
        """
        print("[{0}] Contact group list:".format(response['status']))

        for cg in response['msg']['contactgroups']:
            print("    {0}".format(cg))
        print

    def format_data(self):
        """format_data populates data structure to be sent to the server.
        """
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "username":  self.options.username,
                "password":  self.options.password}

        if self.options.operation == 'info':
            data['name'] = self.options.name

        if self.options.operation == 'update':
            data['name']     = self.options.name
            data['timezone'] = self.options.timezone

        return data

    def list(self):
        """Lists all contact groups.
        """
        return self.format_data()

    def info(self):
        """Get the details of a certain contact group.
        """
        return self.format_data()

    def update(self):
        """Updates parameters of a certain contact group.
        """
        return self.format_data()

class Downtime(CentreonObject):
    """Manages DOWNTIME objects.
    """
    def __init__(self, options):
        super(Downtime, self).__init__()
        self.options = self.parse_options(options)

    def parse_options(self, options):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        if options.operation == 'add':
            if not options.message:
                print("[error] Downtime message is required.")
                sys.exit(1)

            if not options.duration:
                print("[error] Downtime duration is required.")
                sys.exit(1)

        return options

    def parse_add(self, response):
        """Parse server response for ADD action.
        """
        print("[{0}] Added downtime for '{1}' with duration of '{2}' minutes.".format(response['status'],
                                                                                      response['msg']['name'],
                                                                                      response['msg']['duration']))

    def format_data(self):
        """format_data populates data structure to be sent to the server.
        """
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "username":  self.options.username,
                "password":  self.options.password}

        if self.options.operation == 'add':
            data["name"] = self.options.name
            data["message"]  = self.options.message
            data["duration"] = self.options.duration

        return data

    def add(self):
        """Adds a new downtime.
        """
        return self.format_data()

class Config(CentreonObject):
    """Manages CONFIG objects.
    """
    def __init__(self, options):
        super(Config, self).__init__()
        self.options = self.parse_options(options)

    def parse_options(self, options):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        if not options.poller:
            print("[error] Poller name is required.")
            sys.exit(1)
        options.name = options.poller.lower()

        return options

    def format_data(self):
        """format_data populates data structure to be sent to the server.
        """
        data = {"object":    self.options.object,
                "operation": self.options.operation,
                "poller":    self.options.poller,
                "username":  self.options.username,
                "password":  self.options.password}

        return data

    def test(self):
        """Tests the validity of configuration for specified Centreon poller.
        """
        return self.format_data()

    def deploy(self):
        """Deploys configuration for a specified poller.
        """
        return self.format_data()

class CentreonClient(object):
    """Prepares the data to be sent to server, formats and prints the response
    """
    def __init__(self, options):
        self.cls  = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.options = options

    def __parse_response(self, response):
        """Convert the server response
        """
        try:
            data = json.loads(response)
        except ValueError:
            print("[error] Server sent malformed data: ('{0}')".format(response))
            sys.exit(1)
        else:
            return data

    def __print_response(self, response):
        """Prints server response in JSON format if raw output was selected
        or parsing and formating in human readable format
        """
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

    def __get_class(self):
        """Decides which class to instantiate depending on
        the object we are working on
        """
        if self.options.object == 'host':
            return Host(self.options)
        elif self.options.object == 'downtime':
            return Downtime(self.options)
        elif self.options.object == 'hostgroup':
            return HostGroup(self.options)
        elif self.options.object == 'contact':
            return Contact(self.options)
        elif self.options.object == 'contactgroup':
            return ContactGroup(self.options)
        elif self.options.object == 'config':
            return Config(self.options)
        else:
            raise NotImplementedError("[error] Object is not supported: {0}".format(self.options.object))

    def get_data(self):
        """Get the data to be sent to the server
        """
        try:
            self.cls = self.__get_class()
            return self.cls.run()
        except NotImplementedError, error:
            print(error)
            sys.exit(1)

    def send(self):
        """Sends and receives data from the server.
        """
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
            print("[error] Could not establish connection to the server ({0}:{1})".format(self.options.api_server, self.options.api_port))
            sys.exit(1)

        finally:
            self.sock.close()

        self.__print_response(response)

if __name__ == "__main__":
    options = get_cmd_options()
    CentreonClient(options).send()
