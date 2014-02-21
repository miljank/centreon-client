#!/usr/bin/env python

"""
Server part of Centreon automation.

Developed by Miljan Karadzic. (miljank@gmail.com)

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
import time
import json
import socket
import subprocess
import SocketServer
from   time      import sleep
from   optparse  import OptionParser
from   threading import Timer

SocketServer.TCPServer.allow_reuse_address = True

def get_cmd_options():
    """Get user input
    """
    usage = "usage: %prog [-i IP/HOSTNAME] [-p PORT] [-h]"

    cmd_line = OptionParser(usage=usage)

    cmd_line.add_option("-i", "--interface", dest="interface", default="localhost",
                        help="IP/Hostname to listen on. Default: localhost")
    cmd_line.add_option("-p", "--port",      dest="port",      default=9995,
                        help="Port to bind to. Default: 9995", type="int")

    (opts, args) = cmd_line.parse_args()

    return opts

class TCPHandler(SocketServer.BaseRequestHandler):
    """Connection handler. Takes the user request, performs a basic sanity check and
    routes the request to a proper Centreon class where the operation is actually executed
    """
    def __parse(self, data, status):
        """Checks if all the basic parameters required for the routing are present
        """
        objects    = ['host', 'hostgroup', 'downtime', 'contact', 'contactgroup', 'config']
        operations = ['add', 'info', 'update', 'remove', 'list', 'test', 'deploy']

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
        """Takes the request and routes it to a proper class. Returns the status to client
        after the processing is done.
        """
        status = Status()

        d    = self.request.recv(8192).strip()
        data = self.__parse(d, status)
        print data

        if data:
            if self.server.debug:
                print("Client sent: ('{0}', {1})".format(data['client'], d))

            if data['object'] == 'host':
                cls = Host(self.server.config, status, data)
            elif data['object'] == 'hostgroup':
                cls = HostGroup(self.server.config, status, data)
            elif data['object'] == 'downtime':
                cls = Downtime(self.server.config, status, data)
            elif data['object'] == 'contact':
                cls = Contact(self.server.config, status, data)
            elif data['object'] == 'contactgroup':
                cls = ContactGroup(self.server.config, status, data)
            elif data['object'] == 'config':
                cls = Config(self.server.config, status, data)
            else:
                status.set('error', "Object is not supported: '{0}'".format(data['object']))
                self.end(status)
                return False

            try:
                cls.run()
            except NotImplementedError, error:
                status.set('error', error)

        self.end(status)

    def end(self, status):
        """Returns the status to the client and closes the connection
        """
        self.request.sendall("{0}\n".format(status.get()))
        self.request.close()

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    """Threaded TCP server
    """
    def set_env(self, config, debug=False):
        """Sets the environment for the TCP server
        """
        self.debug  = debug
        self.config = config
        self.config.timer = ReloadTimer()

class Centreon(object):
    """A class that wraps around Centreon command line API. It performs most the actions
    supported by the API with the addition of setting downtime for hosts (it uses CentCore for this).
    """
    def __init__(self, data, status):
        self.data     = data
        self.status   = status
        self.api_cmd  = '/usr/local/bin/centreon -u {0} -p {1}'.format(self.data['username'], self.data['password'])
        self.commands = {'get_host':           '-o HOST -a show -v',
                         'get_tpl':            '-o HTPL -a show',
                         'get_hg':             '-o HG -a show',
                         'get_poller':         '-a POLLERLIST',
                         'add_host':           '-o HOST -a ADD -v',
                         'apply_tpls':         '-o HOST -a applytpl -v',
                         'cfg_generate':       '-a POLLERGENERATE -v',
                         'cfg_test':           '-a POLLERTEST -v',
                         'cfg_move':           '-a CFGMOVE -v',
                         'poller_reload':      '-a POLLERRELOAD -v',
                         'poller_hosts':       '-o INSTANCE -a GETHOSTS -v',
                         'host_hostgroups':    '-o HOST -a gethostgroup -v',
                         'host_templates':     '-o HOST -a gettemplate -v',
                         'update_host':        '-o HOST -a setparam -v',
                         'list_hostgroup':     '-o HG -a show',
                         'hostgroup_info':     '-o HG -a getmember -v',
                         'list_contactgroups': '-o CG -a show',
                         'contactgroup_info':  '-o CG -a getcontact -v',
                         'update_contact':     '-o contact -a setparam -v'}

        # CentCore user and group ID
        self.uid = 81
        self.gid = 81
        self.cmd_file = '/var/lib/centreon/centcore.cmd'

        # Get the poller ID if needed
        if 'poller' in self.data and self.data['poller']:
            self.poller    = self.data['poller']
            self.poller_id = self.__get_poller_id(self.poller)
        else:
            self.poller    = None
            self.poller_id = None

    def __exec(self, cmd, attributes="", need_output=True):
        """Executes the Centreon API command line and returns command output if
        need_output is set (default) or a boolean if it is set to false.
        """
        command = "{0} {1} '{2}'".format(self.api_cmd, self.commands[cmd], attributes)

        p = subprocess.Popen(command,
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        while p.poll() is None:
            sleep(.5)

        if p.returncode == 0:
            if need_output:
                output = ''.join(p.stdout.readlines()).lower()
                if not output:
                    self.status.set("error", "No output for command '{0}'".format(cmd))
                    return False
                return output
            else:
                return True

        return False

    def __poller_list(self):
        """Lists all defined pollers
        """
        output = self.__exec('get_poller')
        if not output:
            self.status.set("error", "Could not list pollers")
            return False

        pollers = []
        for line in output.split('\n'):
            match = re.search(r'^(?P<id>[\d]+)\t(?P<name>[\w]+)$', line)
            if match:
                pollers.append(match.groupdict())

        if not pollers:
            self.status.set("error", "Could not list pollers")
            return False

        return pollers

    def __get_poller_id(self, poller):
        """Returns ID of a requested poller
        """
        output = self.__exec('get_poller')
        if not output:
            self.status.set("error", "Could not list pollers")
            return False

        match = re.search(r'^(?P<id>[\d]+)\t{0}$'.format(poller), output, re.MULTILINE)

        if not match:
            self.status.set("error", "Poller '{0}' is not defined".format(poller))
            return False

        return match.groupdict()['id']

    def __host_in_poller(self, hostname, poller):
        """Tries to find if a host is assigned to a specific poller
        """
        output = self.__exec('poller_hosts', poller)
        if not output:
            self.status.set('error', 'Could not list poller hosts')
            return False

        return re.search(r'^\d+;{0};.*'.format(hostname.replace('.','\.')), output, re.MULTILINE)

    def __add_host(self, data, host_templates, host_groups):
        """Defines a new host
        """
        if not host_templates or not host_groups:
            return False

        attrs = "{0};{1};{2};{3};{4};{5}".format(data['name'],
                                                 data['alias'],
                                                 data['ip'],
                                                 host_templates,
                                                 self.poller,
                                                 host_groups)
        rc = self.__exec('add_host', attrs, need_output=False)
        if not rc:
            self.status.set("error", "Failed to add host '{0}'".format(host['name']))
            return False

        return True

    def __get_host_info(self, host):
        """Returns host ip and status
        """
        output = self.__exec('get_host', host)
        match = re.search(r'^\d+;{0};[\w\d\.\-]+;(?P<ip>[\d\.]+);(?P<active>\d+)'.format(host.replace('.','\.')), output, re.MULTILINE)
        if not match:
            return False

        return match.groupdict()

    def __get_host_hostgroups(self, host):
        """Returns hostgroups assigned to a host
        """
        output = self.__exec('host_hostgroups', host)
        match = re.findall(r'^\d+;(?P<name>[\w\d\.\-\_]+)', output, re.MULTILINE)
        if not match:
            return False

        return match

    def __get_host_templates(self, host):
        """Returns host templates assigned to a host
        """
        output = self.__exec('host_templates', host)
        match = re.findall(r'^\d+;(?P<name>[\w\d\.\-\_]+)', output, re.MULTILINE)
        if not match:
            return False

        return match

    def __get_time(self):
        """Returns current UNIX time
        """
        return int(time.time())

    def get_hostgroup_members(self, hg_name):
        """Lists all hosts that are in specified hostgroup
        """
        match = []
        output = self.__exec('hostgroup_info', hg_name)
        if not output:
            self.status.set('error', "Hostgroup has no members '{0}'".format(hg_name))
            return False

        for line in output.split('\n'):
            host = re.findall(r'\d+;(?P<name>[\w\s\-\.]+)', line)
            if host:
                match.append(host[0])
        match.sort()
        return match

    def get_contactgroup_members(self, cg_name):
        """Lists all contacts that are in specified contact group
        """
        match = []
        output = self.__exec('contactgroup_info', cg_name)
        if not output:
            self.status.set('error', "Contact group has no members '{0}'".format(cg_name))
            return False

        for line in output.split('\n'):
            contact = re.findall(r'\d+;(?P<name>[\w\s\-\.]+)', line)
            if contact:
                match.append(contact[0])
        match.sort()
        return match

    def find_host_poller(self, hostname):
        """Returns a poller to which a host is assigned
        """
        pollers = self.__poller_list()
        if not pollers:
            return False

        for poller in pollers:
            if self.__host_in_poller(hostname, poller['name']):
                return poller

        self.status.set('error', 'Could not find host in any poller')
        return False

    def host_is_defined(self, host):
        """Returns True if a host is already defined or False if not
        """
        output = self.__exec('get_host', host)
        match = re.search(r'^\d+;{0};.*'.format(host.replace('.','\.')), output, re.MULTILINE)
        if match:
            return True

        return False

    def filter_hostgroups(self, groups):
        """Finds hostgroup names that are in groups
        """
        output = self.__exec('get_hg')
        match  = re.findall(r'^\d+;({0});.*'.format(groups), output, re.MULTILINE)

        if not match:
            self.status.set("error", "No matching host groups: '{0}'".format(groups))
            return False

        return '|'.join(match)

    def filter_hosttemplates(self, groups):
        """Finds host template names that in groups
        """
        output = self.__exec('get_tpl')
        match = re.findall(r'^\d+;({0});.*'.format(groups), output, re.MULTILINE)

        if not match:
            self.status.set("error", "No matching host templates: '{0}'".format(groups))
            return False

        return '|'.join(match)

    def apply_templates(self, host):
        """Creates all host template services for host
        """
        rc = self.__exec('apply_tpls', host, need_output=False)
        if not rc:
            self.status.set("error", "Failed to apply templates for host '{0}'".format(host['name']))
            return False
        return True

    def cfg_generate(self):
        """Generates configuration for a poller
        """
        rc = self.__exec('cfg_generate', self.poller_id, need_output=False)
        if not rc:
            self.status.set("error", "Failed to generate configuration for poller '{0}'".format(self.poller))
            return False
        return True

    def cfg_test(self):
        """Tests configuration for a poller
        """
        rc = self.__exec('cfg_test', self.poller_id, need_output=False)
        if not rc:
            self.status.set("error", "Configuration test failed for poller '{0}'".format(self.poller))
            return False
        return True

    def cfg_move(self):
        """Moves configuration to a poller
        """
        rc = self.__exec('cfg_move', self.poller_id, need_output=False)
        if not rc:
            self.status.set("error", "Failed to move configuration for poller '{0}'".format(self.poller))
            return False
        return True

    def poller_reload(self):
        """Instructs poller to reload configuration
        """
        rc = self.__exec('poller_reload', self.poller_id, need_output=False)
        if not rc:
            self.status.set("error", "Failed to reload poller '{0}'".format(self.poller))
            return False
        return True

    def add_host(self, data):
        """Adds a new host and its services
        """
        if not self.poller_id:
            return False

        host_groups    = self.filter_hostgroups(data['templates'])
        host_templates = self.filter_hosttemplates(data['templates'])

        if not self.__add_host(data, host_templates, host_groups):
            return False

        if not self.apply_templates(data['name']):
            return False

        # Do not deploy config automatically
        #if not self.cfg_generate():
        #   return False
        #
        #if not self.cfg_test():
        #    return False
        #
        #if not self.cfg_move():
        #    return False
        #
        #if not self.poller_reload():
        #    return False

        return True

    def add_downtime(self, data):
        """Adds a downtime for a host and all of its services. This is done using CentCore
        functionality to send commands to pollers, including the local one.
        """
        start = self.__get_time()
        end   = start + data['duration']

        host_cmd = "EXTERNALCMD:{0}:[{1}] SCHEDULE_HOST_DOWNTIME;{2};{3};{4};1;0;{5};{6};{7}\n".format(self.poller_id,
                                                                                                       start,
                                                                                                       data['name'],
                                                                                                       start,
                                                                                                       end,
                                                                                                       data['duration'],
                                                                                                       data['username'],
                                                                                                       data['message'])
        svc_cmd = "EXTERNALCMD:{0}:[{1}] SCHEDULE_HOST_SVC_DOWNTIME;{2};{3};{4};1;0;{5};{6};{7}\n".format(self.poller_id,
                                                                                                          start,
                                                                                                          data['name'],
                                                                                                          start,
                                                                                                          end,
                                                                                                          data['duration'],
                                                                                                          data['username'],
                                                                                                          data['message'])
        if os.path.isfile(self.cmd_file):
            with open(self.cmd_file, 'a') as f:
                f.write(host_cmd)
                f.write(svc_cmd)
                f.close()
        else:
            with open(self.cmd_file, 'w') as f:
                f.write(host_cmd)
                f.write(svc_cmd)
                f.close()
            os.chown(self.cmd_file, self.uid, self.gid)
            os.chmod(self.cmd_file, 0644)

        return True

    def get_host_info(self, host):
        """Gets all the information related to a host. At the moment this is:

        - Host IP and status
        - All of its hostgroups
        - All of its templates
        """
        info = {}
        info['host']       = self.__get_host_info(host)
        info['hostgroups'] = self.__get_host_hostgroups(host)
        info['templates']  = self.__get_host_templates(host)

        return info
        return self.__parse_host_info(host, info)

    def set_host_timezone(self, hostname, data):
        """Changes timezone for a specified host
        """
        attrs = "{0};location;{1}".format(hostname, data["timezone"])
        rc = self.__exec('update_host', attrs, need_output=False)
        if not rc:
            self.status.set("error", "Failed to update host timezone '{0}'".format(hostname))
            return False

        return True

    def hostgroup_list(self):
        """Lists all defined hostgroups
        """
        match = []
        output = self.__exec('list_hostgroup')
        for line in output.split('\n'):
            hg = re.findall(r'\d+;(?P<name>[\w\s\-\.]+);[\w\s\-\.]+', line)
            if hg:
                match.append(hg[0])

        match.sort()
        return match

    def set_hostgroup_timezone(self, hg_name, data):
        """Changes timezone for all hosts in a hostgroup
        """
        hosts = self.get_hostgroup_members(hg_name)
        if not hosts:
            return False

        for host in hosts:
            if not self.set_host_timezone(host, data):
                self.status.set('error', "Failed to set timezone for host '{}'".format(host))
                return False

        return True

    def contactgroup_list(self):
        """Lists all defined contact groups
        """
        match = []
        output = self.__exec('list_contactgroups')
        for line in output.split('\n'):
            cg = re.findall(r'\d+;(?P<name>[\w\s\-\.]+);[\w\s\-\.]+', line)
            if cg:
                match.append(cg[0])

        match.sort()
        return match

    def set_contactgroup_timezone(self, sg_name, data):
        """Changes timezone for all contacts in a contact group
        """
        contacts = self.get_contactgroup_members(sg_name)
        if not contacts:
            return False

        for contact in contacts:
            if not self.set_contact_timezone(contact, data):
                self.status.set('error', "Failed to set timezone for contact '{}'".format(contact))
                return False

        return True

    def set_contact_timezone(self, contactname, data):
        """Changes timezone for a specified contact
        """
        attrs = "{0};location;{1}".format(contactname, data["timezone"])
        rc = self.__exec('update_contact', attrs, need_output=False)
        if not rc:
            self.status.set("error", "Failed to update contact timezone '{0}'".format(contactname))
            return False

        return True

class Status(object):
    """Class used for passing around status between different objects.
    """
    def __init__(self):
        self.status = {'status': 'error', 'msg': 'Client sent malformed data'}

    def set(self, status, msg):
        """Set status
        """
        self.status = {'status': status, 'msg': msg}

    def get(self):
        """Get status
        """
        return json.dumps(self.status)

class ReloadTimer(object):
    """Timer class for sharing reload status among threads.
    """
    def __init__(self):
        self.timer = False

    def set(self, status):
        """Set timer status
        """
        self.timer = status

    def get(self):
        """Get timer status
        """
        return self.timer

class CentreonObject(object):
    """Prototype class defining all the methods for Centreon objects.
    Methods defined in this class should be implemented in classes
    that are subclussing CentreonObject class.
    """
    def __init__(self, config, status):
        self.config   = config
        self.status   = status
        self.centreon = None

    def __parse_input(self, data):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        raise NotImplementedError('Operation is not supported: __parse_input')

    def update(self):
        """Updates parameters of an object.
        """
        raise NotImplementedError('Operation is not supported: update')

    def info(self):
        """Get the details of an object.
        """
        raise NotImplementedError('Operation is not supported: info')

    def list(self):
        """Lists all the objects of certain type.
        """
        raise NotImplementedError('Operation is not supported: list')

    def add(self):
        """Adds a new object to Centreon.
        """
        raise NotImplementedError('Operation is not supported: add')

    def test(self):
        """Tests the validity of configuration for specified Centreon poller.
        """
        raise NotImplementedError('Operation is not supported: test')

    def deploy(self):
        """Deploys configuration for a specified poller.
        """
        raise NotImplementedError('Operation is not supported: deploy')

    def run(self):
        """Decides which operation to run
        """
        if self.data['operation']   == 'add':
            return self.add()
        elif self.data['operation'] == 'update':
            return self.update()
        elif self.data['operation'] == 'info':
            return self.info()
        elif self.data['operation'] == 'list':
            return self.list()
        elif self.data['operation'] == 'test':
            return self.test()
        elif self.data['operation'] == 'deploy':
            return self.deploy()
        else:
            raise NotImplementedError("[error] Operation is not implemented: {0}".format(self.options.operation))

class Host(CentreonObject):
    """Manages HOST objects.
    """
    def __init__(self, config, status, data):
        super(Host, self).__init__(config, status)
        self.data     = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status)
        self.wait_for_reload = 30 * 60

    def __parse_input(self, data):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        if not 'name' in data or not data['name']:
            try:
                address = socket.gethostbyaddr(data['client'])
            except socket.herror:
                self.status.set("error", "Cannot derive the name of the client using reverse DNS record")
                return False
            else:
                data['name'] = address[0]
                if len(address[1]) > 0:
                    data['alias'] = address[1][0]

        data['name'] = data['name'].lower()

        if data['operation'] == 'add':
            if not 'poller' in data or not data['poller']:
                self.status.set("error", "Poller name is not set")
                return False
            data['poller'] = data['poller'].lower()

            if 'templates' in data and data['templates']:
                data['templates'] = data['templates'].replace(':', '|').lower()
            else:
                data['templates'] = 'linux'

            if 'alias' not in data or not data['alias']:
                data['alias'] = data['name'].split('.')[0]

            try:
                data['ip'] = socket.gethostbyname(data['name'])
            except socket.gaierror:
                self.status.set('error', "Cannot resolve hostname '{0}'".format(data['name']))
                return False

            if not 'reload_poller' in data:
                data['reload_poller'] = False
            if not 'reload_poller_now' in data:
                data['reload_poller_now'] = False

        if data['operation'] == 'update':
            if 'timezone' not in data or type(data['timezone']) != int:
                self.status.set('error', 'Timezone offset is not set')
                return False

        return data

    def update(self):
        """Updates parameters of a host.
        """
        if not self.data:
            return False

        if not self.centreon.host_is_defined(self.data['name']):
            self.status.set('error', "Host is not defined '{0}'".format(self.data['name']))
            return False

        if not self.centreon.set_host_timezone(self.data['name'], self.data):
            return False

        self.status.set('ok', {'name': self.data['name']})

    def info(self):
        """Get the details of a host.
        """
        if not self.data:
            return False

        if not self.centreon.host_is_defined(self.data['name']):
            self.status.set('error', "Host is not defined '{0}'".format(self.data['name']))
            return False

        info = self.centreon.get_host_info(self.data['name'])
        self.status.set('ok', {'name': self.data['name'], 'info': info})

    def add(self):
        """Adds a new object to Centreon.
        """
        if not self.data or not self.data['templates']:
            return False

        if self.centreon.host_is_defined(self.data['name']):
            self.status.set('error', "Host is already defined '{0}'".format(self.data['name']))
            return False

        if not self.centreon.add_host(self.data):
            return False

        if self.data['reload_poller']:
            if not self.__reload_poller():
                return False

        self.status.set('ok', {'name': self.data['name']})

    def __config_reload(self):
        """Generates, tests, deploys new configuration for
        a poller and then does a reload
        """
        if not self.centreon.cfg_generate():
            return False

        if not self.centreon.cfg_test():
            return False

        if not self.centreon.cfg_move():
           return False

        if not self.centreon.poller_reload():
           return False

        self.status.set('ok', {'name': self.data['poller']})
        return True

    def __config_reload_timer(self):
        """Used with a delayed reload. It reloads the poller
        with a new configuration and resets the timer.
        """
        self.__config_reload()
        self.config.timer.set(False)

    def __reload_poller(self):
        """Reloads the poller with new configuration either
        immediately or with a delay
        """
        if self.data['reload_poller_now']:
            return self.__config_reload()
        else:
            if not self.config.timer.get():
                self.config.timer.set(True)
                Timer(self.wait_for_reload, self.__config_reload_timer).start()

        return True

class HostGroup(CentreonObject):
    """Manages HOSTGROUP objects.
    """
    def __init__(self, config, status, data):
        super(HostGroup, self).__init__(config, status)
        self.data     = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status)

    def __parse_input(self, data):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        if data['operation'] == 'info':
            if 'name' not in data or not data['name']:
                self.status.set('error', 'Hostgroup name is required.')
                return False

        if data['operation'] == 'update':
            if 'name' not in data or not data['name']:
                self.status.set('error', 'Hostgroup name is required.')
                return False

            if 'timezone' not in data or type(data['timezone']) != int:
                self.status.set('error', 'Timezone is required.')
                return False

        return data

    def update(self):
        """Updates parameters of a hostgroup.
        """
        if not self.data:
            return False

        if not self.centreon.set_hostgroup_timezone(self.data['name'], self.data):
            return False

        self.status.set('ok', {'name': self.data['name']})

    def info(self):
        """Get the details of a hostgroup.
        """
        if not self.data:
            return False

        hosts = self.centreon.get_hostgroup_members(self.data['name'])
        if not hosts:
            return False

        self.status.set('ok', {'hosts': hosts})

    def list(self):
        """Lists all hostgroups.
        """
        hostgroups = self.centreon.hostgroup_list()
        self.status.set('ok', {'hostgroups': hostgroups})

class Contact(CentreonObject):
    """Manages CONTACT objects.
    """
    def __init__(self, config, status, data):
        super(Contact, self).__init__(config, status)
        self.data     = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status)

    def __parse_input(self, data):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        if 'name' not in data or not data['name']:
            self.status.set('error', 'Contact name is required.')
            return False

        if 'timezone' not in data or type(data['timezone']) != int:
            self.status.set('error', 'Timezone is required.')
            return False

        return data

    def update(self):
        """Updates parameters of a contact.
        """
        if not self.data:
            return False

        if not self.centreon.set_contact_timezone(self.data['name'], self.data):
            return False

        self.status.set('ok', {'name': self.data['name']})

class ContactGroup(CentreonObject):
    """Manages CONTACTGROUP objects.
    """
    def __init__(self, config, status, data):
        super(ContactGroup, self).__init__(config, status)
        self.data     = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status)

    def __parse_input(self, data):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        if data['operation'] == 'info':
            if 'name' not in data or not data['name']:
                self.status.set('error', 'Contact group name is required.')
                return False

        if data['operation'] == 'update':
            if 'name' not in data or not data['name']:
                self.status.set('error', 'Contact group name is required.')
                return False

            if 'timezone' not in data or type(data['timezone']) != int:
                self.status.set('error', 'Timezone is required.')
                return False

        return data

    def update(self):
        """Updates parameters of a contact group.
        """
        if not self.data:
            return False

        if not self.centreon.set_contactgroup_timezone(self.data['name'], self.data):
            return False

        self.status.set('ok', {'name': self.data['name']})

    def info(self):
        """Get the details of a contact group.
        """
        if not self.data:
            return False

        contacts = self.centreon.get_contactgroup_members(self.data['name'])
        if not contacts:
            return False

        self.status.set('ok', {'contacts': contacts})

    def list(self):
        """Lists all the objects of certain type.
        """
        conactgroups = self.centreon.contactgroup_list()
        self.status.set('ok', {'contactgroups': conactgroups})

class Downtime(CentreonObject):
    """Manages DOWNTIME objects.
    """
    def __init__(self, config, status, data):
        super(Downtime, self).__init__(config, status)
        self.data     = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status)

    def __parse_input(self, data):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        if not 'name' in data or not data['name']:
            try:
                address = socket.gethostbyaddr(data['client'])
            except socket.herror:
                self.status.set("error", "Cannot derive the name of the client using reverse DNS record")
                return False
            else:
                data['name'] = address[0]
                if len(address[1]) > 0:
                    data['alias'] = address[1][0]

        data['name'] = data['name'].lower()

        if 'message' not in data or not data['message']:
            self.status.set("error", "Downtime message is not set")
            return False
        data['message'] = data['message'].replace("'", "").replace(';', '')

        if 'duration' not in data and not data['duration']:
            self.status.set("error", "Downtime duration is not set")
            return False

        try:
            data['duration'] = int(data['duration']) * 60
        except ValueError:
            self.status.set("error", "Downtime duration should be an integer")
            return False

        return data

    def add(self):
        """Adds a new downtime for a host and its services.
        """
        if not self.data:
            return False

        poller = self.centreon.find_host_poller(self.data['name'])
        if not poller:
            return False

        self.centreon.poller    = poller['name']
        self.centreon.poller_id = poller['id']

        self.centreon.add_downtime(self.data)
        self.status.set('ok', {'name': self.data['name'], 'duration': self.data['duration'] / 60})

class Config(CentreonObject):
    """Manages CONFIG objects.
    """
    def __init__(self, config, status, data):
        super(Config, self).__init__(config, status)
        self.data     = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status)

    def __parse_input(self, data):
        """This method is used for parsing user input.
        It checks if all required parameters for certain operation are set.
        """
        if not 'poller' in data or not data['poller']:
            self.status.set("error", "Poller name is not set")
            return False
        data['poller'] = data['poller'].lower()

        return data

    def test(self):
        """Tests the validity of configuration for a poller.
        """
        if not self.data:
            return False

        if not self.centreon.cfg_generate():
            return False

        if not self.centreon.cfg_test():
            return False

        self.status.set('ok', {'name': self.data['poller']})

    def deploy(self):
        """Deploys configuration for a poller.
        """
        if not self.data:
            return False

        if not self.centreon.cfg_generate():
            return False

        if not self.centreon.cfg_test():
            return False

        if not self.centreon.cfg_move():
           return False

        if not self.centreon.poller_reload():
           return False

        self.status.set('ok', {'name': self.data['poller']})

if __name__ == "__main__":
    options = get_cmd_options()

    try:
        server = ThreadedTCPServer((options.interface, options.port), TCPHandler)
        server.set_env(config=options)
        server.serve_forever()
        server.shutdown()
    except KeyboardInterrupt:
        print("\nExiting...")
    except:
        print("Socket still in use, please wait")
        sys.exit(1)

    sys.exit(0)
