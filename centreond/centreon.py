import os
import re
import time
from centreond.process import Process


class Centreon(object):
    def __init__(self, data, status, logger=None):
        self.data = data
        self.status = status
        self.logger = logger

        self.api_cmd = '/usr/local/bin/centreon -u {0} -p {1}'.format(self.data['username'], self.data['password'])
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
                         'update_contact':     '-o contact -a setparam -v',
                         'set_attr':           '-o host -a setattr -v',
                         'get_attr':           '-o host -a getattr -v',
                         'del_attr':           '-o host -a delattr -v',
                         'get_attrs':          '-o host -a getattrs -v',
                         'get_attr_vals':      '-o host -a getattrvals -v'}

        self.uid = 501
        self.gid = 501
        self.cmd_file = '/var/lib/centreon/centcore.cmd'

        if 'poller' in self.data and self.data['poller']:
            self.poller = self.data['poller']
            self.poller_id = self.__get_poller_id(self.poller)
        else:
            self.poller = None
            self.poller_id = None

    def __exec(self, cmd, attributes="", return_stdout=True):
        cmd = "{0} {1} '{2}'".format(self.api_cmd, self.commands[cmd], attributes)

        proc = Process(cmd, logger=self.logger)
        proc.run()

        if not proc.status:
            self.logger.error("Command failed: {0}".format(cmd))
            self.logger.debug(proc.stdout)
            self.logger.debug(proc.stderr)
            return False

        if return_stdout:
            stdout = ''.join(proc.stdout).lower()

            if not stdout:
                self.status.set("error", "No stdout for command '{0}'".format(cmd))
                return False

            return stdout

        return True

    def __poller_list(self):
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
        output = self.__exec('poller_hosts', poller)
        if not output:
            self.status.set('error', 'Could not list poller hosts')
            return False

        return re.search(r'^\d+;{0};.*'.format(hostname.replace('.', '\.')), output, re.MULTILINE)

    def __add_host(self, data, host_templates, host_groups):
        if not host_templates or not host_groups:
            return False

        attrs = "{0};{1};{2};{3};{4};{5}".format(data['name'],
                                                 data['alias'],
                                                 data['ip'],
                                                 host_templates,
                                                 self.poller,
                                                 host_groups)
        rc = self.__exec('add_host', attrs, return_stdout=False)
        if not rc:
            self.status.set("error", "Failed to add host '{0}'".format(data['name']))
            return False

        return True

    def __get_host_info(self, host):
        output = self.__exec('get_host', host)
        match = re.search(r'^\d+;{0};(?P<aliases>[\w\d\.\,\ \-]+);(?P<ip>[\d\.]+);(?P<active>\d+)'.format(host.replace('.', '\.')), output, re.MULTILINE)
        if not match:
            return False

        return match.groupdict()

    def __get_host_hostgroups(self, host):
        output = self.__exec('host_hostgroups', host)
        match = re.findall(r'^\d+;(?P<name>[\w\d\.\-\_]+)', output, re.MULTILINE)
        if not match:
            return False

        return match

    def __get_host_templates(self, host):
        output = self.__exec('host_templates', host)
        match = re.findall(r'^\d+;(?P<name>[\w\d\.\-\_]+)', output, re.MULTILINE)
        if not match:
            return False

        templates = {"host": [], "contact": []}
        for template in match:
            if template.startswith('contact_'):
                templates['contact'].append(template)
            else:
                templates['host'].append(template)

        return templates

    def __get_time(self):
        return int(time.time())

    def get_hostgroup_members(self, hg_name):
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
        pollers = self.__poller_list()
        if not pollers:
            return False

        for poller in pollers:
            if self.__host_in_poller(hostname, poller['name']):
                return poller

        self.status.set('error', 'Could not find host in any poller')
        return False

    def host_is_defined(self, host):
        output = self.__exec('get_host', host)
        match = re.search(r'^\d+;{0};.*'.format(host.replace('.', '\.')), output, re.MULTILINE)
        if match:
            return True

        return False

    def filter_hostgroups(self, groups):
        output = self.__exec('get_hg')
        match = re.findall(r'^\d+;({0});.*'.format(groups.encode('ascii', 'ignore')), output, re.MULTILINE)

        if not match:
            self.status.set("error", "No matching host groups: '{0}'".format(groups))
            return False

        return '|'.join(match)

    def filter_hosttemplates(self, groups):
        output = self.__exec('get_tpl')
        match = re.findall(r'^\d+;({0});.*'.format(groups.encode('ascii', 'ignore')), output, re.MULTILINE)

        if not match:
            self.status.set("error", "No matching host templates: '{0}'".format(groups))
            return False

        return '|'.join(match)

    def apply_templates(self, host):
        rc = self.__exec('apply_tpls', host, return_stdout=False)
        if not rc:
            self.status.set("error", "Failed to apply templates for host '{0}'".format(host['name']))
            return False
        return True

    def cfg_generate(self):
        rc = self.__exec('cfg_generate', self.poller_id, return_stdout=False)
        if not rc:
            self.status.set("error", "Failed to generate configuration for poller '{0}'".format(self.poller))
            return False
        return True

    def cfg_test(self):
        rc = self.__exec('cfg_test', self.poller_id, return_stdout=False)
        if not rc:
            self.status.set("error", "Configuration test failed for poller '{0}'".format(self.poller))
            return False
        return True

    def cfg_move(self):
        rc = self.__exec('cfg_move', self.poller_id, return_stdout=False)
        if not rc:
            self.status.set("error", "Failed to move configuration for poller '{0}'".format(self.poller))
            return False
        return True

    def poller_reload(self):
        rc = self.__exec('poller_reload', self.poller_id, return_stdout=False)
        if not rc:
            self.status.set("error", "Failed to reload poller '{0}'".format(self.poller))
            return False
        return True

    def add_host(self, data):
        if not self.poller_id:
            return False

        host_groups = self.filter_hostgroups(data['templates'])
        host_templates = self.filter_hosttemplates(data['templates'])

        if not self.__add_host(data, host_templates, host_groups):
            return False

        if not self.apply_templates(data['name']):
            return False

        if not self.cfg_generate():
            return False

        if not self.cfg_test():
            return False

        return True

    def __add_downtime(self, downtimes):
        if os.path.isfile(self.cmd_file):
            with open(self.cmd_file, 'a') as f:
                for downtime in downtimes:
                    f.write(downtime)
                f.close()

        else:
            with open(self.cmd_file, 'w') as f:
                for downtime in downtimes:
                    f.write(downtime)
                f.close()

            os.chown(self.cmd_file, self.uid, self.gid)
            os.chmod(self.cmd_file, 0644)

    def add_host_downtime(self, data):
        start = self.__get_time()
        end = start + data['duration']

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
        self.__add_downtime([host_cmd, svc_cmd])
        return True

    def add_service_downtime(self, data):
        start = self.__get_time()
        end = start + data['duration']

        svc_cmd = "EXTERNALCMD:{0}:[{1}] SCHEDULE_SVC_DOWNTIME;{2};{3};{4};{5};1;0;{6};{7};{8}\n".format(self.poller_id,
                                                                                                         start,
                                                                                                         data['name'],
                                                                                                         data['service'],
                                                                                                         start,
                                                                                                         end,
                                                                                                         data['duration'],
                                                                                                         data['username'],
                                                                                                         data['message'])
        self.__add_downtime([svc_cmd])
        return True

    def get_host_info(self, host):
        info = {}
        info['host'] = self.__get_host_info(host)
        if 'aliases' in info['host']:
            info['host']['aliases'] = info['host']['aliases'].split(', ')

        info['hostgroups'] = self.__get_host_hostgroups(host)
        info['templates'] = self.__get_host_templates(host)

        return info
        return self.__parse_host_info(host, info)

    def set_host_timezone(self, hostname, data):
        attrs = "{0};location;{1}".format(hostname, data["timezone"])
        rc = self.__exec('update_host', attrs, return_stdout=False)
        if not rc:
            self.status.set("error", "Failed to update host timezone '{0}'".format(hostname))
            return False

        return True

    def hostgroup_list(self):
        match = []
        output = self.__exec('list_hostgroup')
        for line in output.split('\n'):
            hg = re.findall(r'\d+;(?P<name>[\w\s\-\.]+);[\w\s\-\.]+', line)
            if hg:
                match.append(hg[0])

        match.sort()
        return match

    def set_hostgroup_timezone(self, hg_name, data):
        hosts = self.get_hostgroup_members(hg_name)
        if not hosts:
            return False

        for host in hosts:
            if not self.set_host_timezone(host, data):
                self.status.set('error', "Failed to set timezone for host '{}'".format(host))
                return False

        return True

    def contactgroup_list(self):
        match = []
        output = self.__exec('list_contactgroups')
        for line in output.split('\n'):
            cg = re.findall(r'\d+;(?P<name>[\w\s\-\.]+);[\w\s\-\.]+', line)
            if cg:
                match.append(cg[0])

        match.sort()
        return match

    def set_contactgroup_timezone(self, sg_name, data):
        contacts = self.get_contactgroup_members(sg_name)
        if not contacts:
            return False

        for contact in contacts:
            if not self.set_contact_timezone(contact, data):
                self.status.set('error', "Failed to set timezone for contact '{}'".format(contact))
                return False

        return True

    def set_contact_timezone(self, contactname, data):
        attrs = "{0};location;{1}".format(contactname, data["attribute"])
        rc = self.__exec('update_contact', attrs, return_stdout=False)
        if not rc:
            self.status.set("error", "Failed to update contact timezone '{0}'".format(contactname))
            return False

        return True

    def del_attribute(self, hostname, data):
        attrs = "{0};{1}".format(hostname, data)
        rc = self.__exec('del_attr', attrs, return_stdout=False)
        if not rc:
            self.status.set("error", "Failed to delete host attribute '{0}'".format(hostname))
            return False

        return True

    def set_attribute(self, hostname, data):
        attrs = "{0};{1}".format(hostname, data)
        rc = self.__exec('set_attr', attrs, return_stdout=False)
        if not rc:
            self.status.set("error", "Failed to update host attribute '{0}'".format(hostname))
            return False

        return True

    def get_attribute(self, data):
        output = self.__exec('get_attr', data)
        match = re.findall(r'^\d+;(?P<name>[\w\d\.\-\_]+)', output, re.MULTILINE)
        if not match:
            self.status.set("error", "Failed to find hosts with attribute '{0}'".format(data))
            return False

        return match

    def get_all_attributes(self):
        output = self.__exec('get_attrs')
        match = re.findall(r'^\d+;(?P<name>[\w\d\.\-\_]+)', output, re.MULTILINE)
        if not match:
            self.status.set("error", "Failed to find any attributes")
            return False

        return match

    def get_attribute_values(self, data):
        output = self.__exec('get_attr_vals', data)
        match = re.findall(r'^\d+;(?P<name>[\w\d\.\-\_]+)', output, re.MULTILINE)
        if not match:
            self.status.set("error", "Failed to find values for attribute '{0}'".format(data))
            return False

        return match
