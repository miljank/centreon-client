import socket
from threading import Timer
from centreond.centreon import Centreon


class CentreonObject(object):
    def __init__(self, config, status, logger=None):
        self.config = config
        self.status = status
        self.logger = logger
        self.centreon = None

    def __parse_input(self, data):
        raise NotImplementedError('Operation is not supported: __parse_input')

    def update(self):
        raise NotImplementedError('Operation is not supported: update')

    def info(self):
        raise NotImplementedError('Operation is not supported: info')

    def list(self):
        raise NotImplementedError('Operation is not supported: list')

    def add(self):
        raise NotImplementedError('Operation is not supported: add')

    def test(self):
        raise NotImplementedError('Operation is not supported: test')

    def deploy(self):
        raise NotImplementedError('Operation is not supported: deploy')

    def values(self):
        raise NotImplementedError('Operation is not supported: values')

    def stop(self):
        raise NotImplementedError('Operation is not supported: stop')


class Host(CentreonObject):
    def __init__(self, config, status, data, logger=None):
        super(Host, self).__init__(config, status, logger=logger)
        self.data = self.__parse_input(data)

        if not self.data:
            return None

        self.centreon = Centreon(self.data, self.status, logger=self.logger)
        self.wait_for_reload = 30 * 60

    def __add_contact_templates(self, templates, poller):
        templates = templates + ['contact_{0}_{1}'.format(t, poller) for t in templates]
        return '|'.join(templates)

    def __parse_input(self, data):
        if not 'name' in data or not data['name']:
            try:
                address = socket.gethostbyaddr(data['client'])
            except socket.herror:
                self.status.set("error", "Cannot derive client name using reverse DNS record")
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
                data['templates'] = data['templates'].lower().split(':')
            else:
                data['templates'] = ['linux']

            data['templates'] = self.__add_contact_templates(data['templates'], data['poller'])

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
        if not self.data:
            return False

        if not self.centreon.host_is_defined(self.data['name']):
            self.status.set('error', "Host is not defined '{0}'".format(self.data['name']))
            return False

        if not self.centreon.set_host_timezone(self.data['name'], self.data):
            return False

        self.status.set('ok', {'name': self.data['name']})

    def info(self):
        if not self.data:
            return False

        if not self.centreon.host_is_defined(self.data['name']):
            self.status.set('error', "Host is not defined '{0}'".format(self.data['name']))
            return False

        info = self.centreon.get_host_info(self.data['name'])
        self.status.set('ok', {'name': self.data['name'], 'info': info})

    def add(self):
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
        self.__config_reload()
        self.config.timer.set(False)

    def __reload_poller(self):
        if self.data['reload_poller_now']:
            return self.__config_reload()
        else:
            if not self.config.timer.get():
                self.config.timer.set(True)
                Timer(self.wait_for_reload, self.__config_reload_timer).start()

        return True


class HostGroup(CentreonObject):
    def __init__(self, config, status, data, logger=None):
        super(HostGroup, self).__init__(config, status, logger=logger)
        self.data = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status, logger=self.logger)

    def __parse_input(self, data):
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
        if not self.data:
            return False

        if not self.centreon.set_hostgroup_timezone(self.data['name'], self.data):
            return False

        self.status.set('ok', {'name': self.data['name']})

    def info(self):
        if not self.data:
            return False

        hosts = self.centreon.get_hostgroup_members(self.data['name'])
        if not hosts:
            return False

        self.status.set('ok', {'hosts': hosts})

    def list(self):
        hostgroups = self.centreon.hostgroup_list()
        self.status.set('ok', {'hostgroups': hostgroups})


class Contact(CentreonObject):
    def __init__(self, config, status, data, logger=None):
        super(Contact, self).__init__(config, status, logger=logger)
        self.data = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status, logger=self.logger)

    def __parse_input(self, data):
        if 'name' not in data or not data['name']:
            self.status.set('error', 'Contact name is required.')
            return False

        if 'timezone' not in data or type(data['timezone']) != int:
            self.status.set('error', 'Timezone is required.')
            return False

        return data

    def update(self):
        if not self.data:
            return False

        if not self.centreon.set_contact_timezone(self.data['name'], self.data):
            return False

        self.status.set('ok', {'name': self.data['name']})


class ContactGroup(CentreonObject):
    def __init__(self, config, status, data, logger=None):
        super(ContactGroup, self).__init__(config, status, logger=logger)
        self.data = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status, logger=self.logger)

    def __parse_input(self, data):
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
        if not self.data:
            return False

        if not self.centreon.set_contactgroup_timezone(self.data['name'], self.data):
            return False

        self.status.set('ok', {'name': self.data['name']})

    def info(self):
        if not self.data:
            return False

        contacts = self.centreon.get_contactgroup_members(self.data['name'])
        if not contacts:
            return False

        self.status.set('ok', {'contacts': contacts})

    def list(self):
        conactgroups = self.centreon.contactgroup_list()
        self.status.set('ok', {'contactgroups': conactgroups})


class Downtime(CentreonObject):
    def __init__(self, config, status, data, logger=None):
        super(Downtime, self).__init__(config, status, logger=logger)
        self.data = self.__parse_input(data)

        if not self.data:
            return None

        self.centreon = Centreon(self.data, self.status, logger=self.logger)

    def __parse_input(self, data):
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
        if not self.data:
            return False

        poller = self.centreon.find_host_poller(self.data['name'])
        if not poller:
            return False

        self.centreon.poller = poller['name']
        self.centreon.poller_id = poller['id']

        self.centreon.add_downtime(self.data)
        self.status.set('ok', {'name': self.data['name'], 'duration': self.data['duration'] / 60})


class Config(CentreonObject):
    def __init__(self, config, status, data, logger=None):
        super(Config, self).__init__(config, status, logger=logger)
        self.data = self.__parse_input(data)
        self.centreon = Centreon(self.data, self.status, logger=self.logger)

    def __parse_input(self, data):
        if not 'poller' in data or not data['poller']:
            self.status.set("error", "Poller name is not set")
            return False
        data['poller'] = data['poller'].lower()

        return data

    def test(self):
        if not self.data:
            return False

        if not self.centreon.cfg_generate():
            return False

        if not self.centreon.cfg_test():
            return False

        self.status.set('ok', {'name': self.data['poller']})

    def deploy(self):
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
