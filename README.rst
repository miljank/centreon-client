======
Centreon client
======

*******
What is Centreon?
*******
Centreon is an awesome product that started as a Nagios web fronted replacement. Since then it evolved into a full monitoring solution supporting distributed monitoring configurations.

*******
What is Centreon Client?
*******
Centreon Client is a wrapper around Centreon command line API. It allows for remote management of your Centreon configuration.

======
Usage
======

centreon-clientd.py is the server part. It needs to run on the same server as Centreon with Centreon Command Line API installed.

centreon-client.py is the client part and it can run anywhere.

::

    $ centreon-client.py host info -h
    Usage: centreon-client.py [object] [operation] [options]

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
        deploy          Deploy configuration to a poller.

    Options:
      -h, --help            show this help message and exit
      -s API_SERVER, --server=API_SERVER
                            API server. Usually the central server running
                            Centreon. Default: localhost
      --port=API_PORT       Port of the API server. Default: 9995
      -p POLLER, --poller=POLLER
                            Centreon poller to operate on. E.g. europe.
      -n NAME, --name=NAME  Name to operate on. Required for add, info, update or
                            remove operations.
      -z TIMEZONE, --timezone=TIMEZONE
                            Timezone offset from UTC time
      -r, --raw             Do not format output, print raw JSON response instead.

      Host options:
        These options can be used to register or remove a host.

        -t TEMPLATES, --template=TEMPLATES
                            Colon delimited list of templates to use for this
                            host.

      Downtime options:
        These options can be used to set, list and remove host downtimes.

        -m MESSAGE, --message=MESSAGE
                            Reason for downtime.
        -d DURATION, --duration=DURATION
                            Downtime duration in minutes.

      Authentication options:
        These options can be used to set authentication parameters.

        -u USERNAME, --username=USERNAME
                            Username to use to authenticate to Centreon.
        --password=PASSWORD
                            Password to use to authenticate to Centreon.

*******
Host
*******
When adding a host, if the client is local (hostname is not specified) it will try to discover the OS of the host, distribution and software raid if it is a Linux host. These are then used for assigning host templates and adding host to proper hostgroups.

::

    $ centreon-client.py host info
    [error] Host is not defined 'server1'

::

    $ centreon-client.py host add -p eu-poller -t mysql
    [ok] Object added 'server1'

::

    $ centreon-client.py host info
    [ok] Details for host server1:

    Host templates:
        linux
        mysql
        md_raid

    Host groups:
        linux
        mysql

    IP Address: 192.0.2.2
    Active:     Yes

At this time, it is not possible to change the host configuration. Only exception is the timezone the host is in.

::

    $ centreon-client.py host update -n server1 -z 7
    [ok] Object updated 'server1'

*******
Hostgroup
*******

::

    $ centreon-client.py hostgroup list
    [ok] Hostgroup list:
        linux
        mysql
        windows

::

    $ centreon-client.py hostgroup info -n linux
    [ok] Hostgroup details:
        server1
        server2
        server3
        server4
        server5

For convenience you can change timezone on all the hosts in a hostgroup.

::

    $ centreon-client.py hostgroup update -n linux -z 7
    [ok] Object updated 'linux'

*******
Contact
*******

Contacts can be update with a timezone as well.

::

    $ centreon-client.py contact update -n user1 -z 7
    [ok] Object updated 'user1'

*******
Contact group
*******
::

    $ centreon-client.py contactgroup list
    [ok] Contact group list:
        database_team
        developers
        network_team
        server_team

::

    $ centreon-client.py contactgroup info -n server_team
    [ok] Contact group details:
        user1
        user2
        user3
        user4
        user5

For convenience you can change timezone on all the contacts in a contact group.

::

    $ centreon-client.py contactgroup update -n server_team -z 7
    [ok] Object updated 'server_team'

*******
Downtime
*******
::

    $ centreon-client.py downtime add -n server2 -m 'Down for maintenance' -d 30
    [ok] Added downtime for 'server2' with duration of '30' minutes.

*******
Configuration
*******
::

    $ centreon-client.py config test -p eu-poller
    [ok] Poller configuration passed the test: 'eu-poller'

::

    $ centreon-client.py config deploy -p eu-poller
    [ok] Poller configuration deployed: 'eu-poller'

