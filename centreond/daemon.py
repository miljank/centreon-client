#!/usr/bin/env python

import os
import sys
import time
import signal
import inspect
import threading


class Daemonize(object):
    """A class takes a list of tasks and creates daemons out of them.

    Well, that's not completely true. Class will deamonize itself and run
    each task in a separate thread.

    Tasks can be either a function or a class. If task is a class it's main
    method needs to be called start, as this is is what will be called from
    the daemon when the thread is started.

    Tasks needs to accept two attributes:
    - options: arguments passed to all tasks.
    - run: a boolean that needs to be checked in the main loop. When run is set
    to False the class needs to exit.

    When SIGTERM (signal 15) is recived by the daemon, it will set run attribute
    to False, wait for all threads to exit, and cleanly stop itself.

    Usage:

    def task(options, run):
        while run:
            print(options)
            time.sleep(5)

    Daemonize([task], options, pid_file='/var/run/centreond.pid')
    """
    def __init__(self, tasks, options=None, pid_file='/var/run/daemonize.pid'):
        self.run = True
        self.options = options
        self.tasks = tasks
        self.pid_file = pid_file
        self.threads = []

        signal.signal(signal.SIGTERM, self.__signal_handler)
        self.__start_daemon()

    def __fork(self):
        """Forks a child process and stops the parent"""
        try:
            pid = os.fork()
            if pid > 0:
                os._exit(0)
        except OSError, e:
            print("error: Fork failed: {0} ({1})".format(e.errno, e.strerror))
            sys.exit(1)

    def __start_all_workers(self):
        """Starts the processing threads"""
        for i in range(len(self.tasks)):
            if inspect.isclass(self.tasks[i]):
                thread = threading.Thread(target=self.tasks[i].start, args=[self.options, self.run])
            elif inspect.isfunction(self.tasks[i]):
                thread = threading.Thread(target=self.tasks[i], args=[self.options, self.run])
            else:
                print("error: Object type is not supported.")
                sys.exit(1)

            thread.start()
            self.threads.append(thread)

    def __signal_handler(self, signal, frame):
        """Signals threads to stop in case a SIGTERM is received"""
        # SIGTERM
        if signal is 15:
            self.run = False

            # Wait for all threads to finish
            [thread.join() for thread in self.threads]

            os.remove(self.pid_file)
            sys.exit(0)

    def __write_pid_file(self):
        """Writes a file containing the PID of the daemon"""
        try:
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
        except:
            print('error: Could not write pid file.')
            sys.exit(1)

    def __start_daemon(self):
        """Forks a daemon process and starts all the threads"""
        # Exit if the PID file is already there
        if os.path.isfile(self.pid_file):
            print("error: PID file exists. '{0}'".format(self.pid_file))
            sys.exit(1)

        self.__fork()

        os.chdir("/")
        os.setsid()
        os.umask(0)

        self.__fork()
        self.__write_pid_file()

        self.__start_all_workers()

        while self.run:
            time.sleep(60)
