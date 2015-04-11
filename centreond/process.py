#!/usr/bin/env python

import os
import shlex
import tempfile
import subprocess
from time import sleep


class Process(object):
    """Wrapper around subprocess module that runs a command with a
    specific environment. When run method is called it will block
    until the command finishes executing.

    Usage:

    command = 'date'
    environment = {'TZ': 'UTC'}

    proc = Process(command, environment)
    proc.run()

    if proc.status:
        print ''.join(proc.stdout)
    else:
        print ''.join(proc.stderr)
    """
    def __init__(self, command, environment=os.environ.copy(), logger=None):
        self.status = None
        self.stdout = None
        self.stderr = None
        self.logger = logger
        self.process = None
        self.command = command
        self.environment = environment

    def run(self):
        f_stdout = tempfile.TemporaryFile()
        f_stderr = tempfile.TemporaryFile()

        self.process = subprocess.Popen(shlex.split(self.command),
                                        env=self.environment,
                                        stdout=f_stdout,
                                        stderr=f_stderr)

        while self.process.poll() is None:
            sleep(.5)

        f_stdout.seek(0)
        f_stderr.seek(0)

        self.stdout = f_stdout.readlines()
        self.stderr = f_stderr.readlines()

        f_stdout.close()
        f_stderr.close()

        if self.process.returncode == 0:
            self.status = True
        else:
            self.status = False

        if self.logger:
            self.logger.debug("[Process:localhost] Executing command: '{0}'".format(self.command))

        return self.status
