#!/usr/bin/env python

import logging
from logging.handlers import RotatingFileHandler


class Logger(object):
    """Logging class that by default writes to stdout.
    If a logfile is passed it will write to both stdout
    and the log file.

    Log file is rotated after max_size is reached (default set
    to 10M). max_size value needs to be in bytes. backups attribute
    defines how many old instances of log files to keep (defaults
    to 5).

    Logging level can be controled using debug attribute. If True
    logging level will be set to debug.

    If debug attribute is True console logging will be disabled.

    To use the class create an instance and use debug(), info(),
    warn() and error() methods.

    Usage:

    log = Logger(log_file='/var/log/centreond.log',
                 daemon=True,
                 debug=True)
    log.info('All is ok')
    log.error('All is f*ed')"""
    def __init__(self, log_file=None, name='Logger',
                 max_size=10240000, backups=5, debug=False, daemon=False):
        self.backups = backups
        self.max_size = max_size

        self.file_format = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
        self.console_format = logging.Formatter("[%(levelname)-5.5s] %(message)s")
        self.logger = logging.getLogger(name)

        self.daemon = daemon

        self.DEBUG = '\033[1;35m'  # Purple
        self.WARNING = '\033[1;33m'  # Yellow
        self.ERROR = '\033[1;31m'  # Red
        self.CLEAR = '\033[0m'  # Clear color

        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        self.__setup(log_file)

    def __setup(self, log_file):
        if log_file:
            file_logger = RotatingFileHandler(log_file,
                                              maxBytes=self.max_size,
                                              backupCount=self.backups)
            file_logger.setFormatter(self.file_format)
            self.logger.addHandler(file_logger)

        if not self.daemon:
            console_logger = logging.StreamHandler()
            console_logger.setFormatter(self.console_format)
            self.logger.addHandler(console_logger)

    def debug(self, message):
        self.logger.debug("{0}{1}{2}".format(self.DEBUG, message, self.CLEAR))

    def info(self, message):
        self.logger.info(message)

    def warn(self, message):
        self.logger.warn("{0}{1}{2}".format(self.WARNING, message, self.CLEAR))

    def error(self, message):
        self.logger.error("{0}{1}{2}".format(self.ERROR, message, self.CLEAR))
