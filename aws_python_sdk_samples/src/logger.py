# -*- coding: utf-8 -*-
"""Logger util which returns logger object"""

import logging

from colorlog import ColoredFormatter

DEFAULT_LOG_LEVEL = "INFO"


class CustomLogger(object):
    """
    customization on logging module.

    custom logger with following log levels with appropriate color codes and
    custom formatting for messages::

        * LOG.response  - [RESPONSE]
        * LOG.payload   - [PAYLOAD]
        * LOG.status    - [STATUS]
        * log.url       - [URL]
        * LOG.info      - [INFO]
        * LOG.warn      - [WARNING]
        * LOG.error     - [ERROR]
        * LOG.critical  - [CRITICAL]

    """

    def __init__(self, name):
        """
        Build CustomLogger based on logging module

        Args:
            name(str): name of the module/logger

        Returns:
           None
        """

        # create custom levels
        self.__add_custom_levels()

        # create console and file handler
        self._ch = logging.StreamHandler()

        # add custom formatter to console handler
        self.__add_custom_formatter()

        # create custom logger
        self._logger = logging.getLogger(name)

        # add console to logger
        self._logger.addHandler(self._ch)

        # set level to log level
        self._logger.setLevel(DEFAULT_LOG_LEVEL)

    def response(self, msg):
        """
        custom response log level

        Args:
            msg(str): message to log

        Returns:
            None
        """

        return self._logger.response(msg)

    def payload(self, msg):
        """
        custom payload log level

        Args:
            msg(str): message to log

        Returns:
            None
        """

        return self._logger.payload(msg)

    def debug(self, msg):
        """
        custom debug log level

        Args:
            msg(str): message to log

        Returns:
            None
        """

        return self._logger.debug(msg)

    def url(self, msg):
        """
        custom url log level

        Args:
            msg(str): message to log

        Returns:
            None
        """

        return self._logger.url(msg)

    def status(self, msg):
        """
        custom status log level

        Args:
            msg(str): message to log

        Returns:
            None
        """

        return self._logger.status(msg)

    def info(self, msg):
        """
        info log level

        Args:
            msg(str): message to log

        Returns:
            None
        """

        return self._logger.info(msg)

    def warning(self, msg):
        """
        warning log level

        Args:
            msg(str): message to log

        Returns:
            None
        """

        return self._logger.warning(msg)

    def error(self, msg):
        """
        error log level

        Args:
            msg(str): message to log

        Returns:
            None
        """

        return self._logger.error(msg)

    def critical(self, msg):
        """
        error log level

        Args:
            msg(str): message to log

        Returns:
            None
        """

        return self._logger.critical(msg)

    def red(self, string):
        """
        log red colored string, useful for highlighting errors

        Args:
            string(str): string to be colored red

        Returns:
            None
        """

        return self.__color(string, "31m")

    def green(self, string):
        """
        log green colored string, useful for highlighting success

        Args:
            string(str): string to be colored green

        Returns:
            None
        """

        return self.__color(string, "32m")

    def yellow(self, string):
        """
        log yellow colored string, useful for highlighting data

        Args:
            string(str): string to be colored green

        Returns:
            None
        """

        return self.__color(string, "33m")

    def blue(self, string):
        """
        log blue colored string, useful for highlighting data

        Args:
            string(str): string to be colored green

        Returns:
            None
        """

        return self.__color(string, "34m")

    def __add_custom_levels(self):
        """
        add new custom level RESPONSE, PAYLOAD, STATUS, URL to logging

        Args:
            None

        Returns:
            None
        """

        RESPONSE = 5
        PAYLOAD = 6
        STATUS = 15
        URL = 16

        levels = [
            (RESPONSE, "RESPONSE"),
            (PAYLOAD, "PAYLOAD"),
            (STATUS, "STATUS"),
            (URL, "URL"),
        ]

        for level in levels:
            value, name = level
            logging.addLevelName(value, name)
            setattr(logging, name, value)

        def response(self, *args, **kwargs):
            """
            new response log level

            Args:
                *args: variable arguments
                **kwargs: variable keyword arguments

            Returns:
                None
            """

            self.log(RESPONSE, *args, **kwargs)

        def payload(self, *args, **kwargs):
            """
            new payload log level

            Args:
                *args: variable arguments
                **kwargs: variable keyword arguments

            Returns:
                None
            """

            self.log(PAYLOAD, *args, **kwargs)

        def url(self, *args, **kwargs):
            """
            new url log level

            Args:
                *args: variable arguments
                **kwargs: variable keyword arguments

            Returns:
                None
            """

            self.log(URL, *args, **kwargs)

        def status(self, *args, **kwargs):
            """
            new status log level

            Args:
                *args: variable arguments
                **kwargs: variable keyword arguments

            Returns:
                None
            """

            self.log(STATUS, *args, **kwargs)

        logging.Logger.response = response
        logging.Logger.payload = payload
        logging.Logger.url = url
        logging.Logger.status = status

    def __add_custom_formatter(self):
        """
        add ColorFormatter with custom colors for each log level

        Args:
            None

        Returns
            None
        """

        fmt = (
            "\n[%(asctime)s %(name)s "
            "[%(log_color)s%(levelname)s%(reset)s] %(message)s"
        )

        formatter = ColoredFormatter(
            fmt,
            datefmt="%Y-%m-%d %H:%M:%S",
            reset=True,
            log_colors={
                "RESPONSE": "purple",
                "PAYLOAD": "yellow",
                "DEBUG": "purple",
                "URL": "blue",
                "STATUS": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "red",
            },
        )

        # add formatter to console handler
        self._ch.setFormatter(formatter)

    def __color(self, string, color):
        """
        set specified color string

        Args:
            string(str): string to be color colded
            color(str): color to be set

        Returns:
            ascii colored string
        """

        if not isinstance(string, str):
            string = str(string)
        COLOR = "\033[0;{}".format(color)
        NC = "\033[0m"
        return COLOR + string + NC
