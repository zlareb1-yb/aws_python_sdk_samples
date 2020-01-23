# -*- coding: utf-8 -*-

from classes import IterableConstants

class ACTIONBASE(object):
    class STATE(IterableConstants):
        RUNNING = u'running'
        STOPPED = u'stopped'
        ERROR = u'ERROR'

    class ACTION(IterableConstants):
        STOP = u'stop'
        START = u'start'
        RESTART = u'restart'

    ACTION_MAP = {
        'stop': u'stop',
        'start': u'start',
        'restart': u'reboot',
    }

class AWS(ACTIONBASE):
    class STATE(IterableConstants):
        RUNNING = u'running'
        STOPPED = u'stopped'

    ACTION_MAP = {
        'stop': u'stop',
        'start': u'start',
        'restart': u'reboot',
    }
