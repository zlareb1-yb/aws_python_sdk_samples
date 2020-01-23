# -*- coding: utf-8 -*-


class __IterableConstantsMeta__(type):
    def __iter__(self):
        for attr in dir(self):
            if not attr.startswith("__"):
                yield getattr(self, attr)


class IterableConstants(object):
    __metaclass__ = __IterableConstantsMeta__
