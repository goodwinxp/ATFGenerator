from abc import ABCMeta, abstractmethod


class IdaTypes:
    __metaclass__ = ABCMeta

    @abstractmethod
    def decode(self, data):
        raise NotImplementedError()

    @abstractmethod
    def get_name(self):
        raise NotImplementedError()

    @abstractmethod
    def get_type(self):
        raise NotImplementedError()
