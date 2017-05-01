from abc import ABCMeta, abstractmethod


class IdaTypes:
    __metaclass__ = ABCMeta

    @abstractmethod
    def decode(self, data):
        raise NotImplementedError()

    @abstractmethod
    def get_type(self):
        raise NotImplementedError()

    @abstractmethod
    def to_string(self, session):
        raise NotImplementedError()

    @abstractmethod
    def from_dict(self, data):
        raise NotImplementedError()
