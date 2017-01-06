from pida_abc_type import IdaTypes
from pida_types import get_base_name
from pida_id import decode_ida_id


class IdaTLocalType(IdaTypes):
    def __init__(self, ida_type):
        self.name = None
        self.normal_id = 0
        self.ida_type = ida_type

    def decode(self, data, ext=False):
        self.__set_normal_id(decode_ida_id(data[:2]))
        if ext:
            self.__extension_id()

        return 2

    def get_name(self):
        if self.name is None:
            self.__load_name()

        return self.name

    def get_type(self):
        return get_base_name(self.ida_type)

    def get_normal_id(self):
        return self.normal_id

    def __set_normal_id(self, normal_id):
        self.normal_id = normal_id
        self.__load_name()

    def __extension_id(self):
        self.normal_id |= 1 << 13

    def __load_name(self):
        # TODO: load info from database
        self.name = 'unknown'
