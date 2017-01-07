from pida_abc_type import IdaTypes
from pida_types import IDA_TYPES
from pida_id import decode_ida_id


class IdaTLocalType(IdaTypes):
    def __init__(self, ida_type=IDA_TYPES['local_type']):
        self.normal_id = 0
        self.ida_type = {'idt': ida_type, 'value': self.normal_id}

    def decode(self, data, ext=False):
        self.__set_normal_id(decode_ida_id(data[:2]))
        if ext:
            self.__extension_id()

        self.ida_type['id'] = self.normal_id
        return 2

    def get_type(self):
        return self.ida_type

    def __set_normal_id(self, normal_id):
        self.normal_id = normal_id

    def __extension_id(self):
        self.normal_id |= 1 << 13
