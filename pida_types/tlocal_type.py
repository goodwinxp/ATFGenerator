from abc_type import IdaTypes
from types import IDA_TYPES


class IdaTLocalType(IdaTypes):
    def __init__(self, ida_type=IDA_TYPES['local_type']):
        self.normal_id = 0
        self.ida_type = {'idt': ida_type, 'value': self.normal_id}

    def decode(self, data, ext=False):
        from ida_decoder import decode_id

        self.__set_normal_id(decode_id(data[:2]))
        if ext:
            self.__extension_id()

        self.ida_type['value'] = self.normal_id
        return 2

    def get_type(self):
        return self.ida_type

    def __set_normal_id(self, normal_id):
        self.normal_id = normal_id

    def __extension_id(self):
        self.normal_id |= 1 << 13


def is_local_type(ida_type):
    ext = False
    if len(ida_type) < 4:
        return False, ext

    rbyte = ord(ida_type[0])
    if ida_type[1] == '#' and rbyte in [4, 5]:
        if rbyte == 5:
            ext = True

        return True, ext

    return False, ext
