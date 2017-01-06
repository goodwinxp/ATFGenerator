from pida_abc_type import IdaTypes
from pida_types import get_base_name, IDA_TYPES
from pida_tlocal_type import IdaTLocalType


class IdaTTypedef(IdaTypes):
    def __init__(self, ida_type):
        self.name = None
        self.ida_type = ida_type

    def decode(self, data):
        len_str = ord(data[0])
        if not (data[1] == '#' and len_str in [4, 5]):
            self.name = data[1:len_str]
            return len_str

        offset = 2
        ext = False
        if len_str == 5:
            offset += 1
            ext = True

        local_type = IdaTLocalType(ida_type=IDA_TYPES['local_type'])
        local_type.decode(data[offset:], ext=ext)

        self.name = local_type.get_name()

        return len_str

    def get_name(self):
        return self.name

    def get_type(self):
        return get_base_name(self.ida_type)
