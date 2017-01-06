from pida_abc_type import IdaTypes
from pida_types import get_base_name
from pida_id import decode_ida_id


class IdaTLocalType(IdaTypes):
    def __init__(self, name, ida_type):
        self.name = name
        self.normal_id = 0
        self.ida_type = ida_type

    def decode(self, data):
        self.normal_id = decode_ida_id(data[:2])
        return 2

    def get_name(self):
        return self.name

    def get_type(self):
        return get_base_name(self.ida_type)
