from abc_type import IdaTypes
from ida_types import get_base_name


class IdaTBase(IdaTypes):
    def __init__(self, ida_type):
        self.ida_type = {'idt': ida_type, 'value': None}

    def decode(self, data):
        return 0

    def get_type(self):
        return self.ida_type

    def to_string(self, session):
        return get_base_name(self.ida_type['idt']) + '{ptr} {name}'

    def from_dict(self, data):
        self.ida_type = data
