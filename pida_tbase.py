from pida_abc_type import IdaTypes
from pida_types import get_base_name


class IdaTBase(IdaTypes):
    def __init__(self, ida_type):
        self.name = None
        self.ida_type = ida_type

    def decode(self, data):
        return 0

    def get_name(self):
        if self.name is None:
            self.name = get_base_name(self.ida_type)

        return self.name

    def get_type(self):
        if self.name is None:
            self.name = get_base_name(self.ida_type)

        return self.name
