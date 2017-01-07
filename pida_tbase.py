from pida_abc_type import IdaTypes


class IdaTBase(IdaTypes):
    def __init__(self, ida_type):
        self.name = None
        self.ida_type = {'idt': ida_type, 'value': None}

    def decode(self, data):
        return 0

    def get_type(self):
        return self.ida_type
