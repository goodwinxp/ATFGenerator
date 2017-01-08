from abc_type import IdaTypes
from types import IDA_TYPES


class IdaTPointer(IdaTypes):
    def __init__(self, ida_type=IDA_TYPES['pointer']):
        self.ida_type = {'idt': ida_type, 'value': None}

    def decode(self, data):
        from ida_decoder import decode_step

        rbyte, value = decode_step(ida_type=data)
        self.ida_type['value'] = value
        return rbyte

    def get_type(self):
        return self.ida_type
