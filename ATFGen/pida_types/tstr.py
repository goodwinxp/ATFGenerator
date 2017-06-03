from abc_type import IdaTypes
from types import IDA_TYPES


class IdaTStr(IdaTypes):
    def __init__(self, ida_type=IDA_TYPES['str']):
        self.ida_type = {'idt': ida_type, 'value': ''}

    def decode(self, data):
        count = ord(data[0])
        offset = 1
        for i in range(0, count):
            import ida_decoder

            rbyte, value = ida_decoder.decode_hybrid_type(ida_type=data[offset:])
            offset += rbyte
            self.ida_type['value'].append(value)

        return offset

    def get_type(self):
        return self.ida_type

    def to_string(self, session):
        return self.ida_type['value'] + '{ptr} {name}'

    def from_dict(self, data):
        self.ida_type = data
