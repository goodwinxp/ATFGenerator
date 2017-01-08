from abc_type import IdaTypes
from types import IDA_TYPES


class IdaTArray(IdaTypes):
    def __init__(self, ida_type=IDA_TYPES['array']):
        self.ida_type = {'idt': ida_type, 'value': {'count': 0, 'type': None}}

    def decode(self, data):
        from ida_decoder import decode_step

        count = ord(data[0])
        offset = 1
        if count > 0x80:
            count = 0x80 * ord(data[1])
            count |= ~(0x80 - ord(data[0]))
            offset = 2

        rbyte, value = decode_step(ida_type=data[offset:])
        offset += rbyte
        self.ida_type['value']['count'] = count
        self.ida_type['value']['type'] = value
        return offset

    def get_type(self):
        return self.ida_type
