from pida_abc_type import IdaTypes
from pida_types import IDA_TYPES
from pida_type_decoder import decode_hybrid_type


class IdaTEnum(IdaTypes):
    def __init__(self, ida_type=IDA_TYPES['enum']):
        self.ida_type = {'idt': ida_type, 'value': []}

    def decode(self, data):
        count = ord(data[0])
        offset = 1
        for i in range(0, count):
            len, value = decode_hybrid_type(ida_type=data[offset:])
            offset += len
            self.ida_type['value'].append(value)

        return offset

    def get_type(self):
        return self.ida_type
