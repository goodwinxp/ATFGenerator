from abc_type import IdaTypes
from types import IDA_TYPES
from serializer_ida_type import serialize_to_string


class IdaTStruct(IdaTypes):
    def __init__(self, ida_type=IDA_TYPES['struct']):
        self.ida_type = {'idt': ida_type, 'value': []}

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
        return serialize_to_string(self.ida_type['value'][0], session)\
                   .replace(' {name}', '')\
                   .replace('{ptr}', '') + '{ptr} {name}'

    def from_dict(self, data):
        self.ida_type = data
