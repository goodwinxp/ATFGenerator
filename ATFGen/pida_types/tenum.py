from ida_types import IDA_TYPES
from tstruct import IdaTStruct


class IdaTEnum(IdaTStruct):
    def __init__(self, ida_type=IDA_TYPES['enum']):
        self.ida_type = {'idt': ida_type, 'value': []}
