from pida_abc_type import IdaTypes
from pida_types import IDA_TYPES
from pida_type_decoder import decode_step


class IdaTFunctions(IdaTypes):
    def __init__(self, ida_type=IDA_TYPES['function']):
        value = {
            'ret_type': {'idt': IDA_TYPES['void'], 'value': None},
            'args_type': [],
            'conv_call': {'idt': IDA_TYPES['str'], 'value': '__cdecl'}
        }
        self.ida_type = {
            'idt': ida_type,
            'value': value
        }

    def decode(self, ida_type):
        convention = get_convention_by_code(ord(ida_type[0]))
        self.ida_type['value']['conv_call'] = convention

        offset = 1
        # no return convention type
        if ord(ida_type[0]) == 175:
            offset += 2

        rbyte, ret_type = decode_step(ida_type[offset:])
        offset += rbyte
        self.ida_type['value']['ret_type'] = ret_type

        count_args = ord(ida_type[offset])
        offset += 1
        for i in range(0, count_args):
            rbyte, value = decode_step(ida_type[offset:])
            offset += rbyte
            self.ida_type['value']['args_type'].append(value)

        return offset

    def get_type(self):
        return self.ida_type

    def get_args(self):
        return self.ida_type['value']['args_type']

    def get_conv_call(self):
        return self.ida_type['value']['conv_call']

    def get_ret_type(self):
        return self.ida_type['value']['ret_type']


CONVENTION_CALL_NM = {
    '__cdecl': [48, 175],
    '__stdcall': [49, 81],
    '__pascal': [64],
    '__fastcall': [112]
}


def get_convention_by_code(code):
    rvalue = {'idt': IDA_TYPES['str'], 'value': '__cdecl'}
    for key, value in CONVENTION_CALL_NM.iteritems():
        if code in value:
            rvalue['value'] = key
            break

    return rvalue
