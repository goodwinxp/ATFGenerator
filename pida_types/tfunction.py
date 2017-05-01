from abc_type import IdaTypes
from types import IDA_TYPES
from pida_types.serializer_ida_type import serialize_to_string


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
        from ida_decoder import decode_step

        raw_conv_type = ord(ida_type[0])
        convention = get_convention_by_code(raw_conv_type)
        self.ida_type['value']['conv_call'] = convention

        offset = 1
        # no return
        if raw_conv_type == 0xAF:
            offset += 2

        if not raw_conv_type == 0x21:
            rbyte, ret_type = decode_step(ida_type[offset:])
            offset += rbyte
            self.ida_type['value']['ret_type'] = ret_type

            # no args
            if raw_conv_type == 0x20:
                return offset

        count_args = ord(ida_type[offset])
        offset += 1
        for i in range(1, count_args):
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

    def build_def(self, session):
        tmpl = '{return_type} (WINAPIV{ptr} {name})({args_type})'
        ret_type = serialize_to_string(self.get_ret_type(), session).replace(' {name}', '').replace('{ptr}', '')
        args_type = list(
            [serialize_to_string(arg_type, session).replace(' {name}', '').replace('{ptr}', '') for arg_type in
             self.ida_type['value']['args_type']])

        return tmpl.format(return_type=ret_type,
                           ptr='{ptr}',
                           name='{name}',
                           args_type=', '.join([x for x in args_type]))

    def to_string(self, session):
        return self.build_def(session)

    def from_dict(self, data):
        self.ida_type = data


CONVENTION_CALL_NM = {
    '__cdecl': [0x20, 0x21, 0x30, 0xAF],
    '__stdcall': [0x31, 0x51],
    '__pascal': [0x40],
    '__fastcall': [0x70]
}


def get_convention_by_code(code):
    rvalue = {'idt': IDA_TYPES['str'], 'value': '__cdecl'}
    for key, value in CONVENTION_CALL_NM.iteritems():
        if code in value:
            rvalue['value'] = key
            break

    return rvalue
