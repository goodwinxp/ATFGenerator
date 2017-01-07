from types import IDA_TYPES
from tlocal_type import IdaTLocalType


def decode_step(ida_type):
    # TODO :
    pass


def decode_hybrid_type(ida_type):
    value = {'idt': None, 'value': None}
    rbyte = ord(ida_type[0])
    if not (ida_type[1] == '#' and rbyte in [4, 5]):
        value = {'idt': IDA_TYPES['str'], 'value': value[1:rbyte]}
        return rbyte, value

    offset = 2
    ext = False
    if rbyte == 5:
        offset += 1
        ext = True

    local_type = IdaTLocalType(ida_type=IDA_TYPES['local_type'])
    local_type.decode(ida_type[offset:], ext=ext)

    value = local_type.get_type()

    return rbyte, value


def decode_id(ida_id):
    normal_id = 0
    for c in ida_id:
        normal_id *= 0x40
        normal_id += (ord(c) & 0x7f)

    normal_id -= 0x40
    return normal_id
