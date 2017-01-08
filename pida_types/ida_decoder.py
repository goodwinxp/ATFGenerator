from types import IDA_TYPES
from binding import PIDA_TYPES
from tlocal_type import IdaTLocalType, is_local_type


def decode_step(ida_type):
    itype = ord(ida_type[0])
    offset = 1
    if itype in [4, 5]:
        is_lt, ext = is_local_type(ida_type[offset:])
        if is_lt:
            offset += 2
            if ext:
                offset += 1

            ttype = PIDA_TYPES[IDA_TYPES['local_type']]()
            rbyte = ttype.decode(ida_type[offset:], ext=ext)
            offset += rbyte
            return offset, ttype.get_type()

    if itype == 0xfe and ord(ida_type[1]) == 0x10:
        # TODO : reverse this type
        offset += 1
        ttype = PIDA_TYPES[IDA_TYPES['struct']]()
        rbyte = ttype.decode(ida_type[offset:])
        offset += rbyte
        return offset, ttype.get_type()

    if itype in [0xfe, 0xff]:
        itype = ord(ida_type[offset])
        offset += 1

    # clear flag const
    itype &= 0xffbf

    ttype = PIDA_TYPES[itype](itype)
    rbyte = ttype.decode(ida_type[offset:])
    offset += rbyte

    return offset, ttype.get_type()


# this method can be call ONLY TStruct and TTypedef
def decode_hybrid_type(ida_type):
    value = {'idt': None, 'value': None}
    rbyte = ord(ida_type[0])
    is_lt, ext = is_local_type(ida_type)
    if not is_lt:
        value = {'idt': IDA_TYPES['str'], 'value': ida_type[1:rbyte]}
        return rbyte, value

    offset = 2
    if rbyte == 5:
        offset += 1

    local_type = IdaTLocalType()
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
