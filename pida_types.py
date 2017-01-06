IDA_TYPES = {
    'void': 1,
    'int8_t': 2,
    'int16_t': 3,
    'int32_t': 4,
    'int64_t': 5,
    'short': 6,
    'int': 7,
    'bool': 8,
    'float': 9,
    'pointer': 10,
    'function': 12,
    'struct': 13,
    'double': 25,
    'array': 27,
    'uint8_t': 34,
    'uint16_t': 35,
    'uint32_t': 36,
    'uint64_t': 37,
    'ushort': 38,
    'uint': 39,
    'long double': 41,
    'enum': 45,
    'char': 50,
    'typedef': 61,
    'args': 114,
    'local_type': 0xff01  # Not ida type
}

IDA_TYPES_RW = {
    IDA_TYPES['void']: 'void',
    IDA_TYPES['int8_t']: 'int8_t',
    IDA_TYPES['int16_t']: 'int16_t',
    IDA_TYPES['int32_t']: 'int32_t',
    IDA_TYPES['int64_t']: 'int64_t',
    IDA_TYPES['short']: 'short',
    IDA_TYPES['int']: 'int',
    IDA_TYPES['bool']: 'bool',
    IDA_TYPES['float']: 'float',
    IDA_TYPES['pointer']: 'pointer',
    IDA_TYPES['function']: 'function',
    IDA_TYPES['struct']: 'struct',
    IDA_TYPES['double']: 'double',
    IDA_TYPES['array']: 'array',
    IDA_TYPES['uint8_t']: 'uint8_t',
    IDA_TYPES['uint16_t']: 'uint16_t',
    IDA_TYPES['uint32_t']: 'uint32_t',
    IDA_TYPES['uint64_t']: 'uint64_t',
    IDA_TYPES['ushort']: 'ushort',
    IDA_TYPES['uint']: 'uint',
    IDA_TYPES['long double']: 'long double',
    IDA_TYPES['enum']: 'enum',
    IDA_TYPES['char']: 'char',
    IDA_TYPES['typedef']: 'typedef',
    IDA_TYPES['args']: 'args',
    IDA_TYPES['local_type']: 'local_type'  # Not ida type
}


def is_const_type(e_type):
    if e_type & 0x40 == 0:
        return False

    return True


def get_base_name(e_type):
    search_type = e_type & 0xFFBF

    value = IDA_TYPES_RW.get(search_type, default='unknown')
    assert not value == 'unknown', e_type

    return value
