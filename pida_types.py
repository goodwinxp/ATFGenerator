from pida_tfunction import IdaTFunctions
from pida_ttypedef import IdaTTypedef
from pida_tstruct import IdaTStruct
from pida_tenum import IdaTEnum
from pida_tbase import IdaTBase

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

    # Not ida type
    'local_type': 0xff01,
    'str': 0xff02
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

    # Not ida type
    IDA_TYPES['local_type']: 'local_type',
    IDA_TYPES['str']: 'str'
}

PIDA_TYPES = {
    IDA_TYPES['void']: IdaTBase,
    IDA_TYPES['int8_t']: IdaTBase,
    IDA_TYPES['int16_t']: IdaTBase,
    IDA_TYPES['int32_t']: IdaTBase,
    IDA_TYPES['int64_t']: IdaTBase,
    IDA_TYPES['short']: IdaTBase,
    IDA_TYPES['int']: IdaTBase,
    IDA_TYPES['bool']: IdaTBase,
    IDA_TYPES['float']: IdaTBase,
    IDA_TYPES['pointer']: None,
    IDA_TYPES['function']: IdaTFunctions,
    IDA_TYPES['struct']: IdaTStruct,
    IDA_TYPES['double']: IdaTBase,
    IDA_TYPES['array']: None,
    IDA_TYPES['uint8_t']: IdaTBase,
    IDA_TYPES['uint16_t']: IdaTBase,
    IDA_TYPES['uint32_t']: IdaTBase,
    IDA_TYPES['uint64_t']: IdaTBase,
    IDA_TYPES['ushort']: IdaTBase,
    IDA_TYPES['uint']: IdaTBase,
    IDA_TYPES['long double']: IdaTBase,
    IDA_TYPES['enum']: IdaTEnum,
    IDA_TYPES['char']: IdaTBase,
    IDA_TYPES['typedef']: IdaTTypedef,
    IDA_TYPES['args']: IdaTBase
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
