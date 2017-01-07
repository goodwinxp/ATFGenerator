from pida_tfunction import IdaTFunctions
from pida_ttypedef import IdaTTypedef
from pida_tstruct import IdaTStruct
from pida_tarray import IdaTArray
from pida_tenum import IdaTEnum
from pida_tbase import IdaTBase
from pida_types import IDA_TYPES

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
    IDA_TYPES['array']: IdaTArray,
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
