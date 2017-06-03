import os
import idc
import idaapi
import idautils
import models_ida

from sqlalchemy import *
from sqlalchemy.orm import sessionmaker


class IdaDumper(object):
    TBL_RAW_NAMES = 0
    TBL_RAW_LOCAL_TYPES = 1
    TBL_RAW_FUNCTIONS = 2

    def __init__(self, db_file):
        self.db_file = db_file
        self.Session = sessionmaker()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.commit()

    def start(self):
        self.__create_connection()
        self.__drop_tables()
        self.__create_tables()
        self.__create_session()
        self.__dump()

    def __create_connection(self):
        base_dir = os.path.dirname(self.db_file)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        if not os.path.exists(self.db_file):
            open(self.db_file, 'a').close()

        self.engine_db = create_engine('sqlite:///' + self.db_file, echo=False)

    def __drop_tables(self):
        models_ida.Base.metadata.drop_all(self.engine_db)

    def __create_tables(self):
        models_ida.Base.metadata.create_all(self.engine_db)

    def __create_session(self):
        self.Session.configure(bind=self.engine_db, autocommit=False)
        self.session = self.Session()

    def __dump(self):
        self.__dump_functions()
        self.__dump_local_types()
        self.__dump_names()
        self.session.commit()

    def __dump_functions(self):
        functions = self.__get_functions()
        self.session.add_all(functions)

    def __dump_local_types(self):
        local_types = self.__get_local_types()
        self.session.add_all(local_types)

    def __dump_names(self):
        names = self.__get_names()
        self.session.add_all(names)

    def __get_functions(self):
        functions = list(idautils.Functions())
        for start_function in functions:
            tinfo = idc.GetTinfo(start_function)
            if tinfo is None:
                continue

            mangled_name = idc.GetFunctionName(start_function)

            demangled = {idc.INF_SHORT_DN: '', idc.INF_LONG_DN: ''}
            for record in demangled.iteritems():
                (type, value) = record
                demangled[type] = idc.Demangle(
                    mangled_name,
                    idc.GetLongPrm(type))

                ida_type, ida_fields = tinfo

            yield models_ida.IdaRawFunctions(start=start_function, end=idc.GetFunctionAttr(start_function, idc.FUNCATTR_END),
                                  ida_type=ida_type, ida_fields=ida_fields, mangled_name=mangled_name,
                                  short_name=demangled[idc.INF_SHORT_DN], long_name=demangled[idc.INF_LONG_DN])

    def __get_local_types(self):
        for id_ida in range(1, idc.GetMaxLocalType()):
            name = idc.GetLocalTypeName(id_ida)
            sizeType = 0
            sid = idc.GetStrucIdByName(name)
            if sid != -1:
                sizeType = idc.GetStrucSize(sid)
            
            one_line = idc.GetLocalType(id_ida, idc.PRTYPE_1LINE);
            multi_line = idc.GetLocalType(id_ida, idc.PRTYPE_MULTI | idc.PRTYPE_TYPE | idc.PRTYPE_PRAGMA);
            
            yield models_ida.IdaRawLocalType(id_ida=id_ida, sizeType=sizeType, name=name, one_line=one_line, multi_line=multi_line)

    def __get_names(self):
        names = list(idautils.Names())
        for record in names:
            ea, name = record
            ida_info = idc.GetTinfo(ea)
            if ida_info is None:
                continue

            ida_type, ida_fields = ida_info
            yield models_ida.IdaRawName(name=name, address=ea, ida_type=ida_type, ida_fields=ida_fields)
