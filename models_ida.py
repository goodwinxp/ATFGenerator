from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class IdaRawName(Base):
    __tablename__ = 'ida_raw_names'
    id = Column('id', INTEGER, primary_key=True)
    name = Column('name', TEXT)
    address = Column('address', INTEGER)
    ida_type = Column('ida_type', BLOB)
    ida_fields = Column('ida_fields', BLOB)

    def __init__(self, name, address, ida_type, ida_fields):
        self.name = name
        self.address = address
        self.ida_type = ida_type
        self.ida_fields = ida_fields

    def __repr__(self):
        return '"{name}" : {address}'.format(
            name=self.name, address=self.address)


class IdaRawLocalType(Base):
    __tablename__ = 'ida_raw_local_types'
    id = Column('id', INTEGER, primary_key=True)
    id_ida = Column('id_ida', INTEGER)
    name = Column('name', TEXT)
    one_line = Column('one_line', TEXT)
    multi_line = Column('multi_line', TEXT)

    def __init__(self, id_ida, name, one_line, multi_line):
        self.id_ida = id_ida
        self.name = name
        self.one_line = one_line
        self.multi_line = multi_line

    def __repr__(self):
        return '"{name}" : {one_line}'.format(
            name=self.name, one_line=self.one_line)


class IdaRawFunctions(Base):
    __tablename__ = 'ida_raw_functions'
    id = Column('id', INTEGER, primary_key=True)
    start = Column('start', INTEGER)
    end = Column('end', INTEGER)
    ida_type = Column('ida_type', BLOB)
    ida_fields = Column('ida_fields', BLOB)
    mangled_name = Column('mangled_name', TEXT)
    short_name = Column('short_name', TEXT)
    long_name = Column('long_name', TEXT)

    def __init__(self, start, end, ida_type, ida_fields,
                 mangled_name, short_name, long_name):
        self.start = start
        self.end = end
        self.ida_type = ida_type
        self.ida_fields = ida_fields
        self.mangled_name = mangled_name
        self.short_name = short_name
        self.long_name = long_name

    def __repr__(self):
        return '"{name}" : {start}'.format(
            name=self.short_name, start=self.start)
