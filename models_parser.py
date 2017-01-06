import json
import pida_fields
import util_parser

from sqlalchemy import Column, ForeignKey, INTEGER, TEXT
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class LocalType(Base):
    __tablename__ = 'local_types'
    id = Column('id', INTEGER, primary_key=True)
    id_ida = Column('id_ida', INTEGER)
    e_type = Column('e_type', TEXT)

    def __init__(self, id_ida, raw_multi):
        self.id_ida = id_ida
        self.raw_multi = raw_multi

    def __repr__(self):
        return '{id_ida} : {e_type}'.format(
            id_ida=self.id_ida, e_type=self.e_type)

    def parsing(self):
        self.__parsing_type()

    def __parsing_type(self):
        value = u'unknown'
        types = [u'struct', u'union', u'enum', u'typedef', u'class']
        offset = 0
        if self.raw_multi.startswith(u'const '):
            offset = len(u'const ')

        for t in types:
            if self.raw_multi.startswith(t, offset):
                value = t
                break

        assert not value == u'unknown', self.raw_multi
        self.e_type = value


class Function(Base):
    __tablename__ = 'functions'
    id = Column('id', INTEGER, primary_key=True)
    id_ida = Column('id_ida', INTEGER)
    name = Column('name', TEXT)
    return_type = Column('return_type', TEXT)
    args_type = Column('args_type', TEXT)
    args_name = Column('args_name', TEXT)

    def __init__(self, id_ida, raw_name, ida_type, ida_fields):
        self.id_ida = id_ida
        self.raw_name = raw_name
        self.ida_type = ida_type
        self.ida_fields = ida_fields
        self.__parsing()

    def __repr__(self):
        return '{name} : {id_ida}'.format(
            name=self.name, id_ida=self.id_ida)

    def parsing(self):
        self.__parsing_name()
        self.__parsing_ret_type()
        self.__parsing_args_type()
        self.__parsing_args_name()
        self.__args_normalize()

    def __parsing_name(self):
        self.name = self.raw_name
        if not self.name:
            return

        arg_pair = util_parser.get_last_pair_sym(self.name, '\(', '\)')
        if arg_pair is not None:
            self.name = self.name[:arg_pair[0]]

        templ_pair = util_parser.get_last_pair_sym(self.name, '<', '>')
        if templ_pair is not None:
            if len(self.name) - 1 == templ_pair[1]:
                self.name = self.name[:templ_pair[0]]

        pos = self.name.rfind('::')
        if pos != -1:
            self.name = self.name[pos + 2:]

    def __parsing_args_type(self):
        args_type = []
        # TODO: decode ida_type
        self.args_type = json.dumps(args_type, separators=(',', ':'))

    def __parsing_args_name(self):
        fields = list(pida_fields.decode_name_fields(self.ida_fields))
        self.args_name = json.dumps(fields, separators=(',', ':'))

    def __parsing_ret_type(self):
        ret_type = None
        # TODO: decode ida_type
        self.return_type = json.dumps(ret_type, separators=(',', ':'))
        pass

    def __args_normalize(self):
        args_name = json.loads(self.args_name)
        args_type = json.loads(self.args_type)

        len_names = len(args_name)
        len_types = len(args_type)
        if len_types <= len_names:
            return

        for i in range(0, len_types - len_names):
            args_name.append('arg_{cur}'.format(cur=i))


class Namespace(Base):
    __tablename__ = 'namespaces'
    id = Column('id', INTEGER, primary_key=True)
    name = Column('name', TEXT)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '{name}'.format(
            name=self.name)


class LinkNamespace(Base):
    """
    This table show relation A(id_local_type) <-> B(id_namespace)
    Sample:
    namespace US
    {
        struct _mon_block_fld
        {
            ...
        }
    }

    relation _mon_block_fld <-> US
    """

    __tablename__ = 'link_namespace'
    id = Column('id', INTEGER, primary_key=True)
    id_local_type = Column('id_local_type', INTEGER, ForeignKey('local_types.id'))
    id_namespace = Column('id_namespace', INTEGER, ForeignKey('namespaces.id'))

    def __init__(self, id_local_type, id_namespace):
        self.id_local_type = id_local_type
        self.id_namespace = id_namespace

    def __repr__(self):
        return '{id_local_type} -> {id_namespace}'.format(
            id_local_type=self.id_local_type, id_namespace=self.id_namespace)


class LinkFunctions(Base):
    """
    This table show relation A(id_local_type) <-> B(id_function)
    Sample:
    struct _mon_block_fld
    {
        void set_position(...);
    }

    relation _mon_block_fld <-> set_position
    """
    __tablename__ = 'link_function'
    id = Column('id', INTEGER, primary_key=True)
    id_local_type = Column('id_local_type', INTEGER, ForeignKey('local_types.id'))
    id_function = Column('id_function', INTEGER, ForeignKey('functions.id'))

    def __init__(self, id_local_type, id_function):
        self.id_local_type = id_local_type
        self.id_function = id_function

    def __repr__(self):
        return '{id_function} -> {id_local_type}'.format(
            id_local_type=self.id_local_type, id_function=self.id_function)


class LinkLocalType(Base):
    """
    This table show relation A(id_child) <-> B(id_parent)
    Sample:
    struct _mon_block_fld
    {
        struct _dummy_position {
        ...
        };

        _dummy_position pos;
    }
    relation _dummy_position <-> _mon_block_fld
    """
    __tablename__ = 'link_local_type'
    id = Column('id', INTEGER, primary_key=True)
    id_parent = Column('id_parent', INTEGER, ForeignKey('local_types.id'))
    id_child = Column('id_child', INTEGER, ForeignKey('local_types.id'))

    def __init__(self, id_parent, id_child):
        self.id_parent = id_parent
        self.id_child = id_child

    def __repr__(self):
        return '{id_child} -> {id_parent}'.format(
            id_child=self.id_child, id_parent=self.id_parent)


class DependLocalType(Base):
    """
    This table show dependenceies A(id_local_type) from B(id_depend)
    Sample:
    struct _dummy_position {
        ...
    };

    struct _mon_block_fld
    {
        _dummy_position pos;
    }

    _mon_block_fld dependence from _mon_block_fld
    """
    __tablename__ = 'dep_local_type'
    id = Column('id', INTEGER, primary_key=True)
    id_local_type = Column('id_local_type', INTEGER, ForeignKey('local_types.id'))
    id_depend = Column('id_depend', INTEGER, ForeignKey('local_types.id'))

    def __init__(self, id_local_type, id_depend):
        self.id_local_type = id_local_type
        self.id_depend = id_depend

    def __repr__(self):
        return '{id_depend} -> {id_local_type}'.format(
            id_depend=self.id_depend, id_local_type=self.id_local_type)


class DependFunction(Base):
    """
    This table show dependenceies A(id_function) <-> B(id_local_type)
    Sample:
    struct _mon_block_fld
    {
        ...
    }

    void check_position(_mon_block_fld* a);

    check_position dependence from _mon_block_fld
    """
    __tablename__ = 'dep_function'
    id = Column('id', INTEGER, primary_key=True)
    id_function = Column('id_function', INTEGER, ForeignKey('functions.id'))
    id_local_type = Column('id_local_type', INTEGER, ForeignKey('local_types.id'))

    def __init__(self, id_function, id_local_type):
        self.id_function = id_function
        self.id_local_type = id_local_type

    def __repr__(self):
        return '{id_local_type} -> {id_function}'.format(
            id_local_type=self.id_local_type, id_function=self.id_function)
