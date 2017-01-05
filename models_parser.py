from sqlalchemy import Column, ForeignKey, INTEGER, TEXT
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class LocalType(Base):
    __tablename__ = 'local_types'
    id = Column('id', INTEGER, primary_key=True)
    id_ida = Column('id_ida', INTEGER)
    e_type = Column('e_type', TEXT)

    def __init__(self, id_ida, e_type):
        self.id_ida = id_ida
        self.e_type = e_type

    def __repr__(self):
        return '{id_ida} : {e_type}'.format(
            id_ida=self.id_ida, e_type=self.e_type)


class Function(Base):
    __tablename__ = 'functions'
    id = Column('id', INTEGER, primary_key=True)
    id_ida = Column('id_ida', INTEGER)
    name = Column('name', TEXT)
    return_type = Column('return_type', TEXT)
    args_type = Column('args_type', TEXT)
    args_name = Column('args_name', TEXT)

    def __init__(self, id_ida, name, return_type, args_type, args_name):
        self.id_ida = id_ida
        self.name = name
        self.return_type = return_type
        self.args_type = args_type
        self.args_name = args_name

    def __repr__(self):
        return '{name} : {id_ida}'.format(
            name=self.name, id_ida=self.id_ida)


class Namespace(Base):
    __tablename__ = 'namespaces'
    id = Column('id', INTEGER, primary_key=True)
    name = Column('name', TEXT)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '{name}'.format(
            name=self.name)


'''
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
'''


class LinkNamespace(Base):
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


'''
This table show relation A(id_local_type) <-> B(id_function)
Sample:
struct _mon_block_fld
{
    void set_position(...);
}

relation _mon_block_fld <-> set_position
'''


class LinkFunctions(Base):
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


'''
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
'''


class LinkLocalType(Base):
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


'''
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
'''


class DependLocalType(Base):
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


'''
This table show dependenceies A(id_function) <-> B(id_local_type)
Sample:
struct _mon_block_fld
{
    ...
}

void check_position(_mon_block_fld* a);

check_position dependence from _mon_block_fld
'''


class DependFunction(Base):
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
