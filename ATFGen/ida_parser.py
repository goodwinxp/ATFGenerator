import os
import re
import models_ida
import models_parser
import util_parser

from config import CONFIG
from sqlalchemy import select
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.expression import func
from pida_types.types import IDA_TYPES


class IdaInfoParser(object):
    def __init__(self, db_file):
        self.db_file = db_file
        self.Session = sessionmaker()
        self.pattern_member = re.compile('(.*) .*\w+')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.commit()

    def start(self):
        self.__create_connection()
        self.__drop_tables()
        self.__create_tables()
        self.__create_session()
        self.__parsing()
        self.__fetch_depend()
        self.__linking()

    def __parsing(self):
        self.__parsing_functions()
        self.__parsing_local_types()

    def __fetch_depend(self):
        self.__fetch_depend_functions()
        self.__fetch_depend_local_types()
        self.__fetch_depend_typedefs()

    def __linking(self):
        self.__linking_functions()
        self.__linking_local_types()

    def __drop_tables(self):
        models_parser.Base.metadata.drop_all(self.engine_db)

    def __create_tables(self):
        models_ida.Base.metadata.create_all(self.engine_db)
        models_parser.Base.metadata.create_all(self.engine_db)

    def __create_session(self):
        self.Session.configure(bind=self.engine_db, autocommit=False)
        self.session = self.Session()

    def __create_connection(self):
        base_dir = os.path.dirname(self.db_file)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        if not os.path.exists(self.db_file):
            open(self.db_file, 'a').close()

        self.engine_db = create_engine('sqlite:///' + self.db_file, echo=CONFIG['sql_verbose'])

    def __parsing_functions(self):
        query = self.session.query(models_ida.IdaRawFunctions)
        count = query.count()
        if CONFIG['verbose']:
            print 'count functions: {count}'.format(count=count)

        index_item = 0
        functions = []
        for item in query.all():
            index_item += 1
            function = models_parser.Function(
                id_ida=item.get_id(),
                raw_name=item.get_name(),
                ida_type=item.get_type(),
                ida_fields=item.get_args_name(),
            )
            try:
                function.parsing()
                functions.append(function)
            except Exception as e:
                print '[Error] function with id = {id}. catch exception = {excpt}'.format(id=item.get_id(), excpt=e)

            if CONFIG['verbose']:
                if (index_item % CONFIG['page_size'] == 0) or (count - index_item == 0):
                    print 'items({current}/{count_item})'.format(current=index_item, count_item=count)

        self.session.bulk_save_objects(functions)
        self.session.commit()

    def __parsing_local_types(self):
        query = self.session.query(models_ida.IdaRawLocalType)
        count = query.count()
        if CONFIG['verbose']:
            print 'count local_type: {count}'.format(count=count)

        index_item = 0
        local_types = []
        for item in query.all():
            index_item += 1
            local_type = models_parser.LocalType(
                id_ida=item.get_id(),
                raw_multi=item.get_type(),
            )
            local_type.parsing()
            local_types.append(local_type)

            if CONFIG['verbose']:
                if (index_item % CONFIG['page_size'] == 0) or (count - index_item == 0):
                    print 'items({current}/{count_item})'.format(current=index_item, count_item=count)

        self.session.bulk_save_objects(local_types)
        self.session.commit()

    def __fetch_local_type(self, all_types):
        local_types = []
        for t in all_types:
            a_type = t
            while True:
                value = a_type['value']
                if a_type['idt'] == IDA_TYPES['local_type']:
                    local_types.append(a_type)
                    break

                elif a_type['idt'] == IDA_TYPES['function']:
                    local_types.extend(self.__fetch_local_type(value['args_type']))
                    value = value['ret_type']

                elif a_type['idt'] == IDA_TYPES['array']:
                    value = value['type']

                if type(value) is not type({}):
                    break

                a_type = value

        return local_types

    def __fetch_depend_functions(self):
        query = self.session.query(models_parser.Function)
        count = query.count()
        if CONFIG['verbose']:
            print 'count functions: {count}'.format(count=count)

        function_deps = []
        index_item = 0
        for item in query.all():
            index_item += 1
            all_types = item.get_args_type()
            all_types.append(item.get_return_type())

            dep_types = self.__fetch_local_type(all_types)

            for dep_type in dep_types:
                depend = models_parser.DependFunction(
                    id_function=item.get_id(),
                    id_local_type=dep_type['value']
                )
                function_deps.append(depend)

            if CONFIG['verbose']:
                if (index_item % CONFIG['page_size'] == 0) or (count - index_item == 0):
                    print 'items({current}/{count_item})'.format(current=index_item, count_item=count)

        self.session.bulk_save_objects(function_deps)
        self.session.commit()

    def __fetch_members(self, one_line):
        local_types = set()

        bracket = [one_line.find('{'), one_line.rfind('}')]
        if -1 in bracket:
            return local_types

        raw_parents = one_line[:bracket[0] - 1]
        inheritance = raw_parents.find(':')
        if inheritance != -1:
            parents = raw_parents[inheritance + 1:]
            tmpl_pairs = list(util_parser.get_pairs_sym(parents, '<', '>'))
            if 0 == len(tmpl_pairs):
                local_types.update(parents.split(','))
            else:
                sets = set()
                for tmpl_pair in tmpl_pairs:
                    count_join = 0
                    for tmpl_pair2 in tmpl_pairs:
                        if not tmpl_pair2[0] <= tmpl_pair[0] <= tmpl_pair2[1]:
                            continue

                        if not tmpl_pair2[0] <= tmpl_pair[1] <= tmpl_pair2[1]:
                            continue

                        count_join += 1

                    sets.add((count_join, tmpl_pair))

                parents += ','
                for v in sets:
                    (count, pair) = v
                    if count != 1:
                        continue

                    if parents[pair[1] + 1] == ',':
                        parents = parents[:pair[1] + 1] + '!' + parents[pair[1] + 1:]

                for parent in parents.split('!,'):
                    local_types.add(parent.strip())

        raw_members = one_line[bracket[0] + 1:bracket[1]]
        for member in raw_members.split(';'):
            type_member = self.pattern_member.search(member)
            if type_member is None:
                continue

            type_member = type_member.group(1).strip()
            local_types.add(type_member)

        ret_local_types = set()
        for lt in local_types:
            ret_local_types.add(lt.strip())

        return ret_local_types

    def __fetch_depend_local_types(self):
        local_types_table = (
            select([models_parser.LocalType.id_ida]).where(models_parser.LocalType.e_type.in_(['struct', 'union']))
        )

        query = self.session.query(models_ida.IdaRawLocalType) \
            .filter(models_ida.IdaRawLocalType.id_ida.in_(local_types_table)) \
            .order_by(models_ida.IdaRawLocalType.id)

        count = query.count()
        if CONFIG['verbose']:
            print 'count local_type: {count}'.format(count=count)

        index_item = 0
        local_type_deps = []
        for item in query.all():
            index_item += 1
            members_type = self.__fetch_members(item.get_one_line())
            if len(members_type):
                id_members_q = (
                    select([models_ida.IdaRawLocalType.id_ida]).where(models_ida.IdaRawLocalType.name.in_(members_type))
                )

                dep_types = self.session.query(id_members_q).all()

                for dep_type in dep_types:
                    if item.get_id() != dep_type.id_ida:
                        depend = models_parser.DependLocalType(
                            id_local_type=item.get_id(),
                            id_depend=dep_type.id_ida
                        )
                        local_type_deps.append(depend)

            if CONFIG['verbose']:
                if (index_item % CONFIG['page_size'] == 0) or (count - index_item == 0):
                    print 'items({current}/{count_item})'.format(current=index_item, count_item=count)

        self.session.bulk_save_objects(local_type_deps)
        self.session.commit()

    def __fetch_depend_typedefs(self):
        local_types_table = (
            select([models_parser.LocalType.id_ida]).where(models_parser.LocalType.e_type == 'typedef')
        )

        query = self.session.query(models_ida.IdaRawLocalType) \
            .filter(models_ida.IdaRawLocalType.id_ida.in_(local_types_table)) \
            .order_by(models_ida.IdaRawLocalType.id)

        count = query.count()
        if CONFIG['verbose']:
            print 'count typedef: {count}'.format(count=count)

        index_item = 0
        local_type_deps = []
        for item in query.all():
            index_item += 1

            type_member = self.pattern_member.search(item.get_one_line())
            id_members_q = (
                select([models_ida.IdaRawLocalType.id_ida]).where(
                    models_ida.IdaRawLocalType.name == type_member.group(1).strip())
            )

            dep_type = self.session.query(id_members_q).one_or_none()
            if dep_type is not None and item.get_id() != dep_type.id_ida:
                depend = models_parser.DependLocalType(
                    id_local_type=item.get_id(),
                    id_depend=dep_type.id_ida
                )
                local_type_deps.append(depend)

            if CONFIG['verbose']:
                if (index_item % CONFIG['page_size'] == 0) or (count - index_item == 0):
                    print 'items({current}/{count_item})'.format(current=index_item, count_item=count)

        self.session.bulk_save_objects(local_type_deps)
        self.session.commit()

    def __linking_functions(self):
        query = self.session.query(models_parser.Function)
        count = query.count()
        if CONFIG['verbose']:
            print 'count local_type: {count}'.format(count=count)

        index_item = 0
        function_link = []
        for item in query.all():
            index_item += 1
            owner_name = item.get_owner_name()

            depend = models_parser.LinkFunctions(
                id_function=item.get_id(),
                owner_name=owner_name
            )
            function_link.append(depend)

            if CONFIG['verbose']:
                if (index_item % CONFIG['page_size'] == 0) or (count - index_item == 0):
                    print 'items({current}/{count_item})'.format(current=index_item, count_item=count)

        self.session.bulk_save_objects(function_link)
        self.session.commit()

    def __link_local_types(self, parts):
        s_names = list()
        search_name = ''
        for p in parts:
            if len(search_name):
                search_name += '::'

            search_name += p
            s_names.append(search_name)

        q = self.session.query(models_ida.IdaRawLocalType) \
            .filter(models_ida.IdaRawLocalType.name.in_(s_names)) \
            .order_by(func.length(models_ida.IdaRawLocalType.name))

        for lt in q.all():
            yield (lt.get_id(), lt.get_name())

    def __linking_local_types(self):
        query = self.session.query(models_ida.IdaRawLocalType)

        count = query.count()
        if CONFIG['verbose']:
            print 'count local_type: {count}'.format(count=count)

        index_item = 0
        link_local_types = []
        link_namespaces = []
        for item in query.all():
            index_item += 1

            parts = list(util_parser.split_name(item.get_name()))
            id_local_types = list(self.__link_local_types(parts))

            if len(id_local_types) >= 2:
                link_lt = models_parser.LinkLocalType(
                    id_parent=id_local_types[-2][0],
                    id_child=item.get_id()
                )
                link_local_types.append(link_lt)

            link_namespace = ''
            _diff = len(parts) - len(id_local_types)
            if _diff == 0:
                link_namespace = None
            else:
                for p in parts[:_diff]:
                    if len(link_namespace):
                        link_namespace += '::'

                    link_namespace += p

            link = models_parser.LinkNamespace(
                id_local_type=item.get_id(),
                namespace=link_namespace
            )

            link_namespaces.append(link)
            if CONFIG['verbose']:
                if (index_item % CONFIG['page_size'] == 0) or (count - index_item == 0):
                    print 'items({current}/{count_item})'.format(current=index_item, count_item=count)

        self.session.bulk_save_objects(link_local_types)
        self.session.bulk_save_objects(link_namespaces)
        self.session.commit()
