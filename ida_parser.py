import os
import re
import math
import models_ida
import models_parser
import util_parser

from config import CONFIG
from sqlalchemy import select
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from paginate_sqlalchemy import SqlalchemyOrmPage
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
        count_page = int(math.ceil(count / float(CONFIG['page_size'])))
        if CONFIG['verbose']:
            print 'count functions: {count}'.format(count=count)
            print 'count page: {count_page}'.format(count_page=count_page)

        functions = []
        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            for item in page.items:
                function = models_parser.Function(
                    id_ida=item.get_id(),
                    raw_name=item.get_name(),
                    ida_type=item.get_type(),
                    ida_fields=item.get_args_name(),
                )
                try:
                    function.parsing()
                    functions.append(function)
                except:
                    print '[Error] function with id = {id}. catch exception'.format(id=item.get_id())

            if CONFIG['verbose']:
                print 'page({current}/{count_page}) items({count_item})'.format(current=i, count_page=count_page,
                                                                                count_item=len(page.items))
        self.session.bulk_save_objects(functions)
        self.session.commit()

    def __parsing_local_types(self):
        query = self.session.query(models_ida.IdaRawLocalType)
        count = query.count()
        count_page = int(math.ceil(count / float(CONFIG['page_size'])))
        if CONFIG['verbose']:
            print 'count local types: {count}'.format(count=count)
            print 'count page: {count_page}'.format(count_page=count_page)

        local_types = []
        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            for item in page.items:
                local_type = models_parser.LocalType(
                    id_ida=item.get_id(),
                    raw_multi=item.get_type(),
                )
                local_type.parsing()
                local_types.append(local_type)

            if CONFIG['verbose']:
                print 'page({current}/{count_page}) items({count_item})'.format(current=i, count_page=count_page,
                                                                                count_item=len(page.items))
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
        count_page = int(math.ceil(count / float(CONFIG['page_size'])))
        if CONFIG['verbose']:
            print 'count functions: {count}'.format(count=count)
            print 'count page: {count_page}'.format(count_page=count_page)

        function_deps = []
        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            for item in page.items:
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
                print 'page({current}/{count_page}) items({count_item})'.format(current=i, count_page=count_page,
                                                                                count_item=len(page.items))
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
            select([models_parser.LocalType.id_ida])
                .where(models_parser.LocalType.e_type.in_(['struct', 'union']))
        )

        query = self.session.query(models_ida.IdaRawLocalType) \
            .filter(models_ida.IdaRawLocalType.id_ida.in_(local_types_table)) \
            .order_by(models_ida.IdaRawLocalType.id)

        count = query.count()
        count_page = int(math.ceil(count / float(CONFIG['page_size'])))
        if CONFIG['verbose']:
            print 'count local types: {count}'.format(count=count)
            print 'count page: {count_page}'.format(count_page=count_page)

        local_type_deps = []
        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            for item in page.items:
                members_type = self.__fetch_members(item.get_one_line())
                if len(members_type) == 0:
                    continue

                id_members_q = (
                    select([models_ida.IdaRawLocalType.id_ida])
                        .where(models_ida.IdaRawLocalType.name.in_(members_type))
                )

                dep_types = self.session.query(id_members_q).all()

                for dep_type in dep_types:
                    depend = models_parser.DependLocalType(
                        id_local_type=item.get_id(),
                        id_depend=dep_type.id_ida
                    )
                    local_type_deps.append(depend)

            if CONFIG['verbose']:
                print 'page({current}/{count_page}) items({count_item})'.format(current=i, count_page=count_page,
                                                                                count_item=len(page.items))
        self.session.bulk_save_objects(local_type_deps)
        self.session.commit()

    def __linking_functions(self):
        query = self.session.query(models_parser.Function)
        count = query.count()
        count_page = int(math.ceil(count / float(CONFIG['page_size'])))
        if CONFIG['verbose']:
            print 'count functions: {count}'.format(count=count)
            print 'count page: {count_page}'.format(count_page=count_page)

        function_link = []
        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            for item in page.items:
                owner_name = item.get_owner_name()

                depend = models_parser.LinkFunctions(
                    id_function=item.get_id(),
                    owner_name=owner_name
                )
                function_link.append(depend)

            if CONFIG['verbose']:
                print 'page({current}/{count_page}) items({count_item})'.format(current=i, count_page=count_page,
                                                                                count_item=len(page.items))
        self.session.bulk_save_objects(function_link)
        self.session.commit()

    def __split_name(self, name):
        br_open = 0
        delim = False
        indx = [0, 0]
        for ch in name:
            indx[1] += 1
            if ch == '<':
                br_open += 1
            elif ch == '>':
                br_open -= 1
            elif ch == ':' and br_open == 0:
                if not delim:
                    delim = True
                    continue

                yield name[indx[0]:indx[1] - 2]
                indx[0] = indx[1]
                delim = False

        yield name[indx[0]:indx[1]]

    def __linking_local_types(self):
        query = self.session.query(models_ida.IdaRawLocalType)

        count = query.count()
        count_page = int(math.ceil(count / float(CONFIG['page_size'])))
        if CONFIG['verbose']:
            print 'count local types: {count}'.format(count=count)
            print 'count page: {count_page}'.format(count_page=count_page)

        link_local_types = []
        link_namespaces = []
        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            for item in page.items:
                name = item.get_name()

                parts = list(self.__split_name(name))

                search_name = ''
                link_namespace = ''
                id_local_types = list()
                for p in parts:
                    if len(search_name):
                        search_name += '::'

                    search_name += p

                    id_local_type_q = (
                        select([models_ida.IdaRawLocalType.id_ida])
                            .where(models_ida.IdaRawLocalType.name == search_name)
                    )

                    id_local_type = self.session.query(id_local_type_q).one_or_none()
                    if id_local_type is None:
                        if len(id_local_types) == 0:
                            link_namespace = search_name
                        continue

                    if item.get_id() == id_local_type[0]:
                        continue

                    id_local_types.append(id_local_type[0])

                id_local_types.append(item.get_id())

                id_parent = id_local_types[0]
                for id in id_local_types[1:]:
                    link_lt = models_parser.LinkLocalType(
                        id_parent=id_parent,
                        id_child=id
                    )
                    id_parent = id
                    link_local_types.append(link_lt)

                if len(parts) == len(id_local_types) or len(link_namespace) == 0:
                    link_namespace = None

                link = models_parser.LinkNamespace(
                    id_local_type=item.get_id(),
                    namespace=link_namespace
                )

                link_namespaces.append(link)

            if CONFIG['verbose']:
                print 'page({current}/{count_page}) items({count_item})'.format(current=i, count_page=count_page,
                                                                                count_item=len(page.items))
        self.session.bulk_save_objects(link_local_types)
        self.session.bulk_save_objects(link_namespaces)
        self.session.commit()
