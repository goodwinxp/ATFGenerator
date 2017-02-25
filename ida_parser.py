import os
import re
import math
import models_ida
import models_parser

from config import CONFIG
from sqlalchemy import select
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
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

        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            functions = []
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
            self.session.add_all(functions)
        self.session.commit()

    def __parsing_local_types(self):
        query = self.session.query(models_ida.IdaRawLocalType)
        count = query.count()
        count_page = int(math.ceil(count / float(CONFIG['page_size'])))
        if CONFIG['verbose']:
            print 'count local types: {count}'.format(count=count)
            print 'count page: {count_page}'.format(count_page=count_page)

        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            local_types = []
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
            self.session.add_all(local_types)
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

        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            function_deps = []
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
            self.session.add_all(function_deps)
        self.session.commit()

    # todo : fetch depend from template
    def __fetch_members(self, one_line):
        local_types = set()

        bracket = [one_line.find('{'), one_line.rfind('}')]
        if -1 in bracket:
            return local_types

        raw_name = one_line[bracket[1] + 2:]

        raw_parents = one_line[:bracket[0] - 1]
        inheritance = raw_parents.find(':')
        if inheritance != -1:
            local_types.update(
                raw_parents[inheritance + 1:].split(','))

        raw_members = one_line[bracket[0] + 1:bracket[1]]
        for member in raw_members.split(';'):
            type_member = self.pattern_member.search(member)
            if type_member is None:
                continue

            local_types.add(type_member.group(1).strip())

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

        for i in range(1, count_page + 1):
            page = SqlalchemyOrmPage(query, page=i, items_per_page=CONFIG['page_size'])
            local_type_deps = []
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
            self.session.add_all(local_type_deps)
        self.session.commit()

    def __linking_functions(self):
        pass

    def __linking_local_types(self):
        self.__linking_namespace()
        pass

    def __linking_namespace(self):
        pass
