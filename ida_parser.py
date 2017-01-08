import os
import math
import models_ida
import models_parser

from config import CONFIG
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from paginate_sqlalchemy import SqlalchemyOrmPage


class IdaInfoParser(object):
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

    def __fetch_depend_functions(self):
        pass

    def __fetch_depend_local_types(self):
        pass

    def __linking_functions(self):
        pass

    def __linking_local_types(self):
        self.__linking_namespace()
        pass

    def __linking_namespace(self):
        pass
