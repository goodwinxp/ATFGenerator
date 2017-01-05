import os
import models_ida
import models_parser

from sqlalchemy import *
from sqlalchemy.orm import sessionmaker


class IdaCodeGen(object):
    def __init__(self, db_file, out_gen):
        self.db_file = db_file
        self.out_gen = out_gen
        self.Session = sessionmaker()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.commit()

    def start(self):
        self.__create_connection()
        self.__create_session()
        self.__code_gen()

    def __create_session(self):
        self.Session.configure(bind=self.engine_db, autocommit=False)
        self.session = self.Session()

    def __create_connection(self):
        base_dir = os.path.dirname(self.db_file)
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        if not os.path.exists(self.db_file):
            open(self.db_file, 'a').close()

        self.engine_db = create_engine('sqlite:///' + self.db_file, echo=True)

    def __code_gen(self):
        pass
