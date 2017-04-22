import os
import re
import shutil
import models_ida
import models_parser
import util_parser

from config import CONFIG
from sqlalchemy import select
from sqlalchemy import create_engine
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

        self.engine_db = create_engine('sqlite:///' + self.db_file, echo=CONFIG['sql_verbose'])

    def __adjust_folder(self):
        shutil.rmtree(self.out_gen, ignore_errors=True)
        os.makedirs(self.out_gen)

    def __copy_common(self):
        common_dir = './common'
        shutil.copytree(common_dir, self.out_gen + common_dir)

    def __generate_code(self):
        self.__generate_local_types()
        self.__generate_typedef_enum()

    def __build_typedef_enum(self, item, items_info, namespace):
        data = item.get_type()
        if len(namespace):
            data = data.replace(namespace + '::', '')

        data = data[:-1] + ';'

        return data

    def __generate_typedef_enum(self):
        q_types = (
            select([models_parser.LocalType.id_ida]).where(
                models_parser.LocalType.e_type.in_(['enum', 'typedef']) & models_parser.LocalType.id_ida.notin_(
                    select([models_parser.LinkLocalType.id_child])))
        )

        query = self.session.query(models_ida.IdaRawLocalType) \
            .filter(models_ida.IdaRawLocalType.id_ida.in_(q_types)) \
            .order_by(models_ida.IdaRawLocalType.id)

        count = query.count()
        if CONFIG['verbose']:
            print 'count typedef/enums: {count}'.format(count=count)

        item_index = 0
        for t in query.all():
            item_index += 1
            self.__generate_type(t, self.__build_typedef_enum)

            if CONFIG['verbose']:
                if (item_index % CONFIG['page_size'] == 0) or (count - item_index == 0):
                    print 'items({current}/{count_item})'.format(current=item_index, count_item=count)

    def __get_namespace(self, id):
        query = self.session.query(models_parser.LinkNamespace) \
            .filter(models_parser.LinkNamespace.id_local_type == id)

        return query.one().get_namespace()

    def __get_childs(self, pid):
        q_sub = (
            select([models_parser.LinkLocalType.id_child]).where(models_parser.LinkLocalType.id_parent == pid)
        )

        query = self.session.query(models_ida.IdaRawLocalType) \
            .filter(models_ida.IdaRawLocalType.id_ida.in_(q_sub))

        return query.all()

    def __get_deps_functions(self, funcs):
        deps = set()
        ids = list([func.get_id() for func in funcs])
        if len(ids):
            for i in range(0, len(ids), 999):
                q_sub = (
                    select([models_parser.DependFunction.id_local_type]).where(
                        models_parser.DependFunction.id_function.in_(ids[i:i + 999]))
                )

                query = self.session.query(models_ida.IdaRawLocalType) \
                    .filter(models_ida.IdaRawLocalType.id_ida.in_(q_sub))

                deps.update(query.all())

        return deps

    def __get_deps_local_type(self, id):
        q_sub = (
            select([models_parser.DependLocalType.id_depend]).where(
                models_parser.DependLocalType.id_local_type == id)
        )

        query = self.session.query(models_ida.IdaRawLocalType) \
            .filter(models_ida.IdaRawLocalType.id_ida.in_(q_sub))

        return query.all()

    def __get_functions(self, name):
        q_sub = (
            select([models_parser.LinkFunctions.id_function]).where(models_parser.LinkFunctions.owner_name == name)
        )

        query = self.session.query(models_parser.Function) \
            .filter(models_parser.Function.id_ida.in_(q_sub))

        return query.all()

    def __fetch_childs(self, level, pid):
        items = self.__get_childs(pid)
        for i in items:
            yield (i, level, self.__get_functions(i.get_name()), list(self.__fetch_childs(level + 1, i.get_id())))

    def __fetch_parent(self, item):
        id = item.get_id()
        while True:
            query = self.session.query(models_parser.LinkLocalType) \
                .filter(models_parser.LinkLocalType.id_child == id)

            tmp_parent = query.one_or_none()
            if tmp_parent:
                id = tmp_parent.id_parent
            else:
                break

        parent = item
        if id != item.get_id():
            query = self.session.query(models_ida.IdaRawLocalType) \
                .filter(models_ida.IdaRawLocalType.id_ida == id)

            parent = query.one_or_none()

        return parent

    def __get_items_info(self, full_item):
        (item, level, funcs, childs) = full_item

        deps = set()
        deps.update(self.__get_deps_functions(funcs))
        deps.update(self.__get_deps_local_type(item.get_id()))

        completed_deps = set()
        for dep in deps:
            root_struct = self.__fetch_parent(dep)
            completed_deps.add(root_struct)

        yield (item, level, funcs, completed_deps)
        for c in childs:
            for x in self.__get_items_info(c):
                yield x

    def __trimming_name(self, name):
        while True:
            pairs = util_parser.get_last_pair_sym(name, '<', '>')
            if pairs is not None:
                name = name[:pairs[0]] + name[pairs[1] + 1:]
            else:
                break

        name = name.replace(':', '_')
        return name

    def __generate_type(self, item, fn_build):
        name = item.get_name()
        namespace = self.__get_namespace(item.get_id())
        if namespace is None:
            namespace = ''

        if name[len(namespace):].find('<') != -1:
            with open(self.out_gen + '/detect_templates.log', 'a') as f_detect:
                f_detect.write('[WARNING] Found template type ' + repr(item) + '\n')

        item_info = (item, 0, self.__get_functions(item.get_name()), list(self.__fetch_childs(1, item.get_id())))

        # todo : detect crosslink
        dependencies = set()
        for val in list(self.__get_items_info(item_info)):
            (i, level, funcs, deps) = val

            if level == 1:
                dependencies -= deps
                dependencies -= set([i])
            elif level == 0:
                dependencies = deps
                continue
            elif level > 1:
                dependencies -= deps

            for prefix in ['std::', 'stdext::']:
                if i.get_name().startswith(prefix):
                    with open(self.out_gen + '/detect_std.log', 'a') as f_detect:
                        f_detect.write('[WARNING] Found using ' + prefix + ' in ' + repr(i) + '\n')
                    break

        dependencies -= set([item])

        parts_namespace = list(util_parser.split_name(namespace.replace('<', '').replace('>', '')))
        padding = ''.join(['    ' for x in xrange(0, 1 + len(parts_namespace))])

        payload = fn_build(item=item, items_info=item_info, namespace=namespace)
        payload = padding + payload
        payload = re.sub('\n ', '\n   ', payload)
        payload = re.sub('\n', '\n' + padding, payload)

        name = self.__trimming_name(name)
        filename = self.out_gen + '/' + name + '.hpp'
        if not os.path.exists(filename):
            with open(filename, 'w') as f_type:
                f_type.write('// This file auto generated by plugin for ida pro. Please, dont change manually\n')
                f_type.write('#pragma once\n\n')
                f_type.write('#include "./common/common.h"\n')

        name_deps = set([self.__trimming_name(dep.get_name()) for dep in dependencies])

        sort_name_deps = list(name_deps)
        sort_name_deps.sort()

        with open(filename, 'a') as f_type:
            for dep in sort_name_deps:
                f_type.write('#include "{dep_name}.hpp"\n'.format(dep_name=self.__trimming_name(dep)))

            f_type.write('\n\nSTART_ATF_NAMESPACE\n')

            index_nm = 1
            for nm in parts_namespace:
                padding = ''.join(['    ' for x in xrange(0, index_nm)])
                f_type.write('{padding}namespace {namespace}\n{padding}{{\n'.format(namespace=nm, padding=padding))
                index_nm += 1

            f_type.write(payload)

            for nm in reversed(parts_namespace):
                index_nm -= 1
                padding = ''.join(['    ' for x in xrange(0, index_nm)])
                f_type.write('\n{padding}}}; // end namespace {namespace}'.format(namespace=nm, padding=padding))

            f_type.write('\nEND_ATF_NAMESPACE\n')
            f_type.close()

    def __build_local_type(self, item, items_info, namespace):
        data = item.get_type()

        align_size = 0
        align = re.search('struct .*__declspec\(align\(([0-9]+)', data)
        if align is not None:
            align_size = align.group(1).strip()
            data = re.sub('__declspec\(align\(([0-9]+)\)\) ', '', data)

        # todo :

        # items = child + parent
        # inserted_child = item[0]
        # for c in items[1:]
        # inserted_child += c

        # add trim_namespace::detail
        # add details

        if len(namespace):
            data = data.replace(namespace + '::', '')

        data = data.replace('__cppobj ', ' ')
        data = data.replace('__unaligned ', ' ')
        data = data[:-1] + ';'

        data = '#pragma pack(push, {align})\n{data}\n#pragma pack(pop)'.format(align=align_size, data=data)

        return data

    def __generate_local_types(self):
        q_types = (
            select([models_parser.LocalType.id_ida]).where(
                models_parser.LocalType.e_type.notin_(['enum', 'typedef']) & models_parser.LocalType.id_ida.notin_(
                    select([models_parser.LinkLocalType.id_child])))
        )

        query = self.session.query(models_ida.IdaRawLocalType) \
            .filter(models_ida.IdaRawLocalType.id_ida.in_(q_types)) \
            .order_by(models_ida.IdaRawLocalType.id)

        count = query.count()
        if CONFIG['verbose']:
            print 'count local_type: {count}'.format(count=count)

        item_index = 0
        for item in query.all():
            item_index += 1

            self.__generate_type(item, self.__build_local_type)

            if CONFIG['verbose']:
                if (item_index % CONFIG['page_size'] == 0) or (count - item_index == 0):
                    print 'items({current}/{count_item})'.format(current=item_index, count_item=count)

    def __code_gen(self):
        self.__adjust_folder()
        self.__copy_common()
        self.__generate_code()
