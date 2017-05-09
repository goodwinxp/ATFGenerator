import collections
import os
import re
import shutil

from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

import models_ida
import models_parser
import util_parser
from config import CONFIG
from pida_types.serializer_ida_type import serialize_to_string


class IdaCodeGen(object):
    def __init__(self, db_file, out_gen):
        self.db_file = db_file
        self.out_gen = out_gen
        self.Session = sessionmaker()
        self.reg_name = []
        self.black_list = []

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
        self.__generate_global_funcs()
        self.__generate_local_types()
        self.__generate_typedef_enum()
        self.__generate_registry()

    def __build_typedef_enum(self, _item, items_info, namespace):
        data = _item.get_type()
        if len(namespace):
            data = data.replace(namespace + '::', '')

        data = data[:-1] + ';'

        return (self.__replace_type(data), None)

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
        ids = list([func[0].get_id() for func in funcs])
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

        query = self.session.query(models_parser.Function, models_ida.IdaRawFunctions) \
            .filter((models_parser.Function.id_ida.in_(q_sub)) &
                    (models_parser.Function.name != '') &
                    (models_ida.IdaRawFunctions.id == models_parser.Function.id_ida) &
                    (models_ida.IdaRawFunctions.short_name != '') &
                    (models_ida.IdaRawFunctions.long_name != '') &
                    (models_ida.IdaRawFunctions.short_name is not None) &
                    (models_ida.IdaRawFunctions.long_name is not None))

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

    @staticmethod
    def __trimming_name(name):
        while True:
            pairs = util_parser.get_last_pair_sym(name, '<', '>')
            if pairs is not None:
                name = name[:pairs[0]] + name[pairs[1] + 1:]
            else:
                break

        name = name.replace(':', '_')
        return name

    @staticmethod
    def __add_padding(payload, level):
        padding = ''.join(['    ' for x in xrange(0, level)])
        payload = padding + payload
        payload = re.sub('\n', '\n' + padding, payload)

        return payload

    def __generate_type(self, item, fn_build):

        name = item.get_name()

        namespace = self.__get_namespace(item.get_id())
        if namespace is None:
            namespace = ''

        for bname in self.black_list:
            if re.search(pattern=bname, string=name) or re.search(pattern=bname, string=namespace):
                return

        is_template = False
        if name[len(namespace):].find('<') != -1:
            is_template = True
            with open(self.out_gen + '/detect_templates.log', 'a') as f_detect:
                f_detect.write('[WARNING] Found template type ' + repr(item) + '\n')

        item_info = (item, 0, self.__get_functions(item.get_name()), list(self.__fetch_childs(1, item.get_id())))

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
        dependencies = set([self.__trimming_name(dep.get_name()) for dep in dependencies])

        (payload, funcs) = fn_build(_item=item, items_info=item_info, namespace=namespace)

        self.__write_file(payload=payload, name=name, namespace=namespace, dependencies=dependencies, my_namespace=True)

        if funcs is not None and is_template is False:
            info_payload = '{info}'.format(
                info=self.__build_detail_info(items_info=item_info))

            array_info = 'hook_record {name}_functions[] = {{\n' \
                         '{rows}\n' \
                         '}};\n'.format(name=name, rows=self.__build_detail_array(items_info=item_info))

            detail_payload = '{init_ptr}\n{wrapper}\n{array}'.format(
                init_ptr=self.__build_detail_init_ptr(items_info=item_info),
                wrapper=self.__build_detail_wrapper(items_info=item_info),
                array=array_info)

            namespace_info = 'info'
            namespace_detail = 'detail'

            if namespace and len(namespace):
                namespace_info = namespace + '::info'
                namespace_detail = namespace + '::detail'

            self.__write_file(payload=info_payload,
                              name=name + '_info',
                              namespace=namespace_info,
                              dependencies=set([name]),
                              my_namespace=True)

            self.__write_file(payload=detail_payload,
                              name=name + '_detail',
                              namespace=namespace_detail,
                              dependencies=set([name + '_info']),
                              my_namespace=True)

            tmpl_registry = 'class {name}_registry : public IRegistry\n' \
                            '{{\n' \
                            '    public: virtual void registry() {{\n' \
                            '        auto& hook_core = CATFCore::get_instance();\n' \
                            '        for (auto& r : {namespace_detail}{name}_functions)\n' \
                            '            hook_core.reg_wrapper(r.pBind, r);\n' \
                            '    }}\n' \
                            '}};\n'

            self.reg_name.append('{name}_registry'.format(name=name))
            self.__write_file(payload=tmpl_registry.format(name=name, namespace_detail=namespace_detail),
                              name=name + '_registry',
                              namespace='registry',
                              dependencies=set([name + '_detail', './common/ATFCore']),
                              my_namespace=True)

    def __write_file(self, payload, name, namespace, dependencies, my_namespace):
        if namespace is None:
            namespace = ''

        parts_namespace = list(util_parser.split_name(namespace.replace('<', '').replace('>', '')))

        base_padding = 0
        if my_namespace:
            base_padding = 1

        payload = self.__add_padding(payload=payload, level=base_padding + len(parts_namespace))

        name = self.__trimming_name(name)
        filename = self.out_gen + '/' + name + '.hpp'
        if not os.path.exists(filename):
            with open(filename, 'w') as f_type:
                f_type.write(
                    '// This file auto generated by plugin for ida pro. Generated code only for x64. Please, dont change manually\n')
                f_type.write('#pragma once\n\n')
                f_type.write('#include "./common/common.h"\n')

        sort_name_deps = list(dependencies)
        sort_name_deps.sort()

        with open(filename, 'a') as f_type:
            for dep in sort_name_deps:
                f_type.write('#include "{dep_name}.hpp"\n'.format(dep_name=self.__trimming_name(dep)))

            f_type.write('\n')
            if my_namespace:
                f_type.write('\nSTART_ATF_NAMESPACE\n')

            index_nm = base_padding
            for nm in parts_namespace:
                padding = ''.join(['    ' for x in xrange(0, index_nm)])
                f_type.write('{padding}namespace {namespace}\n{padding}{{\n'.format(namespace=nm, padding=padding))
                index_nm += 1

            f_type.write(payload)

            for nm in reversed(parts_namespace):
                index_nm -= 1
                padding = ''.join(['    ' for x in xrange(0, index_nm)])
                f_type.write('\n{padding}}}; // end namespace {namespace}'.format(namespace=nm, padding=padding))

            if my_namespace:
                f_type.write('\nEND_ATF_NAMESPACE\n')

            f_type.close()

    @staticmethod
    def __replace_type(name):
        replacing_subs = [('this', '_this'),
                          ('__cdecl ', 'WINAPIV '),
                          ('_BOOL ', 'BOOL '),
                          ('_BYTE ', 'BYTE '),
                          ('_WORD ', 'WORD '),
                          ('_DWORD ', 'DWORD '),
                          ('_QWORD ', 'QWORD ')]
        for i in replacing_subs:
            name = name.replace(i[0], i[1])

        return name

    def __generate_functions(self, prefix, namespace, funcs, fn_builder):
        functions = dict()
        for value in funcs:
            (func, raw_func) = value
            functions.setdefault(raw_func.get_name(), []).append(value)

        functions = collections.OrderedDict(sorted(functions.items()))
        indx = 0
        for key, value in functions.iteritems():
            funcs = value
            for v in funcs:
                indx += 1
                (func, raw_func) = v
                func_name = func.get_name()
                if func_name.find('`') != -1:
                    continue

                if func_name.find('operator') != -1:
                    continue

                if raw_func.get_size() == 5 and len(funcs) > 1:
                    continue

                clean_owner = func.get_owner_name()
                if clean_owner is None:
                    clean_owner = ''

                if namespace and len(namespace):
                    clean_owner = clean_owner.replace(namespace + '::', '')

                clean_owner = self.__trimming_name(clean_owner)
                if func_name.startswith('~'):
                    yield fn_builder(v, func_name, True, indx, prefix)
                    func_name = 'dtor_' + func_name[1:]
                elif clean_owner.endswith(func_name):
                    yield fn_builder(v, func_name, True, indx, prefix)
                    func_name = 'ctor_' + func_name

                yield fn_builder(v, func_name, False, indx, prefix)

    def __build_local_type(self, _item, items_info, namespace):
        (item, level, funcs, childs) = items_info

        data = item.get_type()
        data = re.sub('\n ', '\n   ', data)

        align_size = 0
        align = re.search('struct .*__declspec\(align\(([0-9]+)', data)
        if align is not None:
            align_size = align.group(1).strip()
            data = re.sub('__declspec\(align\(([0-9]+)\)\) ', '', data)

        second_part = ''
        detail_include = ''
        data_childs = ''
        definition = ''
        members = ''
        pair_sym = util_parser.get_last_pair_sym(data, '{', '}')
        if pair_sym:
            definition = data[:pair_sym[0] + 1]
            second_part = data[pair_sym[1]:]
            members = self.__replace_type(data[pair_sym[0] + 1:pair_sym[1]])
        elif data.startswith('struct '):
            definition = data[:-1] + '\n{\n'
            second_part = '}\n' + data[-1:]

        if definition.find('<') != -1:
            definition = 'template<>\n' + definition

        for child in childs:
            (body, ign) = self.__build_local_type(_item, child, namespace)
            data_childs = '{prev_data}\n{new_data}'.format(prev_data=data_childs, new_data=body)

        name = item.get_name() + '::'
        if len(namespace):
            name = name.replace(namespace + '::', '')

        data_functions = ''.join(
            self.__generate_functions(prefix='', namespace=namespace, funcs=funcs,
                                      fn_builder=self.__build_adapter_function))
        if len(data_functions):
            data_functions = 'public:' + data_functions + '\n'

        data = '{first_part}{data_childs}{members}{functions}{second_part}'.format(
            first_part=definition,
            data_childs=data_childs,
            members=members,
            second_part=second_part,
            functions=data_functions).replace(name, '')

        if funcs is None or len(funcs) == 0:
            funcs = None

        if len(namespace):
            data = data.replace(namespace + '::', '')

        data = data.replace('__cppobj ', ' ')
        data = data.replace('__unaligned ', ' ')
        data = data[:-1] + ';'

        if align_size and level == 0:
            data = '#pragma pack(push, {align})\n{data}\n#pragma pack(pop)'.format(align=align_size, data=data)

        if level == 0:
            data += detail_include

        return (self.__add_padding(payload=data, level=level), funcs)

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

    def __build_adapter_function(self, info, name, dctor, indx, prefix):
        (func, raw_func) = info
        tmpl = '''
    {specifier}{return_type}{name}({args})
    {{
        using org_ptr = {return_type_typedef}(WINAPIV*)({args_type});
        {org_return}(org_ptr({org_address}))({name_args});
    }};'''
        args_name = func.get_args_name()
        args_type = list(
            [serialize_to_string(arg_type, self.session).replace('{ptr}', '') for arg_type in func.get_args_type()])
        ret_type = serialize_to_string(func.get_return_type(), self.session).replace('{ptr}', '').replace(' {name}', '')

        org_return = 'return '
        if ret_type == 'void' or dctor:
            org_return = ''

        ret_type += ' '
        return_type_typedef = ret_type
        if dctor:
            ret_type = ''

        specifier = ''
        start_indx = 1
        name_args = ', '.join([x for x in args_name])
        if raw_func.get_long_name().find('static ') != -1:
            start_indx = 0
            specifier = 'static '
            name_args = name_args.replace('this', '_this')

        if func.get_owner_name() is None:
            start_indx = 0
            name_args = name_args.replace('this', '_this')

        if ret_type.find('(WINAPIV') != -1:
            specifier = 'using {name}_ret = {definition};\n    ' + specifier
            specifier = specifier.format(name=name, definition=ret_type.strip())
            ret_type = name + '_ret '
            return_type_typedef = ret_type

        diff_len = len(args_name) - len(args_type)
        if diff_len > 0:
            args_name += list(['arg_name_{indx}'.format(indx) for indx in range(0, diff_len)])

        args = [args_type[indx].format(name=args_name[indx]) for indx in range(start_indx, len(args_name))]

        return tmpl.format(specifier=specifier,
                           return_type=ret_type,
                           return_type_typedef=return_type_typedef,
                           name=name,
                           args=self.__replace_type(', '.join([x for x in args])),
                           args_type=', '.join([x for x in args_type]).replace(' {name}', ''),
                           org_address=hex(raw_func.get_start()),
                           org_return=org_return,
                           name_args=name_args)

    def __build_detail_info(self, items_info):
        (item, level, funcs, childs) = items_info
        data_childs = ''
        for child in childs:
            body = self.__build_detail_info(child)
            if len(body):
                data_childs = '{prev_data}\n{new_data}'.format(prev_data=data_childs, new_data=body)

        return ''.join(
            self.__generate_functions(prefix=self.__trimming_name(item.get_name()),
                                      namespace=self.__get_namespace(item.get_id()), funcs=funcs,
                                      fn_builder=self.__build_info_detail)) + data_childs

    def __build_detail_init_ptr(self, items_info):
        (item, level, funcs, childs) = items_info
        data_childs = ''
        for child in childs:
            body = self.__build_detail_init_ptr(child)
            if len(body):
                data_childs = '{prev_data}\n{new_data}'.format(prev_data=data_childs, new_data=body)

        return ''.join(
            self.__generate_functions(prefix=self.__trimming_name(item.get_name()),
                                      namespace=self.__get_namespace(item.get_id()), funcs=funcs,
                                      fn_builder=self.__build_init_detail)) + data_childs

    def __build_detail_wrapper(self, items_info):
        (item, level, funcs, childs) = items_info
        data_childs = ''
        for child in childs:
            body = self.__build_detail_wrapper(child)
            if len(body):
                data_childs = '{prev_data}\n{new_data}'.format(prev_data=data_childs, new_data=body)

        return ''.join(
            self.__generate_functions(prefix=self.__trimming_name(item.get_name()),
                                      namespace=self.__get_namespace(item.get_id()), funcs=funcs,
                                      fn_builder=self.__build_wrapper_detail)) + data_childs

    def __build_detail_array(self, items_info):
        (item, level, funcs, childs) = items_info
        data_childs = ''
        for child in childs:
            body = self.__build_detail_array(child)
            if len(body):
                data_childs = '{prev_data}\n{new_data}'.format(prev_data=data_childs, new_data=body)

        return ''.join(
            self.__generate_functions(prefix=self.__trimming_name(item.get_name()),
                                      namespace=self.__get_namespace(item.get_id()), funcs=funcs,
                                      fn_builder=self.__build_array_detail)) + data_childs

    def __build_wrapper_detail(self, info, name, dctor, indx, prefix):
        if dctor or name.find('operator') != -1:
            return ''

        (func, raw_func) = info
        def_name = '{prefix}{name}{indx}'.format(prefix=self.__trimming_name(prefix), name=name, indx=indx)

        tmpl = '{return_type}{def_name}_wrapper({args})\n' \
               '{{\n' \
               '   {org_return}{def_name}_user({name_args});\n' \
               '}};\n'

        args_name = func.get_args_name()
        args_type = list(
            [serialize_to_string(arg_type, self.session).replace('{ptr}', '') for arg_type in func.get_args_type()])
        ret_type = serialize_to_string(func.get_return_type(), self.session).replace('{ptr}', '').replace(' {name}', '')

        org_return = 'return '
        if ret_type == 'void':
            org_return = ''

        args_name.append('{def_name}_next'.format(def_name=def_name))
        name_args = ', '.join([x.replace('this', '_this') for x in args_name])

        if ret_type.find('(WINAPIV') != -1:
            ret_type = name + '_ret '

        ret_type += ' '

        diff_len = len(args_name) - len(args_type)
        if diff_len > 0:
            args_name += list(['arg_name_{indx}'.format(indx) for indx in range(0, diff_len)])

        args = [args_type[indx].format(name=args_name[indx]) for indx in range(0, len(args_name))]

        return tmpl.format(def_name=def_name,
                           return_type=ret_type,
                           args=self.__replace_type(', '.join([x for x in args])),
                           args_type=', '.join([x for x in args_type]).replace(' {name}', ''),
                           org_return=org_return,
                           name_args=name_args)

    def __build_info_detail(self, info, name, dctor, indx, prefix):
        if dctor or name.find('operator') != -1:
            return ''

        def_name = '{prefix}{name}{indx}'.format(prefix=self.__trimming_name(prefix), name=name, indx=indx)
        (func, raw_func) = info
        tmpl = 'using {def_name}_ptr = {return_type}(WINAPIV*)({args_type_ptr});\n' \
               'using {def_name}_clbk = {return_type}(WINAPIV*)({args_type_clbk});\n'

        args_type = list(
            [serialize_to_string(arg_type, self.session).replace('{ptr}', '') for arg_type in func.get_args_type()])
        args_type.append('{def_name}_ptr'.format(def_name=def_name))
        ret_type = serialize_to_string(func.get_return_type(), self.session).replace('{ptr}', '').replace(' {name}', '')

        if ret_type.find('(WINAPIV') != -1:
            specifier = 'using {def_name}_ret = {definition};\n'
            specifier = specifier.format(def_name=def_name, definition=ret_type.strip())
            tmpl = specifier + tmpl
            ret_type = def_name + '_ret'

        ret_type += ' '

        return tmpl.format(return_type=ret_type,
                           def_name=def_name,
                           args_type_ptr=', '.join([x for x in args_type[:-1]]).replace(' {name}', ''),
                           args_type_clbk=', '.join([x for x in args_type]).replace(' {name}', ''))

    def __build_init_detail(self, info, name, dctor, indx, prefix):
        if dctor or name.find('operator') != -1:
            return ''

        def_name = '{prefix}{name}{indx}'.format(prefix=self.__trimming_name(prefix), name=name, indx=indx)
        tmpl = 'info::{def_name}_ptr {def_name}_next(nullptr);\n' \
               'info::{def_name}_clbk {def_name}_user(nullptr);\n'

        return tmpl.format(def_name=def_name)

    def __build_array_detail(self, info, name, dctor, indx, prefix):
        if dctor or name.find('operator') != -1:
            return ''

        (func, raw_func) = info
        def_name = '{prefix}{name}{indx}'.format(prefix=self.__trimming_name(prefix), name=name, indx=indx)
        tmpl = '{{   (LPVOID){org_address},\n' \
               '    (LPVOID *)&{def_name}_user,\n' \
               '    (LPVOID *)&{def_name}_next,\n' \
               '    (LPVOID)cast_pointer_function({def_name}_wrapper),\n' \
               '    (LPVOID)cast_pointer_function(({cast_type})&{fn_addr_name}) }},\n'

        cast_type = '{ret}({name_owner}*)({args_type})'
        args_type = list(
            [serialize_to_string(arg_type, self.session).replace('{ptr}', '') for arg_type in func.get_args_type()])
        ret_type = serialize_to_string(func.get_return_type(), self.session).replace('{ptr}', '').replace(' {name}', '')

        if ret_type.find('(WINAPIV') != -1:
            ret_type = name + str(indx) + '_ret'

        start_indx = 1
        name_owner = ''
        if raw_func.get_long_name().find('static ') != -1:
            start_indx = 0
        if func.get_owner_name() is None:
            start_indx = 0
        else:
            name_owner = func.get_owner_name() + '::'

        fn_addr_name = name_owner + name

        completed_args_type = list(
            [args_type[indx].replace(' {name}', '') for indx in range(start_indx, len(args_type))])

        completed_args_type = ', '.join(completed_args_type)

        return tmpl.format(def_name=def_name,
                           org_address=hex(raw_func.get_start()),
                           cast_type=cast_type.format(ret=ret_type, name_owner=name_owner,
                                                      args_type=completed_args_type),
                           fn_addr_name=fn_addr_name)

    def __generate_global_funcs(self):
        funcs = self.__get_functions(name=None)

        prefix = 'global'
        name = 'global'
        namespace = 'global'

        adapters_functions = ''.join(
            self.__generate_functions(prefix=prefix, namespace=namespace, funcs=funcs,
                                      fn_builder=self.__build_adapter_function))

        completed_deps = set()
        for dep in self.__get_deps_functions(funcs):
            root_struct = self.__fetch_parent(dep)
            completed_deps.add(root_struct)

        dependencies = set([val.get_name() for val in completed_deps])
        self.__write_file(payload=adapters_functions,
                          name=name,
                          namespace=namespace,
                          dependencies=dependencies,  # todo
                          my_namespace=True)

        array_info = 'hook_record {name}_functions[] = {{\n' \
                     '{rows}\n' \
                     '}};\n'.format(name=prefix, rows=''.join(
            self.__generate_functions(prefix=prefix, namespace=namespace, funcs=funcs,
                                      fn_builder=self.__build_array_detail)))

        init_ptr = ''.join(
            self.__generate_functions(prefix=prefix, namespace=namespace, funcs=funcs,
                                      fn_builder=self.__build_init_detail))

        wrapper = ''.join(
            self.__generate_functions(prefix=prefix, namespace=namespace, funcs=funcs,
                                      fn_builder=self.__build_wrapper_detail))

        detail_payload = '{init_ptr}\n{wrapper}\n{array}'.format(
            init_ptr=init_ptr,
            wrapper=wrapper,
            array=array_info)

        info_payload = ''.join(
            self.__generate_functions(prefix=prefix, namespace=namespace, funcs=funcs,
                                      fn_builder=self.__build_info_detail))
        namespace_info = 'info'
        namespace_detail = 'detail'

        if namespace and len(namespace):
            namespace_info = namespace + '::info'
            namespace_detail = namespace + '::detail'

        self.__write_file(payload=info_payload,
                          name=name + '_info',
                          namespace=namespace_info,
                          dependencies=set([name]),
                          my_namespace=True)

        self.__write_file(payload=detail_payload,
                          name=name + '_detail',
                          namespace=namespace_detail,
                          dependencies=set([name + '_info']),
                          my_namespace=True)

        self.reg_name.append('{name}_registry'.format(name=name))
        tmpl_registry = 'class {name}_registry : public IRegistry\n' \
                        '{{\n' \
                        '    public: virtual void registry() {{\n' \
                        '        auto& hook_core = CATFCore::get_instance();\n' \
                        '        for (auto& r : {namespace_detail}{name}_functions)\n' \
                        '            hook_core.reg_wrapper(r.pBind, r);\n' \
                        '    }}\n' \
                        '}};\n'

        self.__write_file(payload=tmpl_registry.format(name=name, namespace_detail=namespace_detail),
                          name=name + '_registry',
                          namespace='registry',
                          dependencies=set([name + '_detail', './common/ATFCore']),
                          my_namespace=True)

    def __generate_registry(self):
        tmpl_mng_wrapper = '''
class CATFCoreRegistry
{{
public:
    CATFCoreRegistry() {{
{create_obj}
    }};

    CATFCoreRegistry(const CATFCoreRegistry&){{}};

public:
    ~CATFCoreRegistry() {{
    }};

    static CATFCoreRegistry& get_instance() {{
        static CATFCoreRegistry instance;
        return instance;
    }};

public:
    void registry()
    {{
        for (auto& w : _wrappers)
            w->registry();
    }};

private:
    std::vector<ImplWrapper_ptr> _wrappers;
}};'''

        create_obj = '\n'.join(
            ['_wrappers.emplace_back(std::make_shared<registry::{name}>());'.format(name=n) for n in self.reg_name])

        self.__add_padding(create_obj, 2)
        dependencies = set()
        dependencies.update(self.reg_name)

        self.__write_file(payload=tmpl_mng_wrapper.format(create_obj=self.__add_padding(create_obj, 2)),
                          name='mng_wrapper',
                          namespace='',
                          dependencies=dependencies,
                          my_namespace=True)
        pass

    def __read_black_list(self):
        with open(CONFIG['black_list'], 'r') as f_list:
            self.black_list = list([line.strip() for line in f_list])

    def __code_gen(self):
        self.__read_black_list()
        self.__adjust_folder()
        self.__copy_common()
        self.__generate_code()
