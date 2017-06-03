import os
CONFIG = {
    'database': './ida_info.sqlite3',
    'out_dir': './code_gen/',
    'black_list': os.path.dirname(os.path.abspath(__file__)) + '/black.list',
    'verbose': False,
    'sql_verbose': False,
    'page_size': 1000
}
