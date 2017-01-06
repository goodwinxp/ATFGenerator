import sys
import getopt

from config import CONFIG
from ida_code_gen import IdaCodeGen
from ida_parser import IdaInfoParser


def print_help():
    print 'Options:'
    print ' -d, --database   Path to database from arguments. Default = ' + CONFIG['database']
    print ' -o, --out_dir    Path to output directory for code generation. Default = ' + CONFIG['out_dir']
    print ' -v, --verbose    Verbose mode programm. Default = ' + str(CONFIG['verbose'])
    print ' --vverbose       Turn on sql echo. Default = ' + str(CONFIG['sql_verbose'])
    print 'Example:'
    print ' python code_gen.py -v --database C:/ida_info.sqlite3 --out_dir C:/code_gen/'


def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hvdo', ['help', 'verbose', 'vverbose', 'database=', 'out_dir='])
    except getopt.GetoptError:
        print_help()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print_help()
            sys.exit()

        if opt in ('-v', '--verbose'):
            CONFIG['verbose'] = True
            continue

        if opt == '--vverbose':
            CONFIG['sql_verbose'] = True
            continue

        if opt in ('-d', '--database'):
            CONFIG['database'] = arg
            continue

        if opt in ('-o', '--out_dir'):
            CONFIG['out_dir'] = arg
            continue

    if CONFIG['verbose']:
        print 'database: ' + CONFIG['database']
        print 'out_dir: ' + CONFIG['out_dir']
        print 'verbose: ' + str(CONFIG['verbose'])

    parser = IdaInfoParser(CONFIG['database'])
    parser.start()

    code_gen = IdaCodeGen(CONFIG['database'], CONFIG['out_dir'])
    code_gen.start()


if __name__ == '__main__':
    main(sys.argv[1:])
