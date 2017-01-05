import sys, getopt
from ida_code_gen import IdaCodeGen
from ida_parser import IdaInfoParser


def print_help():
    print 'Options:'
    print ' -d, --database   path to database from arguments'
    print ' -o, --out_dir    path to output directory for code generation'
    print 'Example:'
    print ' python code_gen.py --database C:/ida_info.sqlite3 --out_dir C:/code_gen/'
    pass


def main(argv):
    db_file = './ida_info.sqlite3'
    out_dir = './code_gen/'

    try:
        opts, args = getopt.getopt(argv, 'hd:o:', ['database=', 'out_dir='])
    except getopt.GetoptError:
        print_help()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print_help()
            sys.exit()

        if opt in ('-d', '--database'):
            db_file = arg
            continue

        if opt in ('-o', '--out_dir'):
            out_dir = arg
            continue

    parser = IdaInfoParser(db_file)
    parser.start()

    code_gen = IdaCodeGen(db_file, out_dir)
    code_gen.start()


if __name__ == '__main__':
    main(sys.argv[1:])
