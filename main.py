from ida_code_gen import IdaCodeGen
from ida_parser import IdaInfoParser

# TODO : path to database from arguments
# TODO : path to output directory for code generation

def main():
    parser = IdaInfoParser(
        "D:/raw_gen/ida_info.sqlite3")
    parser.start()

    code_gen = IdaCodeGen(
        "D:/raw_gen/ida_info.sqlite3",
        'D:/new_code_gen/')
    code_gen.start()


if __name__ == '__main__':
    main()
