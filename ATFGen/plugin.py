from config import CONFIG
from ida_dumper import IdaDumper
from ida_parser import IdaInfoParser
from ida_code_gen import IdaCodeGen

class ATFGenerator(object):
    def start(self):
        print '== start dump =='
        idaDumper = IdaDumper(CONFIG['database']);
        idaDumper.start()
        print '== complete =='
        
        print '== start parsing =='
        idaParser = IdaInfoParser(CONFIG['database']);
        idaParser.start()
        print '== complete =='
        
        print '== start generate =='
        idaCodeGen = IdaCodeGen(CONFIG['database'], CONFIG['out_dir']);
        idaCodeGen.start()
        print '== complete =='
        
