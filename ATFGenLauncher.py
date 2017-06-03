import idaapi
from ATFGen.plugin import ATFGenerator

class ATFGenLauncher(idaapi.plugin_t):
    flags = 0
    comment = "Generator ATF framework"
    help = "help"
    wanted_name = "ATF Generator"
    wanted_hotkey = 'Ctrl+Alt+D'

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print "[*] ATF Generator: run"
        pluginImpl = ATFGenerator()
        pluginImpl.start()

    def term(self):
        print "[*] ATF Generator: terminated\n"

def PLUGIN_ENTRY():
    return ATFGenLauncher()
