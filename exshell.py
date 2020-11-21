import pinjection
import testmodule
import constantsfile
def shell(pid):
    pinject = pinjection.Inject(
        pid,
        function = testmodule.test_function,
        constants = constantsfile.get_constants(),
        verbose = True
        )
    cmd = input("> ")
    while not cmd in ("exit", "quit"):
        if cmd == "inject":
            pinject.inject()
        elif cmd == "deallocate":
            pinject.deallocate()
        elif cmd == "read":
            try:
                if pinject.base_addr == 0:
                    pass
                else:
                    pinject.base_addr = int(input("Set the base address to read: "))
            except Exception as err:
                print(f"Exception occurred: {str(err)}")
            if pinject.base_addr == 0:
                pass
            else:
                pinject.read()
        elif cmd == "execute":
            try:
                if pinject.base_addr == 0:
                    pass
                else:
                    pinject.base_addr = int(input("Set the base address to read: "))
            except Exception as err:
                print(f"Exception occurred: {str(err)}")

            if pinject.base_addr == 0:
                pass
            else:
                pinject.execute()
        elif cmd == "set baseaddr":
            try:
                if pinject.base_addr == 0:
                    pass
                else:
                    pinject.base_addr = int(input("Set the base address to read: "))
            except Exception as err:
                print(f"Exception occurred: {str(err)}")
        elif cmd == "set buffsize":
            try:
                pinject.buffsize = int(input("Buffer size: "))
                pinject.buff = bytes(pinject.buffsize)
            except Exception as err:
                print(f"Exception occurred: {str(err)}")
        elif cmd == "verbose":
            if pinject.verbose:
                pinject.verbose = False
            else:
                pinject.verbose = True
            print(f"Verbose set to {pinject.verbose}")
        elif cmd == "debug":
            if pinject.debug:
                pinject.debug = False
            else:
                pinject.debug = True
            print(f"Debug set to {pinject.debug}")
        elif cmd in ("?", "help", "ayuda"):
            print("""
Help message:

inject: Inject into the given PID
deallocate: Deallocate the memory region with base address of Inject.base_addr")
read: Prompt the base address (if it is 0) then read the memory region of it
execute: Prompt the base address (if it is 0) then execute the memory region of it
set baseaddr: Ask the base address to set
set buffsize: Ask the buffer size (this will also set the current buffer to a bytearray of the entered number, overwriting any previous saved buffer.)
verbose: Enable/disable verbosity
debug: Enable/disable debug
exit/quit: Quit application
            """)
        else:
            print("Invalid command")
        cmd = input("> ")
if __name__ == '__main__':
    _pid = int(input("PID: "))
    shell(_pid)
        
