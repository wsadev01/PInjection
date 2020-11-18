##Copyright (C) 2020  torswq(systemnaut)
##
##    This program is free software: you can redistribute it and/or modify
##    it under the terms of the GNU General Public License as published by
##    the Free Software Foundation, either version 3 of the License, or
##    (at your option) any later version.
##
##    This program is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##    GNU General Public License for more details.
##
##    You should have received a copy of the GNU General Public License
##    along with this program.  If not, see <https://www.gnu.org/licenses/>.

__AUTHOR__ = 'torswq(systemnaut) <torsw@protonmail.com>'
__LICENSE__ = 'GNU GPLv3'
__VERSION__ = '0.2'
__doc__ = '''
PInjection (Python Injection)
----------------------------

Description
-----------
    Python script to inject Python Bytecode or CodeType into
    the memory of an already open process.
    
'''
__docES__ = '''
PInyeccion (Python Inyeccion

Descripcion
-----------
    Libreria para inyectar CodeType o bytecode donde se te cante,
    en realidad en procesos que se estan ejecutando (Igual,
    OJO no vas a poder inyectar en el proceso "[System Process]" o
    "winlogon.exe", tampoco flashes kernel land, procesos tranqui,
    "explorer.exe" seria un buen target).
'''
 
from ginutils import *
from types import CodeType, FunctionType

import argparse
import dis
import inspect
import importlib
import marshal
import sys


class Inject:
    '''
Description
-----------
    This is the main object of an injection.
        This class contains all the necessary
    information you need to know
    
    * PID of the injected process.
    * Number of bytes allocated in memory.
    * Base address of the memory region.
    * A handle to the process with the given PID.
    '''
    def __init__(self, pid, function = None, obj = None, filename = '', cle = False):
        '''
Description
-----------
    Initialize the necessary variables.
    
Parameters
----------
self: class
    The class itself.

pid: int
    PID of a given process

function: FunctionType
    The given function to get the code
    
filename: string
    The filename of the given function (optional)
    
obj: CodeType ('code')
    The code object that will be 'marshalized'
    
cle: bool
    If you are executing this from the Command Line,
    you will inject directly by passing the pid, but
    if you import this, you can use this file as a
    module.

Returns
-------
None.
        ''' 
        # * Base address (returned from VirtualAllocEx).
        self.base_addr = 0
        # * Buffer to work with.
        self.buff = bytes(0)
        # * Number of bytes allocated.
        self.bytes_allocated = 0
        # * See docstring
        self.filename = filename
        # * Module function from which bytecode will be allocated.
        self.function = function
        # * Handle to the process that will be allocated to.
        self.hProc = 0
        # * Status of the injection.
        self.injected = False
        # * CodeType of the function
        self.obj = obj
        # * Marshaled version of the obj variable
        self.mobj = obj
        self.mobj_size = 0
        # * PID for the process handle
        self.pid = pid
        
        # * cle = Command Line Execution.
        if cle:
            status = self.inject()
            return status
            
    def inject(self):
        '''Inject the obj to the given object'''
        # * Set the object if it is not already set.
        if not self.obj:
            self.obj = self.setObj()
            if self.obj == False:
                print("Unable to set the object")
                return

        self.mobj = marshal.dumps(self.obj)
        self.mobj_size = len(self.mobj)
        # * Set the buffer to the current length
        # * of the marshaled object
        self.buff = bytes(self.mobj_size)
        
        # * HANDLE of the process
        self.hProc =  OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            False,
            self.pid
            )
        if args.verbose:
            print("VirtualAllocEx ... ", end='')
        # * Set the base address
        self.base_addr = VirtualAllocEx(
            self.hProc,
            0,
            self.mobj_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
            )
        
        if not self.base_addr:
            if args.verbose:
                print("NOT OK")
            else:
                print("")
            print(WinError(GetLastError()))
            return False
            
        if args.verbose:
            print("OK")
            print(f"Value returned from VirtualAllocEx {self.base_addr}")
        
        if args.verbose:
            print("WriteProcessMemory ... ", end = '')
        status = WriteProcessMemory(
            self.hProc,
            self.base_addr,
            self.mobj,
            self.mobj_size,
            0  
            )
        
            
        if not status:
            if args.verbose:
                print("NOT OK")
            else:
                print("")
            print(WinError(GetLastError()))
            return False
        if args.verbose:
            print("OK") 
            print(f"Value returned from WriteProcessMemory {status}")
        
        print(f"Correct injection in the process with PID {self.pid}")
        print(f"Base address - {hex(self.base_addr)}.")
            
    def setObj(self):
        '''Set 'obj' with the proper Code Object'''
        byte_code = dis.Bytecode(self.function)
        co = byte_code.codeobj
        
        # * This tuple has the same order
        # * as CodeType parameters.
        obj = (
            co.co_argcount,
            co.co_kwonlyargcount,
            co.co_nlocals,
            co.co_stacksize,
            co.co_flags,
            co.co_code,
            co.co_consts,
            co.co_names,
            co.co_varnames,
            self.filename,
            co.co_name,
            co.co_firstlineno,
            co.co_lnotab
            )
        self.obj = CodeType(*obj)
        

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(
        description = 'Inject bytecode or CodeType into a running process'
        )
    
    parser.add_argument(
        'pid', metavar='PID', type=int, nargs='+', 
        help = 'The PID of the process to inject'
        )
    parser.add_argument(
        'module_function', metavar='Function',
        help = 'The module/function imported from a module separated by 3 underlines e.g '
        'myModuleWithoutDotPy___myfunction'
        )
    parser.add_argument('--verbose', metavar='Verbosity',
        help = 'Can\'t stop talking')
        
    args = parser.parse_args()
    
    module_function = args.module_function.split('___')
    module = module_function[0]
    try:
        module = importlib.import_module(module)
        function = module_function[1]
        function = getattr(module, function)
        
        injection = Inject(args.pid[0], function, cle = True)
    except ImportError as err:
        print(str(err))
        
    
    
