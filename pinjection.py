##Copyright (C) 2020  Aitor Santoro
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
__VERSION__ = '0.7.1a'
__doc__ = '''
PInjection (Python Injection)
----------------------------

Description
-----------
    Python script to inject Python Bytecode or CodeType into
    the memory of an already open process.
    
'''
__docES__ = '''
PInjection (Python Injection)

Descripcion
-----------
    Libreria para inyectar CodeType o bytecode donde se te cante,
    en realidad en procesos que se estan ejecutando (Igual,
    OJO no vas a poder inyectar en el proceso "[System Process]" o
    "winlogon.exe", tampoco flashes kernel land, procesos tranqui,
    "explorer.exe" seria un buen target).
'''

from types import CodeType, FunctionType

import argparse

import ctypes
from ctypes import wintypes

import dis
import inspect
import importlib
import marshal
from pathlib import Path
import os
import sys


# * BEGIN .declarations

# * SECTION .WINDOWS_LIBRARIES
KERNEL32 = ctypes.WinDLL('kernel32.dll')
GetLastError = KERNEL32.GetLastError
# * SECTION .WINDOWS_LIBRARIES

WinError = ctypes.WinError

# * SECTION .WIN32-FUNCTIONS
OpenProcess = KERNEL32.OpenProcess
OpenProcess.argtypes = [
    wintypes.DWORD, #dwDesiredAccess
    wintypes.BOOL,  #bInheritHandle
    wintypes.DWORD  #dwProcessId
    ]
OpenProcess.restype = wintypes.HANDLE

CloseHandle = KERNEL32.CloseHandle
CloseHandle.argtypes = [
    wintypes.HANDLE #hObject
    ]
CloseHandle.restypes = wintypes.BOOL

ReadProcessMemory = KERNEL32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wintypes.HANDLE, #hProcess
    wintypes.LPCVOID,#lpBaseAddress
    wintypes.LPVOID, #lpBuffer
    ctypes.c_size_t, #nSize
    ctypes.c_size_t  #*lpNumberOfBytesRead
    ]
ReadProcessMemory.restypes = wintypes.BOOL

VirtualAllocEx = KERNEL32.VirtualAllocEx
VirtualAllocEx.argtypes = [
    wintypes.HANDLE, #hProcess
    wintypes.LPVOID, #lpAddress
    ctypes.c_size_t, #dwSize
    wintypes.DWORD,  #flAllocationType
    wintypes.DWORD,  #flProtect
    ]
VirtualAllocEx.restype = wintypes.DWORD

VirtualFreeEx = KERNEL32.VirtualFreeEx
VirtualFreeEx.argtypes = [
    wintypes.HANDLE,  #hProcess
    wintypes.LPVOID, #lpAddress
    ctypes.c_size_t, #dwSize
    wintypes.DWORD   #dwFreeType
    ]
VirtualFreeEx.restype = wintypes.BOOL

WriteProcessMemory = KERNEL32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    wintypes.HANDLE, #hProcess
    wintypes.LPVOID, #lpAddress
    wintypes.LPCVOID,#lpBuffer
    ctypes.c_size_t, #nSize,
    ctypes.c_size_t, #lp*NumberOfBytesWritten
    ]
WriteProcessMemory.restype = wintypes.BOOL
# * SECTION .WIN32-FUNCTIONS

# * SECTION .WIN32-PROCESS_ACCESS_RIGHTS
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SET_INFORMATION = 0x0200
PROCESS_TERMINATE = 0x0001
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ =  0x0010
PROCESS_VM_WRITE = 0x0020
# * SECTION .WIN32-PROCESS_ACCESS_RIGHTS

# * SECTION.WIN32-PAGE_CONSTANTS
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_TARGETS_INVALID = 0x40000000
PAGE_TARGETS_NO_UPDATE = 0x40000000

PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400
# * SECTION.WIN32-PAGE_CONSTANTS


# * SECTION .WIN32-MEMORY_CONSTANTS
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RESET = 0x00080000
MEM_RESET_UNDO = 0x10000000

MEM_LARGE_PAGES = 0x20000000
MEM_PHYSICAL = 0x00400000
MEM_TOP_DOWN = 0x00100000

MEM_DECOMMIT = 0x00004000
MEM_RELEASE = 0x00008000
# * SECTION .WIN32-MEMORY_CONSTANTS

# END .declarations


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
    def __init__(self, pid, base_address = 0,
        buffsize = 0, constants = {}, filename = '', function = None,
        obj = None, cle = False, verbose = False, debug = False):
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

base_address: int
    Base address of the allocated memory region (optional)
 
constants: dictionary
    A dictionary containing the constants for the function
 
filename: string
    The filename of the given function (optional)
    
function: FunctionType
    The given function to get the code  
    
obj: CodeType ('code')
    The code object that will be 'marshalized'
    
cle: bool
    If you are executing this from the Command Line,
    you will inject directly by passing the pid, but
    if you import this, you can use this file as a
    module.

verbose: bool
    Enables verbosity

debug: bool
    Enables debug mode
    
Returns
-------
None.
        ''' 
        # * Base address (returned from VirtualAllocEx).
        self.base_addr = base_address
        # * Buffer to work with.
        self.buff = bytes(buffsize)
        self.buffsize = buffsize
        # * Constants for the function to execute.
        self.constants = constants
        # * Command Line Execution
        self.cle = cle
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
        # * co. properties
        self.co = 0
        # * Marshaled version of the obj variable
        self.mobj = obj
        self.mobj_size = buffsize
        # * PID for the process handle
        self.pid = pid
        
        # * Arguments parser passing to class attribute.
        self.verbose = verbose
        self.debug = debug
        
        
        # * cle = Command Line Execution.
        if self.cle:
            if args.read:
                status = self.read()
            elif args.execute:
                status = self.execute()
            elif args.deallocate:
                status = self.deallocate()
            else:
                status = self.inject()
                
            if self.verbose:
                if status == None or status == True:
                    print(f"PInjection: Action completed successfully")
                else:
                    print("PInjection: Action not completed")
            
    def inject(self):
        '''Inject the obj to the given PID.'''
        # * Set the object if it is not already set.
        if not self.obj:
            self.setObj()
            if not self.obj:
                print("Unable to set the object")
                return
        
        self.mobj = marshal.dumps(self.obj)
        self.mobj_size = len(self.mobj)
        # * Set the buffer to the current length
        # * of the marshaled object
        self.buff = bytes(self.mobj_size)
        
        if self.verbose:
            print(f"Content to inject\n\n{self.mobj}\n")
            print(f"Size of content: {self.mobj_size}")
            print(f"Length of the buffer: {len(self.buff)}\n")
        
        # * HANDLE of the process
        self.hProc =  OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            False,
            self.pid
            )
        if self.verbose:
            print("VirtualAllocEx ... ", end='')
        # * Set the base address
        self.base_addr = VirtualAllocEx(
            self.hProc,
            0,
            self.mobj_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
            )
        
        if not self.base_addr:
            if self.verbose:
                print("NOT OK")
            else:
                print("")
            print(WinError(GetLastError()))
            return False

        if self.verbose:
            print("OK")
            print(f"Value returned from VirtualAllocEx {self.base_addr}")
            print(f"Size of bytes allocated {self.mobj_size}\n")

        if self.verbose:
            print(f"WriteProcessMemory base address: {self.base_addr}")
            print("WriteProcessMemory ... ", end = '')
        
        status = WriteProcessMemory(
            self.hProc,
            self.base_addr,
            self.mobj,
            self.mobj_size,
            0  
            )
        
            
        if not status:
            if self.verbose:
                print("NOT OK")
            else:
                print("")
            print(WinError(GetLastError()))
            return False
        if self.verbose:
            print("OK") 
            print(f"Value returned from WriteProcessMemory {status}")
        
        print(f"Correct injection in the process with PID {self.pid}")
        print(f"Base address - {hex(self.base_addr)}.")
            
    def setObj(self):
        '''Set 'obj' with the proper Code Object.'''
        byte_code = dis.Bytecode(self.function)
        self.co = byte_code.codeobj
        
        # * This tuple has the same order
        # * as CodeType parameters.
        
        self.obj = CodeType(
            self.co.co_argcount,
            self.co.co_kwonlyargcount,
            self.co.co_nlocals,
            self.co.co_stacksize,
            self.co.co_flags,
            self.co.co_code,
            self.co.co_consts,
            self.co.co_names,
            self.co.co_varnames,
            self.filename,
            self.co.co_name,
            self.co.co_firstlineno,
            self.co.co_lnotab
            )
        if self.verbose:
            self.printObj()
            
        return True
    
    def printObj(self, pause=False):
        '''Print the disassembled functions properties.'''
        if not self.obj:
            print("There is no object to display")
            return False
        print(f'\nco.co_argcount {self.co.co_argcount}')
        print(f'co.co_kwonlyargcount {self.co.co_kwonlyargcount}')
        print(f'co.co_nlocals {self.co.co_nlocals}')
        print(f'co.co_stacksize {self.co.co_stacksize}')
        print(f'co.co_flags {self.co.co_flags}')
        print(f'co.co_code {self.co.co_code}')
        print(f'co.co_consts {self.co.co_consts}')
        print(f'co.co_names {self.co.co_names}')
        print(f'co.co_varnames {self.co.co_varnames}')
        print(f'co.co_filename {self.filename}')
        print(f'co.co_name {self.co.co_name}')
        print(f'co.co_firstlineno {self.co.co_firstlineno}')
        print(f'co.co_lnotab {self.co.co_lnotab}\n')
        if pause:
            os.system("pause")
        return True
        
        
    def read(self):
        '''Read the memory region from a process.'''
        if self.buffsize == 0:
            if self.cle:
                print(
                    "Buffer length is 0. Specify the buffer size with the "
                    "\"--buffsize N\" argument"
                    )
                return False
            else:
                print("Buffer length is 0. Specify the buffer size")
                return False
        
        if self.verbose:
            print("PInjection will read the process memory")
            print("Base address: 0x%08X"%self.base_addr)
            
        # * Check for hProcess
        if not self.hProc:
            if self.verbose:
                print("OpenProcess ... ", end='')
                
            self.hProc = OpenProcess(
                PROCESS_VM_READ,
                0,
                self.pid
                )    
            if not self.hProc:
                if self.verbose:
                    print("NOT OK")
                print(WinError(GetLastError()))
                print("")
                return False
        else:
            if self.verbose:
                print("OpenProcess ... ", end='')
            status = CloseHandle(self.hProc)
            if not status:
                if self.verbose:
                    print("NOT OK")
                print(WinError(GetLastError()))
                print("")
                return False
                
            if self.verbose:
                print("OpenProcess ... ", end='')
            self.hProc = OpenProcess(
                PROCESS_VM_READ,
                0,
                self.pid
                )    
            if not self.hProc:
                if self.verbose:
                    print("NOT OK")
                print(WinError(GetLastError()))
                print("")
                return False
             
        if self.verbose:
            print("OK")
            print("")
            print("ReadProcessMemory ... ", end='')
            
        status = ReadProcessMemory(
            self.hProc,
            self.base_addr,
            self.buff,
            self.buffsize,
            0
            )
        if not status:
            if self.verbose:
                print("NOT OK")
            print(f"{WinError(GetLastError())}\n")
            return False
            
        print("Content retrieved successfully")
        if self.verbose:
            print("OK")
            print(f"Content in buffer\n\n{self.buff}\n")
        return True
        
    def execute(self):
        '''Execute from the buffer.'''
        status = self.read()
        if not status:
            print('Failed to retrieve memory to the buffer.')
            print(f'Process PID - {self.pid}\n')
            return False
            
        # * Check if content is valid marshal or not.
        try:
            content = marshal.loads(self.buff)
        except TypeError as type_err:
            print("TypeError raised, unable to de-marshalize")
            if self.verbose:
                print("Error message")
                print(str(type_err))
            print("")
            return False
        except ValueError as value_err:
            print("ValueError raised, unable to de-marshalize")
            if self.verbose:
                print("Error message")
                print(str(value_err))
            print("")
            return False
        except EOFError as eof_err:
            print("EOFError raised, unable to de-marshalize")
            if self.verbose:
                print("Error message")
                print(str(eof_err))
            print("")
            return False
        
        try:
            if type(self.constants) != type({}):
                print("Invalid constants, function won't be executed")
                print("You must pass the constants with --constants\n")
                return False
            if self.verbose:
                print("Assignment of the crafted function ... ", end="")
            
            function = FunctionType(content, self.constants)
            if self.verbose:
                # * THIS OK IS FROM THE UPPER VERBOSITY ROUTINE.
                print("OK\n")
        except Exception as err:
            print("NOT OK")
            print("An error occurred in the function assignment\n")
            if self.verbose:
                print("Error message: ")
                print(f"{str(err)}\n")
                return False
                
        if self.verbose and not function:
            print("NOT OK\n")
            return False
        function()
        
        return True
    
    def deallocate(self):
        '''Use VirtualFree to deallocate the given memory region.'''
        
        # * Check for hProcess
        if not self.hProc:
            if self.verbose:
                print("OpenProcess ... ", end='')
                
            self.hProc = OpenProcess(
                PROCESS_VM_OPERATION,
                0,
                self.pid
                )    
            if not self.hProc:
                if self.verbose:
                    print("NOT OK")
                print(WinError(GetLastError()))
                print("")
                return False
        else:
            if self.verbose:
                print("OpenProcess ... ", end='')
            status = CloseHandle(self.hProc)
            if not status:
                if self.verbose:
                    print("NOT OK")
                print(WinError(GetLastError()))
                print("")
                return False
                
            if self.verbose:
                print("OpenProcess ... ", end='')
            self.hProc = OpenProcess(
                PROCESS_VM_OPERATION,
                0,
                self.pid
                )    
            if not self.hProc:
                if self.verbose:
                    print("NOT OK")
                print(WinError(GetLastError()))
                print("")
                return False
        
        if self.verbose:
            # * This ok is from the verbosity of the upper routine.
            print("OK\n")
            print(
                "PInjection will deallocate memory "
                f"from the process {self.pid}"
                )
            print("Base address: 0x%08X"%self.base_addr)
            print("VirtualFreeEx ... ", end='')
        
        status = VirtualFreeEx(
            self.hProc,
            self.base_addr, #lpAddress
            0,
            MEM_RELEASE
            )
        if not status:
            print("NOT OK")
            print(WinError(GetLastError()))
            return False
        else:
            if self.verbose:
                print("OK")
        
        print(
            "PInjector succesfully deallocated the memory region, ",
            end = '')
        print("base address 0x%08X"%self.base_addr)   
    

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(
        description = 'Inject bytecode or CodeType into a running process'
        )
    
    parser.add_argument(
        'pid', metavar='PID', type=int, nargs='+', 
        help = 'The PID of the process to inject'
        )
    parser.add_argument(
        '--function', metavar='Function',
        help = 'The module/function imported from a module separated by 3 underlines e.g '
        'myModuleWithoutDotPy___myfunction'
        )
        
    parser.add_argument(
        '--constants', metavar='File',
        help='A file containing a function called get_constants.'
            ' This function should return a constants dictionary')
    parser.add_argument(
        '--baseaddr', metavar='IntNumber', type = int,
        help = 'Base address of the region to read/deallocate'
        )
    
    parser.add_argument(
        '--buffsize', metavar='N', type = int, default = 0,
        help = 'Buffer size')
    
    parser.add_argument(
        '--read', action = 'store_true',
        help = 'Read the process memory (requires a base address)')
    parser.add_argument(
        '--execute', action = 'store_true',
        help = 'Try to execute marshalized Code object from the memory '
               '(Only works for test_function from testmodule.py,'
               ' enable debugmode to use this beta feature)')
    
    parser.add_argument(
        '--deallocate', action = 'store_true',
        help = 'Deallocate the memory regions with a given base address'
               ' (Requires --baseaddr)')
    
    parser.add_argument(
        '--filename', metavar='Filename', default='',
        help='The filename of the module (Optional)')
        
    parser.add_argument(
        '--debug', action='store_true',
        help='Enable debug mode')
    parser.add_argument(
        '--verbose', action='store_true',
        help = 'Can\'t stop talking')
        
    args = parser.parse_args()
    sys.path.append(os.getcwd())
    
    if args.function == None:
        func = ''
    else:
        module_function = args.function.split('___')
        module = module_function[0]
        
        module = importlib.import_module(module)
        func = module_function[1]
        func = getattr(module, func)
    if args.constants == None:
        constants = ''
    else:
        constantFile = importlib.import_module(args.constants)
        constants = constantFile.get_constants()
        if args.verbose:
            print(f"Constants\n{constants}\n")
            os.system("PAUSE")
    
    try:
        injection = Inject(
            args.pid[0], #pid
            base_address = args.baseaddr,
            buffsize = args.buffsize,
            constants = constants,
            function = func,
            filename = args.filename,
            verbose = args.verbose,
            debug = args.debug,
            cle = True
            )
    except ImportError as err:
        print(str(err))
        
    
    
