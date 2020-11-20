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
import os
import sys

# Declare the necessary structures and variables.

# * BEGIN .declarations

# * Major declarations
KERNEL32 = ctypes.WinDLL('kernel32.dll')
GetLastError = KERNEL32.GetLastError
WinError = ctypes.WinError

# * Function declarations and types configuration
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

VirtualFree = KERNEL32.VirtualFree
VirtualFree.argtypes = [
    wintypes.LPVOID, #lpAddress
    ctypes.c_size_t, #dwSize
    wintypes.DWORD   #dwFreeType
    ]
VirtualFree.restype = wintypes.BOOL

WriteProcessMemory = KERNEL32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    wintypes.HANDLE, #hProcess
    wintypes.LPVOID, #lpAddress
    wintypes.LPCVOID,#lpBuffer
    ctypes.c_size_t, #nSize,
    ctypes.c_size_t, #lp*NumberOfBytesWritten
    ]
WriteProcessMemory.restype = wintypes.BOOL

# * Process Access Rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SET_INFORMATION = 0x0200
PROCESS_TERMINATE = 0x0001
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ =  0x0010
PROCESS_VM_WRITE = 0x0020

# * Memory regions constants and variables
#   * Page constants
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

#   * Memory constants
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RESET = 0x00080000
MEM_RESET_UNDO = 0x10000000

MEM_LARGE_PAGES = 0x20000000
MEM_PHYSICAL = 0x00400000
MEM_TOP_DOWN = 0x00100000

MEM_DECOMMIT = 0x00004000
MEM_RELEASE = 0x00008000


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
    def __init__(self, pid, base_address = 0, buffsize = 0, filename = '', function = None, obj = None, cle = False):
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

Returns
-------
None.
        ''' 
        # * Base address (returned from VirtualAllocEx).
        self.base_addr = base_address
        # * Buffer to work with.
        self.buff = bytes(buffsize)
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
        # * Marshaled version of the obj variable
        self.mobj = obj
        self.mobj_size = buffsize
        # * PID for the process handle
        self.pid = pid
        
        
        # * cle = Command Line Execution.
        if self.cle:
            if args.read:
                status = self.read()
            else:
                status = self.inject()
                
            if args.verbose:
                if status == None or status == True:
                    print(f"PInjection: Action completed successfully")
                else:
                    print("PInjection: Action not completed")
            
    def inject(self):
        '''Inject the obj to the given PID.'''
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
        
        if args.verbose:
            print(f"Content to inject\n\n{self.mobj}\n")
            print(f"Size of content: {self.mobj_size}")
            print(f"Length of the buffer: {len(self.buff)}")
            print('')
        
        # * HANDLE of the process
        self.hProc =  OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
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
            MEM_RESERVE | MEM_COMMIT,
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
            print(f"Size of bytes allocated {self.mobj_size}")
            print('')
        
        if args.verbose:
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
        '''Set 'obj' with the proper Code Object.'''
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
        
        if args.verbose:
            print(f'co.co_argcount {co.co_argcount}')
            print(f'co.co_kwonlyargcount {co.co_kwonlyargcount}')
            print(f'co.co_nlocals {co.co_nlocals}')
            print(f'co.co_stacksize {co.co_stacksize}')
            print(f'co.co_flags {co.co_flags}')
            print(f'co.co_code {co.co_code}')
            print(f'co.co_consts {co.co_consts}')
            print(f'co.co_names {co.co_names}')
            print(f'co.co_varnames {co.co_varnames}')
            print(f'co.co_filename {self.filename}')
            print(f'co.co_name {co.co_name}')
            print(f'co.co_firstlineno {co.co_firstlineno}')
            print(f'co.co_lnotab {co.co_lnotab}')
            os.system('pause')
            print('')
        
        return CodeType(*obj)
    
    def read(self):
        '''Read the memory region from a process.'''
        if len(self.buff) == 0:
            if self.cle:
                print(
                    "Buffer length is 0. Specify the buffer size with the "
                    "\"--buffsize N\" argument"
                    )
                return False
            else:
                print("Buffer length is 0. Specify the buffer size")
                return False
        
        if args.verbose:
            print("PInjection will read the process memory")
            print("Base address: 0x%08X"%self.base_addr)
            
        if not self.hProc:
            if args.verbose:
                print("OpenProcess ... ", end='')
                
            self.hProc = OpenProcess(
                PROCESS_VM_READ,
                0,
                self.pid
                )    
            if not self.hProc:
                if args.verbose:
                    print("NOT OK")
                print(WinError(GetLastError()))
                print("")
                return False
        else:
            if args.verbose:
                print("OpenProcess ... ", end='')
            status = CloseHandle(self.hProc)
            if not status:
                if args.verbose:
                    print("NOT OK")
                print(WinError(GetLastError()))
                print("")
                return False
                
            if args.verbose:
                print("OpenProcess ... ", end='')
            self.hProc = OpenProcess(
                PROCESS_VM_READ,
                0,
                self.pid
                )    
            if not self.hProc:
                if args.verbose:
                    print("NOT OK")
                print(WinError(GetLastError()))
                print("")
                return False
        
             
        if args.verbose:
            print("OK")
            print("")
            print("ReadProcessMemory ... ", end='')
            
        status = ReadProcessMemory(
            self.hProc,
            self.base_addr,
            self.buff,
            self.mobj_size,
            0
            )
        if not status:
            if args.verbose:
                print("NOT OK")
            print(WinError(GetLastError()))
            print('')
        print("Content retrieved successfully")
        if args.verbose:
            print("OK")
            print(f"Content in buffer\n\n{self.buff}\n")
                
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
        '--filename', metavar='Filename', default='',
        help='The filename of the module (Optional)')
        
    parser.add_argument(
        '--debug', action='store_true',
        help='Enable debug mode')
    parser.add_argument(
        '--verbose', action='store_true',
        help = 'Can\'t stop talking')
        
    args = parser.parse_args()
    
    if args.function == None:
        func = ''
    else:
        module_function = args.function.split('___')
        module = module_function[0]
        module = importlib.import_module(module)
        func = module_function[1]
        func = getattr(module, func)
        
    try:
        injection = Inject(
            args.pid[0], #pid
            base_address = args.baseaddr,
            buffsize = args.buffsize,
            function = func,
            filename = args.filename,
            cle = True
            )
    except ImportError as err:
        print(str(err))
        
    
    