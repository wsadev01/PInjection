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

'''Module containing general utilities, useful redefinitions and function'''


__author__ = 'Aitor Santoro <torsw@protonmail.com>'
__version__ = '1.0'
__license__ = 'LGPLv3'

import ctypes
import ctypes.wintypes as wintypes
import os
import sys


# * VARIABLES, STRUCTS, UNIONS BELOW THIS COMMENT

# * Structures first, variables later
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', ctypes.c_long),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', ctypes.c_char*260)
        ]


# * Functions renamed for the sake of clarity
# * All functions will be 
# * loaded using 'ctypes.WinDLL', thanks to @Eryk Sun
# * from sharing your knowledge and some kind of standard.
# * Source:
# * https://stackoverflow.com/questions/35093690/how-to-call-a-winapi-function-with-ctypes-and-store-the-return-value

ADVAPI32 = ctypes.WinDLL('advapi32.dll')
KERNEL32 = ctypes.WinDLL('kernel32.dll')
NTDLL = ctypes.WinDLL('ntdll.dll')
USER32 = ctypes.WinDLL('user32.dll')
PSAPI = ctypes.WinDLL('Psapi.dll')

WinError = ctypes.WinError

# * KERNEL32 Functions
CreateToolhelp32Snapshot = KERNEL32.CreateToolhelp32Snapshot
GetLastError = KERNEL32.GetLastError
GetModuleHandle = KERNEL32.GetModuleHandleW
Process32First = KERNEL32.Process32First
Process32Next = KERNEL32.Process32Next
QueryFullProcessImageNameW = KERNEL32.QueryFullProcessImageNameW

ReadProcessMemory = KERNEL32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.c_size_t
    ]
ReadProcessMemory.restypes = wintypes.BOOL

SetConsoleTitle = KERNEL32.SetConsoleTitleW
SetProcessInformation = KERNEL32.SetProcessInformation # * This function is only after Windows 8.
VirtualAllocEx = KERNEL32.VirtualAllocEx
VirtualAllocEx.argtypes = [
    wintypes.HANDLE, #hProcess
    wintypes.LPVOID, #lpAddress
    ctypes.c_size_t,   #dwSize
    wintypes.DWORD,  #flAllocationType
    wintypes.DWORD,  #flProtect
    ]
VirtualAllocEx.restype = wintypes.DWORD

WriteProcessMemory = KERNEL32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    wintypes.HANDLE, #hProcess
    wintypes.LPVOID, #lpAddress
    wintypes.LPCVOID,#lpBuffer
    ctypes.c_size_t, #nSize,
    ctypes.c_size_t, #lp*NumberOfBytesWritten
    ]
WriteProcessMemory.restype = wintypes.BOOL

# * NTDLL Functions
NtSetInformationProcess = NTDLL.NtSetInformationProcess
RtlAdjustPrivilege = NTDLL.RtlAdjustPrivilege

# * PSAPI Functions
GetModuleFileNameEx = PSAPI.GetModuleFileNameExW

# * USER32 Functions
GetActiveWindow = USER32.GetActiveWindow

# * Variables used, source: MSDN
# * Toolhelp32Snapshot

TH32CS_INHERIT = 0x80000000
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPALL =  TH32CS_INHERIT\
                | TH32CS_SNAPHEAPLIST\
                | TH32CS_SNAPMODULE\
                | TH32CS_SNAPMODULE32\
                | TH32CS_SNAPPROCESS\
                | TH32CS_SNAPTHREAD


# * Process access rights
# * https://stackoverflow.com/questions/15237357/windll-kernel32-openprocessprocess-all-access-pid-false-process-all-access
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SET_INFORMATION = 0x0200
PROCESS_TERMINATE = 0x0001
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ =  0x0010
PROCESS_VM_WRITE = 0x0020

# * TOKEN ACCESS FOUND IN PLUTO, FOR REAL ALL UNDOCUMENTED STUFF...
# * SOURCE: https://referencesource.microsoft.com/#System/compmod/microsoft/win32/NativeMethods.cs,c020eb55dd6a0811

TOKEN_ALL_ACCESS   = 0x000f01ff

# * Used by RtlAdjustPrivilege and NtQueryInformationProcess

ProcessBreakOnTermination = 0x1D #29d
SeDebugPrivilege = 19 #20

# * MessageBox Variables
MB_OK = 0x00000000

MB_ICONINFORMATION = 0x00000040
MB_ICONERROR = 0x00000010

MB_SYSTEMMODAL = 0x00001000
MB_TASKMODAL = 0x00002000
MB_APPMODAL = 0x00000000

# * VirtualAllocEx Variables
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RESET = 0x00080000
MEM_RESET_UNDO = 0x10000000

MEM_LARGE_PAGES = 0x20000000
MEM_PHYSICAL = 0x00400000
MEM_TOP_DOWN = 0x00100000

# * Page constants
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


# -= END .'WIN32 Section' .=-
# -= BEGIN 'Python Bytecode Section' =-


# * FLAGS *
CO_OPTIMIZED = 0x0001
CO_NEWLOCALS = 0x0002
CO_VARARGS = 0x0004
CO_VARKEYWORD = 0x0008
CO_NESTED = 0x0008
CO_GENERATOR = 0x0020
CO_NOFREE = 0x0040
CO_NOROUTINE = 0x0080
CO_ITERABLECOROUTINE = 0x0100

CO_FUTURE_DIVISION = 0x2000
CO_FUTURE_ABSOLUTE_IMPORT = 0x4000
CO_FUTURE_WITH_STATEMENT = 0x8000
CO_FUTURE_PRINT_FUNCTION = 0x10000
CO_FUTURE_UNICODE_LITERALS = 0x20000
CO_FUTURE_BARRY_AS_BDFL = 0x40000
CO_FUTURE_GENERATOR_STOP = 0x80000


# -= END .'Python Bytecode Section'.=-
# -= BEGIN .'Functions section' .=-


# * WIN32 functions.
def _get_PE32Data(PE32 = PROCESSENTRY32):
    '''
    Retrieve the data of a given PROCESSENTRY32 struct to an object.
    '''
    obj = {}
    for field_tuple in PE32._fields_:
            # * This loop stores the PROCESSENTRY32 
            # * structure values to the process_objects
            # * variable, therefore the process_objects
            # * should look like this.
            # *
            # * process_objects = {
            # *                 "Process": {
            # *                     "dwSize": pe32.dwSize,
            # *                     "cntUsage": pe32.cntUsage,
            # *                         ...         ...
            # *                     }
            # *                 }
            
            field_name = field_tuple[0]
            obj[field_name] = getattr(PE32, field_tuple[0])
    return obj


# * Take current process snapshot.
def get_ProcessSnapshot(DEBUG = False, quiet = False):
    '''
    Snap the running processes and return them as object
    this object has the properties of PROCESSENTRY32. And
    each object key is the process SzExeFile.
    i.e process_snapshot['[System Process]']
    has the same properties as PROCESSENTRY32.
    i.e process_snapshot['pythonw']['SzExeFile'] = 'pythonw'.
    '''
    process_objects = {}
    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(pe32)
    lppe32 = ctypes.byref(pe32)
    
    # * 'handle' is a handle of CreateToolhelp32Snapshot 
    handle = CreateToolhelp32Snapshot(
        TH32CS_SNAPALL, # dwFlags
        0               # th32ProcessID
        )
    
    p_retrieve = Process32First(
        handle,                       # hSnapshot
        lppe32# lppe
        )

    if not p_retrieve:
        colorprint(' [!] Unable to retrieve the first process', 'red')
        colorprint(
            f' [!] Process32First failed with code {GetLastError()} -'
            f'({ctypes.WinError(GetLastError())})',
            'yellow',
            end = ''
            )
        return False
            
    # * Iterate trought the process until error 0x12 (ERROR_NO_MORE_FILES)
    # * This is the proper way to iterate trough Process32Next
    # * https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-#ERROR_NO_MORE_FILES
    while p_retrieve: 
        process_name = pe32.szExeFile.decode()
        process_objects[process_name] = _get_PE32Data(PE32 = pe32)
        if DEBUG:
            colorprint(
            ' [+] Successfully retrieved process: '
            f"{process_objects[process_name]['szExeFile'].decode()}"
            f" with PID {process_objects[process_name]['th32ProcessID']}"
            f" and PriorityClass {process_objects[process_name]['pcPriClassBase']}",
            'green'
            )
        p_retrieve = Process32Next(handle, lppe32)
    
    if DEBUG:
        return True
    else:
        if not quiet:
            colorprint('   +-----------------------------------------+ ', 'green')
            colorprint(' [/!\] Process list retrieved successfully [/!\]', 'green')
            colorprint(' =====-------------------------------------=====', 'green')
            print('')
        return process_objects




# * Get the priority classes from process snapshot.
def get_PriorityClass(DEBUG = False):
    '''Take a snapshot of all process and check their priority.'''
    process_list = _process_snap_toObj(DEBUG = False)
    for process in process_list:
        colorprint(f" [!] pcPriClassBase: {process_list[process]['pcPriClassBase']}",'yellow')
    if DEBUG: return True

# * General utilities functions.

# * Print in color.
def colorprint(text, color='none', effect='none', end='\n', persist = False, DEBUG = False):
    '''
Description
-----------
    Print the desired colour in terminal

Parameters
----------
text: string
    The text to colour.
    
colour: string
    * 'default' - Default colour
    * 'green' - 'red' - 'yellow' - 'cyan'

Return
------
    Returns the parameter 'text' coloured.
    '''
        # * Error check
    if DEBUG:
        for color in COLORS:
            print(COLORS[color]+f'{color}')
        for effect in EFFECTS:
            print(EFFECTS[effect]+f'{effect}')
        print(EFFECTS['default'])
        return
    if type(text) != type(''):
        print(f"Colorprint message\nInvalid type: '{type(text)}' for the text")
    elif not color in list(COLORS.keys()):
        print(f"Colorprint message\nInvalid color: '{color}'")
    else:
        pass
    if persist:
        string = f"{COLORS[color]}{EFFECTS[effect]}{text    }"
    else:
        string = f"{COLORS[color]}{EFFECTS[effect]}{text}{COLORS['default']}"
    
    print(string, end=end)
    return string
   
# * "Press enter to continue" function.
def kbhit_enter(_color = 'none', _effect = 'none', _end = '', debugmsg = False):
    '''Prompts a "Press enter to continue".'''
    if debugmsg:
        msg = ' [DEBUG:] Press enter to continue...'
    else:
        msg = 'Press enter to continue...'
    colorprint(
        msg,
        color = _color,
        effect =_effect,
        end = _end
        )
    input()

# * Checks the VirtualTerminalLevel (Only for MS Windows)
def _check_termvirt():

    '''Checks for VirtualTerminalLevel windows registry key.'''
    import winreg

    HKEYCU = winreg.HKEY_CURRENT_USER
    KEY_NAME = "Console"
    VALUE_NAME = "VirtualTerminalLevel"
    FULL_KEY = f"HKEY_CURRENT_USER\\{KEY_NAME}\\{VALUE_NAME}"
    DWORD_VALUE = 0x00000001
    KEY_ALL_ACCESS = winreg.KEY_ALL_ACCESS
    DEBUG = False
    
    OPEN_KEY = winreg.CreateKeyEx(
        HKEYCU,     # *HKEY_CURRENT_USER...
        KEY_NAME,   # *...\\Console
        0,          # * reserved = 0
        KEY_ALL_ACCESS
        )
        
    # * Index 1: An integer giving the number of values this key has.
    # *          
    # * https://docs.python.org/3/library/winreg.html#winreg.QueryInfoKey
    values_length = winreg.QueryInfoKey(OPEN_KEY)[1]
    values = []
    
    for i in range(0, values_length):
        # * Index 0: A string that identifies the value name
        # * Index 1: An object that holds the value data, and whose 
        # *          type depends on the underlying registry type
        # * Index 2: An integer that identifies the type of the value
        # *          data (see table in docs for SetValueEx())
        # *
        # * https://docs.python.org/3/library/winreg.html#winreg.EnumValue
    
        value = winreg.EnumValue(OPEN_KEY, i)

        # * Check if the registry value is equal to
        # * >>> ('VirtualTerminalLevel', 1, 4)
        if value[0] == VALUE_NAME:
            if value[1] == DWORD_VALUE:
                if value[2] == winreg.REG_DWORD:
                    if DEBUG:
                        print(
                            "[!] Query succeed\n"
                            f"[+] Key queried {FULL_KEY}: {DWORD_VALUE}"
                            )

                    
                    return True
    
    winreg.SetValueEx(
        OPEN_KEY,
        VALUE_NAME,
        0,
        winreg.REG_DWORD,
        DWORD_VALUE
        )

    values_length = winreg.QueryInfoKey(OPEN_KEY)[1]
    for i in range(0, values_length):
        value = winreg.EnumValue(OPEN_KEY, i)

        if value[0] == VALUE_NAME:
            if value[1] == DWORD_VALUE:
                if value[2] == winreg.REG_DWORD:
                    if DEBUG:
                        print(
                            "[!] Query succeed\n"
                            f"[+] Key queried {FULL_KEY}: {DWORD_VALUE}"
                            )
                    
                    return True
    print("[!] Can't write to the registry, try"
          " running the script as administrator")
    return False

# -= END .'Function Section' .=-   

TERMVIRT_SUPPORT = _check_termvirt()

if TERMVIRT_SUPPORT == True:
    G = '\033[92m'
    R = '\033[31m'
    Y = '\033[33m'
    C = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    SMSO = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[6m'
    INVISIBLE = '\033[7m'
    DEF = '\033[0m'
else:
    G = ''
    R = ''
    Y = ''
    C = ''
    BOLD = ''
    DIM = ''
    SMSO = ''
    UNDERLINE = ''
    BLINK = ''
    REVERSE = ''
    INVISIBLE = ''
        
        
COLORS = {
    'none': '',
    'default': DEF,
    'green': G,
    'red': R,
    'yellow': Y,
    'cyan': C
    }
    
EFFECTS = {
    'none': '',
    'default': DEF,
    'bold': BOLD,
    'dim': DIM,
    'smso': SMSO,
    'underline': UNDERLINE,
    'blink': BLINK,
    'reverse': REVERSE,
    'invisible': INVISIBLE
    }

