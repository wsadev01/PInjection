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

__AUTHOR__ = 'Aitor Santoro <torsw@protonmail.com>'
__LICENSE__ = 'GNU GPLv3'
__VERSION__ = '0.1'
__doc__ = '''
Pyjection (Python Injection)
----------------------------

Description
-----------
    Libreria para inyectar codigo python donde se te cante,
    en realidad en procesos que se estan ejecutando (Igual,
    OJO no vas a poder ejecutar en el proceso "[System Process]" o
    "winlogon.exe", tampoco flashes kernel land, procesos tranqui,
    "explorer.exe" seria un buen target.
    
'''


from ginutils import *
from types import CodeType, FunctionType

import dis
import inspect
import marshal
import sys

def test_injection():
    '''Try to inject test_function to explorer.exe'''
    pSnap = get_ProcessSnapshot(quiet = True)
    explorer_pid = pSnap['explorer.exe']['th32ProcessID']
    co = test_function.__code__
    codestring = bytes(
       [0x74,
        0x00,
        0xA0,
        0x01,
        0x64,
        0x01,
        0x64,
        0x02,
        0x64,
        0x03,
        0x74,
        0x02,
        0xA1,
        0x04,
        0x01,
        0x00,
        0x64,
        0x00,
        0x53]
        )
    
    # * Codigo objeto (CodeType).
    test_function_code = CodeType(
        0, #argcount
        0, #kwonlyargcount
        0, #nlocals
        6, #stacksize
        (CO_NEWLOCALS | CO_NOFREE), #flags
        codestring, #codestring
        (None, 0, 'Test Function!(crafted)', 'Function Test(crafted)',), #const_names (constants)
        ('USER32', 'MessageBoxW', 'MB_OK'), #global_names (names)
        (), #varnames
        '', #filename
        'test_function_crafted', #name
        83, #firstlineno
        b'', #lnotab
        (), #freevars
        () #cellvars
        )
    
    bb = marshal.dumps(test_function_code)
    kbhit_enter()
    # * Funcion crafteada a manopla (FunctionType).
    test_function_crafted = FunctionType(
        test_function_code, #CodeType
        {'USER32': USER32,  #Globals
        'MessageBoxW': USER32.MessageBoxW,
        'MB_OK': MB_OK}
        )
    
    # * Contenido serializado (Osea, pasado a bytes).
    serialized_code = marshal.dumps(test_function_code)
    sizeof_serialized_code = len(serialized_code)

    colorprint('Vamos a llamar la funcion crafteada', 'green')
    kbhit_enter()
  
    test_function_crafted()
    
    print()
    colorprint(
        'Pyinjector va a intentar alocar memoria via VirtualAllocEx',
        'yellow',
        'bold',
        )
    colorprint(f'\nContenido serializado: {serialized_code}', 'green')
    colorprint('Tamaño en bytes: ', 'green', end = '')
    colorprint(f'{sizeof_serialized_code}', 'yellow', 'underline')
    kbhit_enter()
    
    # * Direccion base de memoria.
    base_addr = ctypes.create_string_buffer(sizeof_serialized_code)
    
    # * HANDLE del proceso.
    hProc =  KERNEL32.OpenProcess(
        PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,
        False,
        explorer_pid
        )
    
    # * Definimos la direccion base.
    base_addr = VirtualAllocEx(
       hProc,
       0,
       sizeof_serialized_code,
       MEM_COMMIT | MEM_RESERVE,
       PAGE_EXECUTE_READWRITE
       )
    
    if not base_addr:
        colorprint(WinError(GetLastError()), 'red', 'underline')
        colorprint('VirtualAllocEx fallo, miserablemente :c ...', 'red')
        return False
        
    colorprint(
        'VirtualAllocEx retorno la direccion base (base address): ',
        'green',
        end = ''
        )
    colorprint('', effect = 'underline', end = '', persist = True)
    colorprint(f'{base_addr}', 'cyan')
    kbhit_enter()
    
    # * Escribimos a la memoria.
    status = WriteProcessMemory(
        hProc,
        base_addr,
        serialized_code,
        sizeof_serialized_code,
        0  
        )
    
    if not status:
        colorprint(WinError(GetLastError()), 'red', 'underline')
        colorprint('Fallo la inyeccion', 'red', 'bold') 
        return False
    colorprint('Se escribio en la memoria con exito', 'green')
    print()
    
    colorprint(
        'A continuacion se va a ejecutar la funcion crafteada'
        ' desde la memoria alocada',
        'yellow',
        'bold'
        )
    kbhit_enter()
    
    # * Buffer al que leer datos
    read_buff = bytes(sizeof_serialized_code)
    
    kbhit_enter()
    read_status = ReadProcessMemory(
        hProc,
        base_addr,
        read_buff,
        len(read_buff),
        0
        )
    
    # * Restauramos al estado original con marshal
    bytes_buffer = marshal.loads(read_buff)
    
    if not read_status:
        colorprint(WinError(GetLastError()), 'red', 'underline')
        colorprint('Fallo la lectura de la memoria (ReadProcessMemory)')
    colorprint('Se leyo la memoria del proceso explorer.exe correctamente', 'green')
    colorprint('Podes llamar directamente la funcion accediendo a la region de memoria', 'green')
    kbhit_enter()
    print()
    
    colorprint(
        'A continuacion se creara una funcion a partir del bytecode guardado'
        ' en la direccion de memoria del proceso explorer.exe',
        'green',
        'bold'
        )
    kbhit_enter()
    crafted_function = FunctionType(
        bytes_buffer,
        {'USER32': USER32,  #Globals
        'MessageBoxW': USER32.MessageBoxW,
        'MB_OK': MB_OK}
        )
    crafted_function()
        
    return True
      
def test_function():
    USER32.MessageBoxW(
        0,
        'Test Function!',
        'Function test!',
        MB_OK
        )
 
 
class Shell:
    '''Un shell nomas.'''
    def __init__(self):
        '''Iniciamos todo, mensaje facha de bienvenida.'''
        colorprint(f"Python Injector SHELL {__VERSION__}", 'green', 'bold')
        self.cmd = ''
        self.read = True
        self.base_addr = 0
        self.hProc = 0
        self.repl()
        
        
    def repl(self):
        '''Funcion Read Evaluate Process Loop para justamente hacer eso.'''
        while self.read:
            self.cmd = input()
            if self.cmd == 'test_dis':
                colorprint(
                'La funcion test_function will se va a desensamblar, codigo python es:',
                'yellow',
                'bold'
                )
                colorprint(inspect.getsource(test_function), 'green', 'bold')
                kbhit_enter()
                colorprint('Python bytecode (from dis.dis function)', 'yellow', 'bold')
                colorprint('', 'cyan', persist = True)
                dis.dis(test_function)
                print('')
                kbhit_enter()
            
            elif self.cmd == 'test_injection':
                colorprint(
                    'Pinject will attempt to inject test_function to explorer.exe',
                    'yellow',
                    )
                status = test_injection()
                if not status:
                    pass
                else:
                    self.base_addr = status[0]
                    self.hProc = status[1]
                    
            elif self.cmd == 'call_from_proc':
                if self.base_addr == 0 or self.hProc == 0:
                    colorprint('Ejecuta el comando test_injection primero', 'yellow')
                else:
                    pass
                    
            elif self.cmd in ('stop', 'exit', 'quit'):
                self.stop()
                
    def read_from(self, process = 0, base_address = 0):
        '''
Descripcion
-----------
    Lee la memoria de un proceso dado

Parameteros
----------
process: WINTYPES HANDLE
    Un handle del proceso a leer con los permisos
    PROCESS_VM_OPERATION y PROCESS_VM_READ.
base_address: int o WINTYPES DWORD
    Offset base de la memoria reservada 
    (Esto se obtiene a traves de VirtualAllocEx)

Return
------
Tuple
    Retorna True y los bytes recibidos respectivamente.
        '''
        raise NotImplementedError
        
        
    def stop(self):
        self.read = False
        
if __name__ == '__main__':
    shell = Shell
    shell()