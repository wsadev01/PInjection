# <h1 align=center><img src=https://raw.githubusercontent.com/systemnaut/Pinjection/master/isologotipo/pinjector-iso-1-alpha.png width=50> PInjector</h1>
![PInjector isologotype](isologotipo/pinjector-isologo-1.png)
# [Readme-ES](README.md) - [Readme-EN](README-EN.md)
## ¿Qué es?
PInjection es un script de Python que puede funcionar como Módulo o como script ejecutable desde la línea de comandos (CLI script). Este script lo que hace es inyectar Código Objeto en una región de memoria específica de un proceso utilizando la API de Windows ([OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess), [VirtuallAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) y [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)).

## ¿Qué NO es?
-----------------
 - PInjection **NO** es un script ejecutable para meter tu virus ejecutarlo y romperle la computadora a tu amigue cuando va al baño.
 - PInjection **NO** es un script ejecutable para guardar funciones ejecutables o código máquina en una región de memoria específica.
 
### ¡Que SÍ es!
-----------------
 - PInjection **SI** es un script ejecutable para meter Código Objeto específico y "marshalizado" en una región de memoria específica.
 - PInjection **SI** es un módulo que provee una interfaz sencilla de utilizar para cualquier novato en Python.
 - PInjection **SI** es una buena elección para ofuscar y ocultar código objeto en un proceso (Similar a [DLL Injection](https://en.wikipedia.org/wiki/DLL_injection))
 - PInjection **SI** es un software libre y gratuito. *(GNU GPLv3)*
 
### Limitaciones
-----------------
Como ya dije, esto no es un script para ejecutar y automáticamente vas a destruír permanentemente la computadora destino, sino un script/módulo para cargar código objeto en la memoria de un proceso, esto quiere decir explicitamente lo dícho, para ejecutar el código objeto que se guarda, se tiene que conocer qué es, ya que luego se tendrá que pasar a FunctionType utilizando la librería [types](https://docs.python.org/3/library/types.html), y ahí se tendrán que definír todas las constantes utilizadas en el código objeto. **_La carga del código objeto es automática, la ejecución NO_**.  
&emsp;&emsp;Tambien hay muchos procesos en los cuales une no podrá inyectar, ya que estos procesos tienen y/o presentan condiciones especificas internas que no permiten acceder a sus regiones de memoria.

### Ejemplos.
Inyectando la función `test_function` del archivo `testmodule` en el proceso explorer.exe (explorer.exe PID 5600).  
Comando: `python pinjection.py 5600 --function testmodule___test_function --verbose`
![Injecting bytecode into explorer.exe](exampligratia/injecting_testmodule.png)

Ejecutando la función una vez inyectada (Se encuentra en la región de memoria cuya dirección base es 14548992)  
Comando: `python pinjection.py 5600 --constants constantsfile --baseaddr 14548992 --buffsize 164 --execute --verbose`
![Executing bytecode from explorer.exe memory](exampligratia/executing_testmodule.png)

#### Notas 0.7
 - Primer release con archivo binario, este debería utilizarse como script CLI, y el archivo python como paquete o módulo.

#### DISCLAIMER, AVISOS y AVISOS LEGALES.
 - Si no se desaloja la memoria en el proceso específico, se generará una [fuga de memoria](https://en.wikipedia.org/wiki/Memory_leak).
 - Todos los contenidos multimedia estan licenciados bajo la licencia [Creative Commons BY-SA](https://creativecommons.org/licenses/by-sa/3.0/deed.es)
 - Este software fué diseñado con fínes educativos. El autor renuncia a toda responsabilidad por el uso que se haga del mismo
