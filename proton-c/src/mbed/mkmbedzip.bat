REM  Microsoft Azure IoT Client Libraries
REM  Copyright (c) Microsoft Corporation
REM  All rights reserved. 
REM  MIT License
REM  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
REM  documentation files (the Software), to deal in the Software without restriction, including without limitation 
REM  the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
REM  and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

REM  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

REM  THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED 
REM  TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
REM  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
REM  CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
REM  IN THE SOFTWARE.

REM  Store the current path and change to the batch file directory
PUSHD %~dp0

REM  Limit the scope of environment variable changes to local only.
SETLOCAL

REM  Check if 7z is already in the system variable PATH
WHERE 7z.exe
IF %ERRORLEVEL% EQU 0 GOTO ZIP_UTIL_FOUND

REM  Try adding the default path to 7z if it's not already in the system variable PATH
PATH %ProgramFiles%\7-Zip;%PATH%
WHERE 7z.exe
IF %ERRORLEVEL% EQU 0 GOTO ZIP_UTIL_FOUND

REM  Abort execution if 7z was not found
@ECHO *******************************************
@ECHO ** ATTENTION:  7z utility was not found. **
@ECHO *******************************************
GOTO END


REM  Found 7z zip utility
:ZIP_UTIL_FOUND
SET outdir=..\..\..\build\mbed
REM  Delete any residual files from previous batch file runs
RMDIR /S/Q %outdir%
DEL /F /Q *.zip
REM  Create a directory for temporary file storage
MKDIR %outdir%
MKDIR %outdir%\proton
MKDIR %outdir%\messenger
MKDIR %outdir%\engine
MKDIR %outdir%\dispatcher
MKDIR %outdir%\transport
MKDIR %outdir%\sasl
MKDIR %outdir%\ssl
MKDIR %outdir%\object
MKDIR %outdir%\codec
MKDIR %outdir%\framing
MKDIR %outdir%\message
MKDIR %outdir%\events
MKDIR %outdir%\mbed
REM  Copy common code
COPY ..\..\..\build\proton-c\src\protocol.h %outdir%
COPY ..\..\..\build\proton-c\src\encodings.h %outdir%
COPY ..\messenger\*.c %outdir%\messenger\*.c
COPY ..\mbed\*.* %outdir%\mbed\*.*
COPY ..\framing\*.* %outdir%\framing\*.*
COPY ..\log.c %outdir%\log.c
COPY ..\util.c %outdir%\util.c
COPY ..\error.c %outdir%\error.c
COPY ..\parser.c %outdir%\parser.c
COPY ..\scanner.c %outdir%\scanner.c
COPY ..\types.c %outdir%\types.c
COPY ..\selectable.c %outdir%\selectable.c
COPY ..\buffer.c %outdir%
COPY ..\engine\*.c %outdir%\engine\*.c
COPY ..\engine\*.h %outdir%\engine\*.h
COPY ..\dispatcher\*.c %outdir%\dispatcher\*.c
COPY ..\dispatcher\*.h %outdir%\dispatcher\*.h
COPY ..\transport\*.c %outdir%\transport\*.c
COPY ..\transport\*.h %outdir%\transport\*.h
COPY ..\sasl\*.c %outdir%\sasl\*.c
COPY ..\sasl\*.h %outdir%\sasl\*.h
COPY ..\object\*.c %outdir%\object\*.c
COPY ..\codec\*.c %outdir%\codec\*.c
COPY ..\codec\*.h %outdir%\codec\*.h
COPY ..\message\*.c %outdir%\message\*.c
COPY ..\mbed\cyassl.c %outdir%\mbed\cyassl.c
COPY ..\ssl\*.h %outdir%\ssl\*.h
COPY ..\events\*.c %outdir%\events\*.c
COPY ..\messenger\*.h %outdir%\messenger\*.h
COPY ..\*.h %outdir%\*.h
COPY ..\..\include\proton\*.h %outdir%\proton\*.h

REM  Put all files into a zip file
PUSHD %outdir%
7z a -r ..\protonc.zip *.*
POPD

RMDIR /S/Q %outdir%

:END

REM  Return to the directory we started in
POPD
