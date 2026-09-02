@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "ROOT=%CD%"
set "BUILD_DIR=%ROOT%\build"
set "PREFIX_FILE=%ROOT%\qt-prefix.txt"
set "CLEAN=0"
set "QT_PREFIX="

if /I "%~1"=="--clean" (
    set "CLEAN=1"
    if not "%~2"=="" set "QT_PREFIX=%~2"
) else if /I "%~1"=="-c" (
    set "CLEAN=1"
    if not "%~2"=="" set "QT_PREFIX=%~2"
) else if /I "%~1"=="--help" (
    goto usage
) else if not "%~1"=="" (
    set "QT_PREFIX=%~1"
    if /I "%~2"=="--clean" set "CLEAN=1"
)

if not exist "%ROOT%\CMakeLists.txt" (
    echo [ERROR] CMakeLists.txt not found
    goto fail
)

if "!QT_PREFIX!"=="" (
    if defined QTDIR set "QT_PREFIX=%QTDIR%"
)
if "!QT_PREFIX!"=="" (
    if exist "%PREFIX_FILE%" set /p QT_PREFIX=<"%PREFIX_FILE%"
)

if defined QT_PREFIX set "QT_PREFIX=!QT_PREFIX:"=!"

if "!QT_PREFIX!"=="" call :find_qt

if "!QT_PREFIX!"=="" (
    echo.
    echo [ERROR] Qt 6 MSVC kit not found automatically.
    echo Need a folder that contains:
    echo   lib\cmake\Qt6\Qt6Config.cmake
    echo Example:
    echo   C:\Qt\6.8.3\msvc2022_64
    echo.
    set /p QT_PREFIX=Enter that path and press Enter: 
    if defined QT_PREFIX set "QT_PREFIX=!QT_PREFIX:"=!"
)

if "!QT_PREFIX!"=="" (
    echo [ERROR] No Qt path given
    goto fail
)

if not exist "!QT_PREFIX!\lib\cmake\Qt6\Qt6Config.cmake" (
    echo [ERROR] Not a Qt 6 kit: !QT_PREFIX!
    echo         Expected: ...\6.x.x\msvc2022_64
    goto fail
)

echo !QT_PREFIX!>"%PREFIX_FILE%"
echo [INFO] Qt path saved to qt-prefix.txt

where git >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git is not on PATH. Install Git and retry.
    goto fail
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found. Install Visual Studio 2022 with C++.
    goto fail
)

set "VSINSTALL="
for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%I"
if not defined VSINSTALL (
    echo [ERROR] Visual Studio with MSVC not found
    goto fail
)

set "VCVARS=%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS%" (
    echo [ERROR] Missing vcvarsall.bat
    goto fail
)

echo [INFO] VS  : %VSINSTALL%
echo [INFO] Qt  : !QT_PREFIX!
echo [INFO] Out : %BUILD_DIR%\Release

call "%VCVARS%" x64
if errorlevel 1 (
    echo [ERROR] Failed to init MSVC x64
    goto fail
)

where cmake >nul 2>&1
if errorlevel 1 (
    echo [ERROR] cmake not found
    goto fail
)

if "!CLEAN!"=="1" (
    if exist "%BUILD_DIR%" (
        echo [INFO] Removing build\
        rmdir /s /q "%BUILD_DIR%"
    )
)
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [INFO] cmake configure
cmake -S "%ROOT%" -B "%BUILD_DIR%" -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="!QT_PREFIX!"
if errorlevel 1 (
    echo [ERROR] CMake configure failed
    goto fail
)

echo [INFO] cmake build Release
cmake --build "%BUILD_DIR%" --config Release
if errorlevel 1 (
    echo [ERROR] Build failed
    goto fail
)

set "EXE=%BUILD_DIR%\Release\ProcessAnnotator.exe"
if not exist "%EXE%" (
    echo [ERROR] Missing %EXE%
    goto fail
)

if exist "!QT_PREFIX!\bin\windeployqt.exe" (
    echo [INFO] windeployqt
    "!QT_PREFIX!\bin\windeployqt.exe" --release --no-translations "%EXE%"
) else if exist "!QT_PREFIX!\bin\windeployqt6.exe" (
    echo [INFO] windeployqt6
    "!QT_PREFIX!\bin\windeployqt6.exe" --release --no-translations "%EXE%"
) else (
    echo [WARN] windeployqt not found
)

echo.
echo [OK] %EXE%
echo.
pause
exit /b 0

:usage
echo build.bat
echo build.bat "C:\Qt\6.8.3\msvc2022_64"
echo build.bat --clean
echo build.bat --clean "C:\Qt\6.8.3\msvc2022_64"
echo.
pause
exit /b 0

:fail
echo.
pause
exit /b 1

:find_qt
for %%D in (C D E) do (
    if exist "%%D:\Qt\" (
        for /d %%Q in ("%%D:\Qt\6.*") do (
            if exist "%%~Q\msvc2022_64\lib\cmake\Qt6\Qt6Config.cmake" (
                set "QT_PREFIX=%%~Q\msvc2022_64"
                goto :eof
            )
            if exist "%%~Q\msvc2019_64\lib\cmake\Qt6\Qt6Config.cmake" (
                set "QT_PREFIX=%%~Q\msvc2019_64"
                goto :eof
            )
        )
    )
)
if exist "%USERPROFILE%\Qt\" (
    for /d %%Q in ("%USERPROFILE%\Qt\6.*") do (
        if exist "%%~Q\msvc2022_64\lib\cmake\Qt6\Qt6Config.cmake" (
            set "QT_PREFIX=%%~Q\msvc2022_64"
            goto :eof
        )
    )
)
goto :eof
