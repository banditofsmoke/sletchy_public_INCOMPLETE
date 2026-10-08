@echo off
rem Open Sletchy: double-click this file.
rem
rem Nothing is installed. The window runs from this folder, everything it writes
rem stays in var\ (LAW 0), and closing the window stops all of it. What every
rem button can do is in apps\desktop\WHAT-A-CLICK-CAN-DO.md.
rem
rem   Open-Sletchy.cmd --check    says what it would do; starts nothing, never waits
rem
rem The name is load-bearing. It has no spaces, it does not begin with a cmd
rem built-in (the first name, "Start Sletchy.cmd", typed without quotes, ran cmd's
rem own START and popped a Windows error), and it is not "sletchy", which would
rem shadow the CLI when typed in this folder. There are no ( ) blocks below,
rem because cmd misparses a block when a path inside it holds a bracket.
rem tests\adversarial\test_launcher.py holds all of this.
setlocal
set "CHECK="
if /i "%~1"=="--check" set "CHECK=1"
cd /d "%~dp0" || exit /b 1
set "KERNEL=.venv\Scripts\sletchy.exe"
set "EXE=apps\desktop\src-tauri\target\release\sletchy-desktop.exe"

if not exist "%KERNEL%" goto :no_kernel
if not exist "%EXE%" goto :no_window
if defined CHECK goto :check_ready
start "" "%EXE%"
exit /b 0

:check_ready
echo ready: would start %EXE%
exit /b 0

:no_kernel
echo Sletchy's Kernel is not set up in this folder yet.
echo Open a terminal here and run:  uv sync
echo Then open this file again.
if not defined CHECK pause
exit /b 2

:no_window
if defined CHECK goto :check_build
echo The Sletchy window has not been built on this computer yet.
echo Building it takes a few minutes the first time. The build goes into
echo apps\desktop in this folder; npm and Rust may also refresh their own download caches.
choice /M "Build it now"
if errorlevel 2 exit /b 1
pushd apps\desktop || goto :failed
if not exist node_modules call npm ci || goto :failed
call npm run tauri -- build --no-bundle || goto :failed
popd
if not exist "%EXE%" goto :failed
start "" "%EXE%"
exit /b 0

:check_build
echo not built yet: would build, then start %EXE%
exit /b 3

:failed
echo The build failed. Nothing was installed and nothing outside this folder changed.
pause
exit /b 1
