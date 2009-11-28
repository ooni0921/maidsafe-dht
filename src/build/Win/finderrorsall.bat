@echo off
setlocal
echo Checking files - each "." represents a single file.
dir ..\..\*.cc /s /b >filelist.txt
dir ..\..\*.h /s /b >>filelist.txt
findstr /i /v "src\boost src\cryptopp src\libupnp src\protobuf src\udt .pb." filelist.txt > filelist2.txt
cd ..\..\..\
set rootpath=%cd%
cd src\build\Win
echo Setup>code_style_errors.txt
set count=0
for /f %%g in (filelist2.txt) do (
  @"cmd /c %rootpath%\src\cpplint.py "%%g" 2>>code_style_errors.txt"
  <nul (set/p z=".")
)
findstr /i /v /b "Setup Done Total" code_style_errors.txt > code_style_errors2
del filelist.txt filelist2.txt code_style_errors.txt
set count=0
for /f  %%g in (code_style_errors2) do (call :s_do_sums)
cls & echo. & echo.
if %count% geq 1 echo There are %count% errors! & call :function & exit /B 1
if %count% equ 0 echo There aren't any errors.
echo.
:s_do_sums
 set /a count+=1
 goto :eof
:function
 echo.
 exit /B 1
 goto :eof
