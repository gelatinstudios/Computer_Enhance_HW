
@echo off

odin build %1

%1 %2 > test.asm
fc test.asm %2.asm
nasm test.asm
echo.
fc test %2

del test
del test.asm
del %1.exe
