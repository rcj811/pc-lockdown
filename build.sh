#!/bin/sh
# 在 Linux 用 MinGW-w64 交叉編譯成 32 位元 Windows 程式（XP SP3 ~ Win11）
# 需要：sudo apt-get install g++-mingw-w64-i686
set -e
cd "$(dirname "$0")"
mkdir -p dist
CXX=i686-w64-mingw32-g++-win32
WINDRES=i686-w64-mingw32-windres

$WINDRES -O coff res/app.rc -o dist/app.res
$CXX -O2 -s -municode -mwindows \
  -D_WIN32_WINNT=0x0501 -DWINVER=0x0501 -DUNICODE -D_UNICODE \
  -fno-exceptions -fno-rtti -Wall \
  src/main.cpp src/reg.cpp src/usb.cpp src/sha256.cpp dist/app.res \
  -static -static-libgcc -static-libstdc++ \
  -lcomctl32 -ladvapi32 -luser32 -lkernel32 \
  -Wl,--major-subsystem-version,5,--minor-subsystem-version,1 \
  -Wl,--major-os-version,5,--minor-os-version,1 \
  -o dist/PcLockdown.exe
rm -f dist/app.res
echo "編譯完成：dist/PcLockdown.exe"
