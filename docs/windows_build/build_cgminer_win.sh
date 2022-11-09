#!/bin/bash
export folder=$(pwd)
cd ~
git clone https://github.com/wareck/cgminer-lketc.git
cd cgminer-lketc
autoreconf -fi
CFLAGS="-O2 -msse2" ./configure --host=i686-w64-mingw32.static --disable-shared --enable-scrypt --enable-zeus --enable-gridseed --enable-lketc
make
strip cgminer.exe
cp cgminer.exe /tmp/
cd /tmp/
wget https://tinyurl.com/4j8ymxe5 -O cgminer-lketc-win32.zip
unzip cgminer-lketc-win32.zip
mv cgminer.exe cgminer-lketc-win32/
cd /tmp/
version=`git ls-remote -h https://github.com/wareck/cgminer-lketc.git | awk '{print $1}' |cut -c1-7`
7z a cgminer-lketc-$version.7z cgminer-lketc-win32
cp cgminer-lketc-$version.7z ~/temp

echo ""
echo "cgminer-lketc-$version.7z is ready in /home/$USER/temp folder"
echo ""
