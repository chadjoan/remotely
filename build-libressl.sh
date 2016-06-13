cd libressl
./autogen.sh
mkdir prefix
CFLAGS="-O2 -pipe -g" ./configure --prefix=$PWD/prefix
make
make install
