mkdir build
cd build
wget https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.7.tar.bz2
tar xvf libgcrypt-1.8.7.tar.bz2
wget https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.39.tar.bz2
tar xvf libgpg-error-1.39.tar.bz2
cd libgpg-error-1.39
./configure --prefix=`pwd`/..
make
make install
cd ../libgcrypt-1.8.7
./configure --prefix=`pwd`/.. --with-libgpg-error-prefix=`pwd`/..
make
make install
cd ..
cmake ..
make

