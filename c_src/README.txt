To compile these files on Linux, you will need libgmp and gcc

To install GMP, do the following (you may use a newer version if you like):

wget http://ftp.sunet.se/pub/gnu/gmp/gmp-4.2.2.tar.bz2
tar -xjvf gmp-4.2.2.tar.bz2
cd gmp-4.2.2
./configure
make
make check
make install

Then, to compile the SecureAjax helper modules:

gcc -o rsa -l gmp rsa.c
gcc -o rsakg -l gmp rsakg2.c
gcc -o gendhkeys -l gmp gendhkeys.c

etc.
