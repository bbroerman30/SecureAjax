This directory contains source for the C applications that may be used for AES, RSA, and Diffie-Hellman routines. 
These are useful if you have a slow server, or can not install the GMP plug-in on your server. 
These files can be compiled with your standard C++ compiler, but you will need the GNU GMP library to link them.
(See the comments in etc/secureajax_helper.php on using these files once compiled)

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
