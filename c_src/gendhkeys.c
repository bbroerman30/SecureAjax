/**************************************************************************************
 
  Secure Ajax Layer Copyright (C) 2008 - 2009 Brad Broerman,  bbroerman@bbroerman.net
  
  This Application is part of the Secure Ajax Layer, and is used to generate Diffie-Hellman
  message used to securely negotiate encryption keys. This program should be compiled on the
  target operating system and placed in the appropriate include directory.

  This program based on RSA Key Generator application by Aggelos Keromitis <kermit@gr.forthnet>  

  You need to obtain and compile the GNU Multi Precision math library for this, 
  get gmp-1.3.2.tar.gz

***************************************************************************************/

#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include "gmp.h"

#define PUBFILE	"pubkey.rsa"
#define SECFILE "seckey.rsa"

volatile unsigned int i, counter, value;

unsigned char get_random() {
	unsigned char rand;

	int randFile = open("/dev/urandom", O_RDONLY);
	read(randFile, &rand, sizeof(rand));
	close(randFile);

	return rand;
}

/*
 * the key files are of the form:
 * modulus				in hex
 * key component (secret or public accordingly) also in hex
 */

main(int argc, char **argv)
{
	MP_INT r, p, gen, exp, pub;
	int i, bits, nibbles, generator = 5;
	unsigned int exponent = 0;
	char *buf;

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <modulus nBits> [<generator>]\n", argv[0]);
		fprintf(stderr, "\tgive modulus size in bits\n");
		fprintf(stderr, "\toptionally give your choice of generator\n");
		exit(-1);
	}

	bits = atoi(argv[1]);
	if (bits < 32)
	{
		fprintf(stderr, "Invalid keysize.\n");
		exit(-1);
	}
	nibbles = (bits + 3)/ 4;

	i = nibbles;

	if ( argc > 2 )
	{
		generator = atoi(argv[2]);
	}
	
	mpz_init_set_ui(&r, 0);				/* Get a "random" prime. Used for the modulus. */
	while ((i -= 2) > 0)
	{
		mpz_mul_ui(&r, &r, 16);
		mpz_add_ui(&r, &r, get_random());
	}
	  
	mpz_init_set_ui(&p, 0);
	mpz_nextprime(&p, &r);
	
	fprintf(stdout, "%u|", generator );

	exponent = get_random();
	fprintf(stdout, "%u|", exponent );
 
	buf = mpz_get_str((char *) NULL, 16, &p);
	fprintf(stdout, "%s|", buf);
	free(buf);

    // Now generate the part of the shared secret we send to the client.
    
    mpz_init_set_ui(&pub, 0);
    mpz_init_set_ui(&gen, generator);
    mpz_init_set_ui(&exp, exponent);
    mpz_powm(&pub,&gen,&exp,&q);

	buf = mpz_get_str((char *) NULL, 16, &pub);
	fprintf(stdout, "%s\n", buf);
	free(buf);

    mpz_clear(&r);
    mpz_clear(&p);
    mpz_clear(&gen);
    mpz_clear(&exp);
    mpz_clear(&pub);
    
	exit(0);
}
