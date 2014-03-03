#include <stdio.h>
#include "gmp.h"
/**************************************************************************************
 
  Secure Ajax Layer Copyright (C) 2008 - 2009 Brad Broerman,  bbroerman@bbroerman.net
  
  This Application is part of the Secure Ajax Layer, and is used to generate Diffie-Hellman
  message used to securely negotiate encryption keys. This program should be compiled on the
  target operating system and placed in the appropriate include directory.

  You need to obtain and compile the GNU Multi Precision math library for this, 
  get gmp-1.3.2.tar.gz

***************************************************************************************/
main(int argc, char **argv)
{
	MP_INT p, gen, exp, pub, sec;
	
	int generator = 0;
	unsigned int exponent = 0;
	char* buf;
	char  inputbuff[20480];
    char* token;

    // Take the parameters from stdin instead of arguments. This is more secure.
    fgets(inputbuff, 20480, stdin); 
    
    token = strtok (inputbuff,"|");
    if(token != NULL)
    {
        // first token is the generator.
         generator = atoi(token);
    }
    else
    {
        fprintf(stdout,"Error: Too few tokens. Unable to process message.\n");
        exit(-1);      
    }
    
    token = strtok (NULL, "|");
    if(token != NULL)
    {
        // Second token is the exponent
        exponent = atoi(token);
    }
    else
    {
        fprintf(stdout,"Error: Too few tokens. Unable to process message.\n");
        exit(-1);      
    }

    token = strtok (NULL, "|");
    if(token != NULL)
    {
        // Third token is the prime modulus
        mpz_init(&p);
        mpz_set_str(&p, token, 16);
    }
    else
    {
        fprintf(stdout,"Error: Too few tokens. Unable to process message.\n");
        exit(-1);      
    }

    token = strtok (NULL, "|");
    if(token != NULL)
    {
        // Fourth token is the message from the client.
        mpz_init(&pub);
        mpz_set_str(&pub, token, 16);
    }   
    else
    {
        fprintf(stdout,"Error: Too few tokens. Unable to process message.\n");
        exit(-1);      
    }
 
    // Now generate the part of the shared secret we send to the client.    
    mpz_init_set_ui(&gen, generator);
    mpz_init_set_ui(&exp, exponent);
    mpz_init_set_ui(&sec, 0);
    
    mpz_powm(&sec,&pub,&exp,&p);

	buf = mpz_get_str((char *) NULL, 16, &sec);
	fprintf(stdout, "%s\n", buf);
	free(buf);

    mpz_clear(&p);
    mpz_clear(&gen);
    mpz_clear(&exp);
    mpz_clear(&pub);
    mpz_clear(&sec);   
    
	exit(0);
}
