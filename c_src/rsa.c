/**************************************************************************************
 
  Secure Ajax Layer Copyright (C) 2008 - 2009 Brad Broerman,  bbroerman@bbroerman.net
  
  This Application is part of the Secure Ajax Layer, and is used to encode and decode
  RSA encrypted text. This program should be compiled on the target operating system and
  placed in the appropriate include directory.
  
  You need to obtain and compile the GNU Multi Precision math library for this, 
  get gmp-1.3.2.tar.gz

***************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "gmp.h"

char* doRSAEncode( MP_INT key, MP_INT mod, int keySize, char* block );
char* doRSADecode( MP_INT key, MP_INT mod, int keySize, char* block );

char* pkcs1pad2(char* s , int keylen);
char* pkcs1unpad2(char* d, int n);

int d2h( char d, char* out );
char h2d( char* h );
char doHexDigit( char in );

main(int argc, char **argv)
{
	MP_INT key, mod;
	
	char  inputbuff[20480];
	char* token = NULL;
	char* inmessage = NULL;
	char* outmessage = NULL;
	int   decode = 0;
	int   nohexencode = 0;
	int   chunklen = 0;
	int   idx;
	
	for( idx = 1; idx < argc; ++idx )
	{
		if( strcmp( argv[idx], "-d" ) == 0 )
		{		
			decode = 1;
		}

		if( strcmp( argv[idx], "-n" ) == 0 )
		{
		nohexencode = 1;
		}
	}
	
	// Take the parameters from stdin instead of arguments. This is more secure.
	fgets(inputbuff, 20479, stdin); 

	int i = strlen(inputbuff)-1;
	while(i>0 && inputbuff[i] == '\n')
		inputbuff[i--] = '\0';
	
	token = strtok (inputbuff,"|");
	if(token != NULL)
	{
		// first token is the key to use (private or public, it doesn't matter).
		mpz_init(&key);
		mpz_set_str(&key, token, 16);
	}
	else
	{
		fprintf(stdout,"Error: Too few tokens. Unable to process message.\n");
		exit(-1);      
	}
	
	token = strtok (NULL, "|");
	if(token != NULL)
	{
		// Second token is the modulus.
		mpz_init(&mod);
		mpz_set_str(&mod, token, 16);
	}
	else
	{
		fprintf(stdout,"Error: Too few tokens. Unable to process message.\n");
		exit(-1);      
	}

	int keysize = mpz_sizeinbase(&key,16);
	if( keysize%2 != 0 )
	{
		keysize++;
	}
	
	chunklen = keysize - 12;

	token = strtok (NULL, "|");
	if(token != NULL)
	{
		// Third token is the message to operate on.
		inmessage = token;
	}
	else
	{
		fprintf(stdout,"Error: Too few tokens. Unable to process message.\n");
		exit(-1);      
	}     
	
	// convert the key string from hexidecimal to binary...
	if( decode == 0 )
	{
		char chunk[chunklen+1]; 
		char hexdigits[3];
		int i = 0, chnkctr = 0;
		for( i = 0; i < strlen(inmessage); ++i )
		{
			if( 0 == nohexencode )
			{
				d2h( inmessage[i], hexdigits );
				chunk[chnkctr++] = hexdigits[0];
				chunk[chnkctr++] = hexdigits[1];
			}
			else
			{
				chunk[chnkctr++] = inmessage[i];
			}

			if( chnkctr >= chunklen )
			{
				chunk[chnkctr] = '\0';
				outmessage = doRSAEncode( key, mod, keysize, chunk );
				fprintf(stdout, "%s ", outmessage);
				chnkctr = 0;
				free(outmessage);
				outmessage = NULL;
			}
		}
		if( chnkctr <= chunklen )
		{   
			chunk[chnkctr] = '\0';
			outmessage = doRSAEncode( key, mod, keysize, chunk );
			fprintf(stdout, "%s", outmessage);
			free(outmessage);
			outmessage = NULL;
		}
	}
	else
	{
		token = strtok (inmessage, " ");
		while(token != NULL)
		{
			outmessage = doRSADecode( key, mod, keysize, token );

			if( 0 == nohexencode )
			{
				int idx = 0;
				int odx = 0;
				char chars[3] = {'\0','\0','\0'};
				char* buffer = malloc(strlen(outmessage));

				while(idx < strlen(outmessage))
				{
					chars[0] = outmessage[idx++];
					chars[1] = outmessage[idx++];
					buffer[odx++] = h2d(chars);
				}
				buffer[odx++] = '\0';
				fprintf(stdout, "%s", buffer);
				free(buffer);
			}
			else
			{
				fprintf(stdout, "%s", outmessage );
			}

			free(outmessage);
			outmessage = NULL;

			token = strtok (NULL, " ");
		}
	}		

	fprintf(stdout, "\n");

	mpz_clear(&key);
	mpz_clear(&mod);
	
	exit(0);
}

char* doRSAEncode( MP_INT key, MP_INT mod, int keySize, char* block )
{
	MP_INT msg, crpt;
	char* padded = NULL;
	char* buf= NULL;

	mpz_init(&msg);

	padded = pkcs1pad2( block , keySize);
	mpz_set_str(&msg, padded, 16);

	mpz_init_set_ui(&crpt, 0);
	mpz_powm(&crpt,&msg,&key,&mod);

	buf = mpz_get_str((char *) NULL, 16, &crpt);

	free( padded );
	mpz_clear(&msg);
	mpz_clear(&crpt);

	return buf;
}

char* doRSADecode( MP_INT key, MP_INT mod, int keySize, char* block )
{
	MP_INT msg, crpt;
	char* padded = NULL;
	char* buf = NULL;

	mpz_init(&msg);
	mpz_set_str(&msg, block, 16);

	mpz_init_set_ui(&crpt, 0);
	mpz_powm(&crpt,&msg,&key,&mod);
	padded = mpz_get_str((char *) NULL, 16, &crpt);

	buf = pkcs1unpad2(padded, keySize);
	free(padded);
	mpz_clear(&msg);
	mpz_clear(&crpt);

	return buf;
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
char* pkcs1pad2(char* s , int keylen)
{
	int i = strlen(s);
	char* ba = NULL;

	srand( (unsigned int)time( NULL ) );   
	
	if( keylen < strlen(s) + 11) 
	{
		fprintf(stderr, "Invalid message size: %u", strlen(s) );
		return NULL;
	}
	
	ba = (char*) malloc(keylen+2);

	ba[keylen] = '\0';
	
	ba[--keylen] = '0';
	
	while (i > 0 && keylen > 0)
	{
		ba[--keylen] = s[--i];
	}
	
	ba[--keylen] = '0';
	
	while(keylen > 2) 
	{ 
		// random non-zero pad
		int r = rand() % 15 + 1;
		char byte = (r < 10)?('0'+(char)r):('A' + (char)(r - 10));
		ba[--keylen] = byte;
	}

	ba[--keylen] = '2';
	ba[--keylen] = '0';

	return ba;  
}

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
char* pkcs1unpad2(char* d, int n) 
{
	int i = 0;
	int offset = 0;
	int dl = strlen(d);
	char* retval = malloc(dl);

	while( i < dl && d[i] == '0')
	{
		++i;
	}
	
	// The leading '0' wasn't there... compensate for it...
	if( i == 0 )
	{
		offset = 1;
	}

	if( dl - i != n - offset || d[i] != '2')
	{
		fprintf(stderr, "Malformed message: %s (dl: %u  i: %u  n: %u  o: %u, %c)\n", d, dl, i, n, offset, d[i] );
		return NULL;
	}
	
	++i;

	while( d[i] != '0' )
		if( ++i >= dl ) 
			return NULL;
	
	int j = 0;
	while( ++i < dl -1 )
		retval[j++] = d[i];
	
	retval[j++] = '\0';    

	return retval;
}

int d2h( char d, char* out )
{
	char  hexchars[17] = "0123456789ABCDEF";
	out[0] = hexchars[ (d >> 4) & 0x0F ];
	out[1] = hexchars[ d & 0x0F ];
	out[2] = '\0';

	return 0;
}

char h2d( char* d )
{
	char byte = 0;
	byte += doHexDigit(d[0]) << 4;
	byte += doHexDigit(d[1]);

	return byte & 0xFF;
}

char doHexDigit( char in )
{
	if( in >= 'A' && in < 'G' )
	return in - 'A';
	else if( in >= 'a' && in < 'g' )
	return in - 'a';
	else if( in >= '0' && in <= '9' ) 
	return in - '0';
}
