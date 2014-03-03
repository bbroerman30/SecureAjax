#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include "gmp.h"

/**********************************************************************

  program by Aggelos Keromitis <kermit@gr.forthnet>

  modified by Adam Back <aba@dcs.ex.ac.uk>
  -  changed to use bits rather than hex nibbles when specifying key sizes
  -  added option to allow choice of small public key exponents

  modified by Brad Broerman <bbroerman@bbroerman.net>
  - changed to use input and output formatting consistent with secureAjax application.

  You need the GNU mp library for this, get gmp-1.3.2.tar.gz

**********************************************************************/
volatile unsigned int i, counter, value;

static void handler(void);

/*
 * get_random:
 * return a random integer 0-255
 */

unsigned int
get_random(void)
{
	struct itimerval x, y;

	i = 0;
	counter = 0;
	value = 0;

	x.it_interval.tv_sec = 0;
	x.it_interval.tv_usec = 1;
	x.it_value.tv_sec = 0;
	x.it_value.tv_usec = 1;

	signal(SIGALRM, handler);
	if (setitimer(ITIMER_REAL, &x, &y) == -1)
	{
		perror("get_random()");
		return 0;
	}

	while (counter < 8)
	  i++;

	signal(SIGALRM, SIG_IGN);

    if (setitimer(ITIMER_REAL, &y, (struct itimerval *) NULL) == -1)
        perror("get_random()");

	return value;
}

/*
 * handler:
 * the SIGALRM handler
 */

void
handler(void)
{
	value = (value << 1) | (i & 0x1);
	counter++;
	i = 0;
	signal(SIGALRM, handler);
}

/*
 * the key files are of the form:
 * modulus				in hex
 * key component (secret or public accordingly) also in hex
 */

main(int argc, char **argv)
{
	MP_INT p, q, phi, n;
	int i, k, bits, nibbles, encrypt_key = 0;
	char *pub_buf, *priv_buf, *n_buf;
	FILE *fp1, *fp2;

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <modulus> [<public exponent>]\n", argv[0]);
		fprintf(stderr, "\tgive modulus size in bits\n");
		fprintf(stderr, "\toptionally give your choice of public exponent\n");
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
		encrypt_key = atoi(argv[2]);
	}
try_again:
	mpz_init_set_ui(&p, 0);				/* Get a "random" p */
	while ((i -= 2) > 0)
	{
		mpz_mul_ui(&p, &p, 16);
		mpz_add_ui(&p, &p, get_random());
	}

	while (!mpz_probab_prime_p(&p, 25))	/* Find a prime */
	    mpz_add_ui(&p, &p, 1);

	i = nibbles;

    mpz_init_set_ui(&q, 0);                         /* Get a "random" q */
    while ((i -= 2) > 0)
    {
        mpz_mul_ui(&q, &q, 16);
        mpz_add_ui(&q, &q, get_random());
    }

    while (!mpz_probab_prime_p(&q, 25))	/* Find a prime */
        mpz_add_ui(&q, &q, 1);

	mpz_init(&n);
	mpz_mul(&n, &p, &q);			/* Calculate the RSA modulus */

	n_buf = mpz_get_str((char *) NULL, 16, &n);

	mpz_sub_ui(&p, &p, 1);
	mpz_sub_ui(&q, &q, 1);
	mpz_init(&phi);
	mpz_mul(&phi, &p, &q);			/* Calculate (p - 1)*(q - 1) */
	mpz_clear(&p);

	i = nibbles;

	if (encrypt_key)
	{					/* user chosen */ 
		mpz_init_set_ui(&p,encrypt_key);/* small public exponent */
	}
	else
	{
		mpz_init_set_ui(&p, 0);		/* Get a "random" secret */
        while ((i--) > 0)
       	{
           	mpz_mul_ui(&p, &p, 16);
            mpz_add_ui(&p, &p, get_random());
       	}

        while (mpz_cmp(&p, &n) >= 0)	/* Chop it if larger than n */
		    mpz_div_ui(&p, &p, 2);

		do
		{
			mpz_add_ui(&p, &p, 1);
			mpz_gcd(&q, &p, &phi);		/* Get the GCD */
		} 
		while (mpz_cmp_ui(&q, 1) && mpz_cmp(&q,&phi)<=0);		/* until it is 1 */
	}
	pub_buf = mpz_get_str((char *) NULL, 16, &p);
	mpz_gcdext(&p, &q, &p, &p, &phi);

	if ( !mpz_cmp_ui(&q,1) || mpz_cmp(&q,&phi) >= 0)
	{
        free(pub_buf);
        free(n_buf);
        goto try_again;
	}
	
	if (mpz_cmp_ui(&q, 0) < 0)		/* If negative, add modulus */
        mpz_add(&q, &q, &phi);

	priv_buf = mpz_get_str((char *) NULL, 16, &q);

	mpz_clear(&p);
	mpz_clear(&q);
	mpz_clear(&phi);

    if( strlen(pub_buf) < nibbles - 1 ||
        strlen(priv_buf) < nibbles - 1 ||
        strlen(n_buf) < nibbles - 1 )
    {
         free(pub_buf);
         free(priv_buf);
         free(n_buf);
         goto try_again;
    }

	fprintf(stdout, "%s|", pub_buf);
	free(pub_buf);

	fprintf(stdout, "%s|", priv_buf);
	free(priv_buf);

	fprintf(stdout, "%s\n", n_buf);
    free(n_buf);

	exit(0);
}
