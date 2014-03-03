#!/usr/bin/php
<?php

/**
 * Secure Ajax Layer Copyright (C) 2008 - 2009 Brad Broerman,  bbroerman@bbroerman.net
 *
 * Process used to generate a table of random RSA keys that can be included in SecureAjax. This pre-calculates
 * the table to make run-time faster (needed when using the pure PHP implementation of SecureAjax methods).
 * You should run this priocess on a box where you have access to either GMP library or the C implementation of RSA methods.
 * Then, the generated output can be captured and piped to the rsakeys.php keys file.
 *
 * The only argument to this script is the number of table entries to create. You should make it a BIG table, and recreate them often!
 *
 */

// For the fastest, use the c implementtion. If you can't run C processes, you can change this to rsa-gmp but it will be slower.
include "rsa-c.php";

// Sart by printing out the header.
echo "<?php\n\n // Table of randomly generated RSA keys.\n \$RSAKEYTABLE = array( ";

// Now, we will create a bunch of RSA keys, and output them to the table.
for( $cnt = 0; $cnt < $argv[1]; ++$cnt ) {
  $curr_key = genRSAKey( 128 );
  $curr_key['public'] = substr('00000'.$curr_key['public'],-32);
  $curr_key['private'] = substr('00000'.$curr_key['private'],-32);
  $curr_key['mod'] = substr('00000'.$curr_key['mod'],-32);

  if( $cnt > 0 ) echo "                      ";
  echo " array(\"". $curr_key['public'] . "\",\"" .  $curr_key['private'] . "\",\"" .$curr_key['mod'] . "\")";
  if( $cnt+1 < $argv[1] ) echo ",\n";
 }

// The method below (which is printed to the file) is used to pick a key from the table at random. 
echo <<< EOFF
);

function chooseRandomRSAKey()
{
    global \$RSAKEYTABLE;

    list(\$usec, \$sec) = explode(' ', microtime());
    srand( (float)\$sec + ((float) \$usec * 100000) );
    \$idx = rand(0, count(\$RSAKEYTABLE)-1);

    \$rsaKey = array();
    \$rsaKey['public'] = \$RSAKEYTABLE[\$idx][0];
    \$rsaKey['private'] = \$RSAKEYTABLE[\$idx][1];
    \$rsaKey['mod'] = \$RSAKEYTABLE[\$idx][2];
    \$rsaKey['size'] = strlen(\$RSAKEYTABLE[\$idx][0]);

    return \$rsaKey;
}
?>
EOFF;

?>
