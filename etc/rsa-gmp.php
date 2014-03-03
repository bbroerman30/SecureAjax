<?php
//
//  Secure Ajax Layer Copyright (C) 2008 - 2009 Brad Broerman,  bbroerman@bbroerman.net
//
//   PHP / GMP implementation of RSA Public Key Cryptography.
//

/**
 * Generate a random RSA key of length keylen. 
 * If the optional parameter encryptKey is passed, use it for the public key exponent.
 * The key returned contains 3 hexidecimal strings: the 'private' exponent, the 'public' exponent, the 'mod'ulus, and the length of the key in nibbles.
 * 
 * @param keylen - integer: The length, in bits, for the key. Should be 128, 256, or 512.
 * @param encryptKey - (optional) integer: If passed, use this value as the public key exponent.
 * @return Array - The keypair to use. Hash keys are private, public, mod, and size. Eash value (except size) is a hexidecimal string.
 */
function genRSAKey( $keylen, $encryptKey = null )
{
    // retry up to 3 times.
    for($i = 0; $i < 3; ++$i )
	{
		$key = doGenRSAKeyTry( $keylen, $encryptKey );
		
		// If we got a good one, return it, else try again.
		if( $key !== false )
		{
		   return $key;
		}
	}
	
	// If we've tried all 3 times and still no proper key, just return false.
	return false;
}

/**
 * From the masterKey (the complete key), extract the portions that are necessary for the private (decryption) key.
 * This is the private exponent, modulus, and the size (this is for convenience)
 *
 * @param masterKey - the complete key array (including the public and private keys)
 * @return array - The private key parts (exp, mod, and size) 
 */
function getPrivateKey( $masterKey )
{
	$key = Array();
	$key['exp'] = $masterKey['private'];
	$key['mod'] = $masterKey['mod']; 
	$key['size'] = $masterKey['size']; 

	return $key;
}

/**
 * From the masterKey (the complete key), extract the portions that are necessary for the public (encryption) key.
 * This is the private exponent, modulus, and the size (this is for convenience)
 *
 * @param masterKey - the complete key array (including the public and private keys)
 * @return array - The public key parts (exp, mod, and size) 
 */
function getPublicKey( $masterKey )
{
	$key = Array();
	$key['exp'] = $masterKey['public'];
	$key['mod'] = $masterKey['mod']; 
	$key['size'] = $masterKey['size']; 

	return $key;
}

/**
 * Make a key array structure from an exponent and a modulus.
 * Returns an array with the keys "exp", "mod", and "size".
 *
 * @param exp - String. Hexidecimal string containing the exponent (public or private)
 * @param mod - String. Hexidecimal string containing the modulus.
 * @return Array - The key structure containing the pieces of the key.
 */
function makeKey( $exp, $mod )
{
	$key = Array();
	$key['exp'] = $exp;
	$key['mod'] = $mod; 
	$key['size'] = strlen($mod); 
	
	if( $key['size'] % 2 == 1 )
	    $key['size'] += 1;	    

	return $key;
}

/**
 * Serialize a key structure (simple way) 
 * Since the key parts are just hexidecimal strings, concatenate them with a vertical pipe separator.
 *
 * @param key - Array. The key structure (private or public key structure, not the master key)
 * @return String - The exponent and modulus concatenated as a pipe delimited string.
 */
function serializeKey( $key )
{
    return $key['exp'] . "|" . $key['mod'];
}

/**
 * Deserilaize a sting and try to build a key structure from it.
 *
 * @param buffer - String. Serialized key structure.
 * @return Array - Reconstituted key structure with exponent, modulus, and size.
 */
function readKey( $buffer )
{
    $keyparts = explode("|", $buffer);
    if( !is_array($keyparts) || count($keyparts) != 2 )
        return false;
        
    return makeKey( $keyparts[0], $keyparts[1] );
}

/**
 * Encrypt an incoming string buffer with RSA using the specified key (private or public, not master)
 * Return the encoded cryptext as a hexidecimal string. The input buffer will be padded using PKCS1-v1
 * While not the most secure, it only has to be good for the current web session. Note also that the RSA
 * here can not be used with other RSA implementations. It's been slightly simplified for the JS encode/decode speed.
 *
 * @param buffer - String: A string to be encoded in RSA using the specified key.
 * @param key - Array: The key to use when encoding the above string (private or public, not the master key)
 * @param hexEncode - (optional) boolean: If set to false, assume the buffer is already encoded in Hexidecimal.
 * @return String - The cryptext of the input buffer, encoded with PKCS1-v1 padding and RSA.
 */
function encryptRSA($buffer, $key, $hexEncode = true)
{
    // Chunk length is 6 bytes (48 bits) less than the key size. 
    // this provides room for the padding, and overhead.
    $chunklen = $key['size'] - 12;

	$i = 0;
	$chunk = "";
	$outStr = "";
		
	// For the entire string,	
	for( $i = 0; $i < strlen($buffer); ++$i )
    {
        // Let's build the chunk buffer, one byte at a time.
	    if( true == $hexEncode )
		{
			// If we need to encode it into hex, get the hex value of the current character.
		    $chunk = $chunk . substr("0" . dechex(ord(substr($buffer,$i,1))),-2);
		}
		else
		{
		    // else, just pull the next character from the buffer.
		    $chunk = $chunk . substr($buffer,$i,1);
		}
		
		// Once we have a full chunk, encode it
		if( strlen($chunk) >= $chunklen )
		{
			$tmpOutStr = doRSAEncode( $key['exp'], $key['mod'], $key['size'], $chunk );
			
			if( false === $tmpOutStr )
				return false;
			
			// And append it to the output string (we add a space inbetween chunks to make the JS easier to decode it). 
			$outStr = $outStr . $tmpOutStr . " ";
			$chunk = "";
		}
    }
	
	// Now, take any final chunk data, and encode it as well.	
    if( strlen($chunk) > 0 )
	{   
		$tmpOutStr = doRSAEncode( $key['exp'], $key['mod'], $key['size'], $chunk );
			
		if( false === $tmpOutStr )
			return false;
			
		$outStr = $outStr . $tmpOutStr;
		$chunk = "";
	}
	
	// return the encoded data.
	return rtrim($outStr);
}

/**
 * Decrypt an RSA encrypted message using the specified key. The message must be encoded using encryptRSA() above, 
 * or from the SecureAjax javascript. It is not compatible with other RSA implementations. By default, it will convert
 * each output byte into an ascii character, but if hexDecode is passed as false, it will leave the output as a hexidecimal 
 * string.
 * 
 * @param buffer - String: the input cryptext.
 * @param key - Array: The key to use when encoding the above string (private or public, not the master key)
 * @param hexDecode - (optional) boolean: If passed as false, leave the output plaintext as a hexidecimal string.
 * @return String - The plaintext message.
 */
function decryptRSA($buffer, $key, $hexDecode = true)
{
    // Split the incoming buffer into blocks on the space.
	$tokens = explode(" ", $buffer);
	$outBuffer = "";
	
	// For each incoming token (a block from the encryption operation)
	for($idx = 0; $idx < count($tokens); ++$idx )
	{
		// Decode the current chunk
    	$outmessage = doRSADecode($key['exp'], $key['mod'], $key['size'], $tokens[$idx]);
		
		// If we had an error, return false immediately.
		if( false === $outmessage )
		{
		    return false;
		}

        // If we're OK, append the chunk to the output buffer.
		if( true == $hexDecode )
		{
		    // Decode the hexidecimal to ascii if we've set hexDecode to true, or didn't pass it.
            for($ctr = 0; $ctr < strlen($outmessage); $ctr += 2)
			{
				$chr = hexdec(substr($outmessage, $ctr, 2));
				$outBuffer .= chr( $chr );
			}
		}
		else
		{
			$outBuffer .= $outmessage;
		}
	}
    
    // finally, return the output buffer...    
    return $outBuffer;
}

//
//  Private Methods:
//
     
/**
 * PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
 *
 * @access private
 * @param str - String: Hexidecimal string to be padded.
 * @param keylen - integer: Length of the key (in nibbles)
 * @return String - The padded block as a hexidecimal string.
 */
function pkcs1pad2($str, $keylen)
{
	$i = strlen($str);
	$ba = "";
	
	// Make sure the input string is the proper size for the key length.
	if( $keylen < $i + 11) 
	{
		return false;
	}

	// Add '0' markers to each end of the input string, 
	// and reverse it's order.
	$ba = '0' . strrev($str) . '0';
	$i += 2;

	// Now, append the random padding to the input string
	while( $i < $keylen - 2) 
	{ 
		// random non-zero pad
		$r = rand(1,15);		
		$nibble = dechex($r);
		$ba .= $nibble;
		++$i;
	}

	// Now, add the padding markers
	$ba = $ba . '2';
	$ba = $ba . '0';

	// and return the string (reversed to it's proper order)
	return strrev($ba);  
}

/**
 * Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
 *
 * @access private
 * @param str - String: The decrypted, but padded plaintext to be un-padded.
 * @param keylen - integer: The length of the key (in nibbles)
 * @return String - The un-padded plaintext message.
 */
function pkcs1unpad2($str, $keylen) 
{
	$i = 0;
	$offset = 0;
	$strl = strlen($str);
	$retval = "";

    // Strip out leading '0'
	while( $i < $strl && substr($str, $i, 1) == '0')
	{
		++$i;
	}
	
	// The leading '0' wasn't there (math issue)... compensate for it...
	if( $i == 0 )
	{
		$offset = 1;
	}

    // validate the position of the start flag '2'.
	if( $strl - $i != $keylen - $offset || substr($str, $i, 1)  != '2')
	{
        return false;
    }
    
    // Validate the end of the string contains a '0'.
    if( substr($str, -1) != '0' )
    {
        return false;
    }
	
	// Now, Skip over the '2'
	++$i;

    // and skip over the padding. (go to the next '0').
	while( substr($str, $i, 1)  != '0' )
	{
		if( ++$i >= $strl ) 
		{
		    return false;
	    }
	}
	
	// Get the rest of the string (skipping the ending '0').
	$retval = substr($str, $i + 1, $strl - $i - 2);		
	
	return $retval;
}

/**
 * Encode an input plaintext block with RSA using PKCS#1 (type 2, random) padding, and
 * the specified key (expopnent) and modulus. The exponent, modulus, and block must all 
 * be hexidecimal numbers in string format. keysize will be an integer.
 * The size of block should be 11 characters less than keySize to make room for the padding.
 *
 * @access private
 * @param key - String: The exponent (public or private) used to encrypt the block. Must be a hexidecimal number.
 * @param mod - String: The modulus. Must be a hexidecimal number.
 * @param keysize - integer: The size of the key in nibbles (characters when in hex)
 * @param block - String: The input plaintext message (in hex format) to encode. Must be 11 characters less than keySize.
 * @return String - The cryptext of the message. Returns boolean false if error.
 */
function doRSAEncode( $key, $mod, $keySize, $block )
{
	// Pad the block (returns false if error)
	$padded = pkcs1pad2( $block , $keySize);

	// If ok, then perform the math: ( msg ^ exp )% mod
    if( false !== $padded )
    {
        $msg = gmp_init($padded,16);
        $key = gmp_init($key,16);
        $mod = gmp_init($mod,16);
    
        $crypt = gmp_powm($msg,$key,$mod);
        
		// Return it as a hexidecimal number.
        return gmp_strval($crypt,16);
    }
    
    // If error (from the padding) return false.
    return false;
}

/**
 * Decode an input cryptotext block with RSA using PKCS#1 (type 2, random) padding, and
 * the specified key (expopnent) and modulus. The exponent, modulus, and block must all 
 * be hexidecimal numbers in string format. keysize will be an integer.
 *
 * @access private
 * @param key - String: The exponent (public or private) used to encrypt the block. Must be a hexidecimal number.
 * @param mod - String: The modulus. Must be a hexidecimal number.
 * @param keysize - integer: The size of the key in nibbles (characters when in hex)
 * @param block - String: The input cryptotext message (in hex format) to decode.
 * @return String - The plaintext of the message. Returns boolean false if error.
 */
function doRSADecode( $key, $mod, $keySize, $block )
{
    $msg = gmp_init($block,16);
    $key = gmp_init($key,16);
    $mod = gmp_init($mod,16);

	$crpt = gmp_powm($msg,$key,$mod);
	
	$padded = gmp_strval($crpt,16);

	$buf = pkcs1unpad2($padded, $keySize);

	return $buf;
}

/**
 * Generate a random RSA key of length keylen. 
 * If the optional parameter encryptKey is passed, use it for the public key exponent.
 * 
 * TODO: remove debug print statements when fully debugged.
 *
 * @access private
 * @param keylen - integer: The length, in bits, for the key. Should be 128, 256, or 512.
 * @param encryptKey - (optional) integer: If passed, use this value as the public key exponent.
 * @return Array - The keypair to use. Hash keys are private, public, mod, and size. Eash value (except size) is a hexidecimal string.
 */
function doGenRSAKeyTry( $keylen, $encryptKey = null )
{
    $const_1 = gmp_init("1",10);
    $const_2 = gmp_init("2",10);

	if( $keylen != 64 && $keylen != 128 && $keylen != 256 && $keylen != 512 )
	{
	    echo "Bad Keylen\n";
	    return false;
	}
    
	$randomStr = getSecureRandom($keylen/2);
	if( false === $randomStr ) {
	    echo "Bad Random\n";
	    return false;
  }
  
  $RandomNbr = gmp_init($randomStr,16);    
  $p = gmp_nextprime($RandomNbr);
    
	$randomStr = getSecureRandom($keylen/2);
	if( false === $randomStr ) {
	    echo "Bad Random\n";
	    return false;
  }
  
	$RandomNbr = gmp_init($randomStr,16);    
    $q = gmp_nextprime($RandomNbr);
    
    // Get the RSA Modulus.
    $n = gmp_mul( $p, $q );
    
    // Calculate ( p - 1 ) * ( q - 1 )
    $phi = gmp_mul( gmp_sub( $p, $const_1 ), gmp_sub( $q, $const_1 ) );
    
    // Get the public exponent.
    $e = "";
    if( null != $encryptKey )
    {
        $e = gmp_init($encryptKey,10);
    }
    else
    {
		$randomStr = getSecureRandom($keylen);
		if( false === $randomStr ) {
	    echo "Bad Random\n";
	    return false;
    }			
        $e = gmp_init($randomStr,16);
        
        while (gmp_cmp($e, $n) >= 0)	/* Chop it if larger than n */
        {
		   $e = gmp_div($e, $const_2);
        }
        
        do
		{
			$e = gmp_add($e, $const_1);			
			$q = gmp_gcd($e, $phi);		/* Get the GCD */
		} 
		while ( gmp_cmp($q, $const_1) != 0 && gmp_cmp($q,$phi) <= 0);		/* until it is 1 */           
    }
    
    // Now calculate the private exponent.
	$d = gmp_invert($e, $phi);
        
	// Test the key before we return it. To see if it's OK.
	$testVector = gmp_init("28471851f289df5d56e0d85e9024f60",16);
	$verified =  gmp_powm(gmp_powm($testVector,$e,$n),$d,$n);
	
	if( gmp_cmp($verified, $testVector ) != 0 )
	{
		return false;
	}
	
    $key = array();
    $key['public'] = gmp_strval($e,16);
    $key['private'] = gmp_strval($d,16);
    $key['mod'] = gmp_strval($n,16);
    $key['size'] = $keylen / 4;
    
    return $key;
}


/**
 * Generate a random number of keylen bits in size.
 * Tries to read from /dev/urandom on UNIX/Linux or CAPICOM COM object on windows.
 * 
 * @param keylen - the size (in bits) of the random number to generate.
 * @return String - A hexidecimal encoded large random number of keylen bits in length, or boolean false if error.
 */
function getSecureRandom($keylen)
{
    $pr_bits = '';
    $numBytes = $keylen / 8;

    // Unix/Linux platform?
    $fp = fopen('/dev/urandom','rb');
    if ($fp !== FALSE) 
    {
        $pr_bits .= fread($fp,$numBytes);
        @fclose($fp);
    }

    // MS-Windows platform?
    else if (@class_exists('COM')) 
    {
        // http://msdn.microsoft.com/en-us/library/aa388176(VS.85).aspx
        try 
        {
            $CAPI_Util = new COM('CAPICOM.Utilities.1');
            $pr_bits .= $CAPI_Util->GetRandom($numBytes,0);

            if ($pr_bits) 
            { 
                $pr_bits = base64_decode($pr_bits,TRUE); 
            }
        } 
        catch (Exception $ex) 
        {
            // Silently fail on this...
        }
    }

    if (strlen($pr_bits) < $numBytes) 
    {
        // do something to warn system owner that
        // pseudorandom generator is missing
        return false;
    }

    return bin2hex($pr_bits);
}
?>