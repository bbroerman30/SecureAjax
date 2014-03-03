<?php
/**
 *  Secure Ajax Layer Copyright (C) 2008 - 2009 Brad Broerman,  bbroerman@bbroerman.net
 *  Utility functions used to prepare and process Diffie-Hellman Key Agreement messages.
 * 
 *  Implemented in pure PHP. This may be slow, so don't use on a large system.
 */
 
// Use the PHP BigInt arbitrary precision math library. Limit our execution time to 60 seconds as it may be slow... 
require_once 'BigInt.php';
set_time_limit( 60 ); 

/**
 * Generate the initial message to be sent to the client for a Diffie Hellman exchange. 
 * This method will generate and return the Generator, Exponent, Modulus, and the initial term for a 
 * Diffie Hellman exchange. It stores the results in a hash to be returned. The message is what is 
 * sent to the client, and the rest is stored locally. (The exponent is kept secret) the return message
 * is sent to the calcDiffieHellmanSecret() method to generate the shared secret.
 * 
 * @param $keylen - int: The length of the key (in bits) to generate.
 * @return Mixed - A hash containing the generator, exponent, modulus, initial calculated term,and message for a Diffie Hellman exchange, or boolean false on error.
 */
function genDiffieHellmanMsg( $keylen )
{
	// Use 5 as our default generator (more secure than using 3 or 7 for some reason)
    $DefaultGenerator = "05";

	// Start off with a random hexidecimal number of keylen bits long,
    $RandomStr = getSecureRandomDH( $keylen );
    // And find the next prime number after it. This wil be our modulus.
    $prime = BigInt::nextPrime(BigInt::fromString($RandomStr,16))->toString(16); 

	// Generate a random 16 bit exponent.
    $randomExp = getSecureRandom(16);
    
    // and generate the message to send to the client.
    $dhMessage = calcDiffieHellmanSecret( $DefaultGenerator, $randomExp, $prime );

	// We pass back the generator, exponent, prime modulus, and the calculated value. 
	// and format a message with the generator, modulus, and calculated message for our client to use.
    $dhKey = array();
    $dhKey['gen'] = $DefaultGenerator;
    $dhKey['exp'] = $randomExp;
    $dhKey['mod'] = $prime;
    $dhKey['calc'] = $dhMessage;
    $dhKey['message'] = $DefaultGenerator . "|" . $prime . "|" . $dhMessage ;

    return $dhKey;
}

/**
 * Calculate the shared secret based on an input generator (or message), random exponent, and modulus.
 * This method generates the shared secret to be used in a symmertric encryption. If a message is passed
 * from the client, the method generates the shared secret, else the method will use the generator to 
 * create a message value to be sent to the client.
 * Note, message will be used when the client initiates the key agreement transaction.
 *
 * @param generator - String (Hexidecimal) Generator. Usually 3, 5, or other small prime. Chosen in genDiffieHellmanMsg() method.
 * @param exponent - String (Hexidecimal) Randomly generated secret number.
 * @param modulus - String (Hexidecimal) Prime number calculated by genDiffieHellmanMsg()
 * @param message - (optional) String (Hexidecimal) Message returned from the client.
 */
function calcDiffieHellmanSecret( $gen, $exp, $mod, $message = null )
{
    // Prepare the base of the operation gen^exp%mod. If we passed in a message, use it.
    // Else use the generator. 
    if( isSet($message) && null != $message && strlen($message) > 0)
    {
        $gen = BigInt::fromString($message,16);
    }
    else
    {
        $gen = BigInt::fromString($gen,16);
    }
    
	// Now, prepare the exponent and modulus.
    $exp = BigInt::fromString($exp,16);
    $mod = BigInt::fromString($mod,16);
    
    // Perform the operation and get the result as a Hex string.
    $sec = BigInt::powMod($gen,$exp,$mod);
    $message = $sec->toString(16);
	
	// Make sure result is padded to byte size.
	if( strlen( $message ) % 2 == 1 )
	{
	    $message = "0" . $message;
	}
	
	// and return it.
    return $message;
}


/**
 * Generate a random number of size keylen.
 * If we are on UNIX/Linux use /dev/urandom else if Windows, find the CAPICOM COM object.
 *
 * @param keylen - int. The number of bits to make the random number.
 * @return String - The random number as a hexidecimal string.
 */
function getSecureRandomDH($keylen)
{
    $pr_bits = '';
    $numBytes = $keylen / 8;

    // Unix/Linux platform?
    $fp = @fopen('/dev/urandom','rb');
    if ($fp !== FALSE) 
    {
        $pr_bits .= @fread($fp,$numBytes);
        @fclose($fp);
    }

    // MS-Windows platform?
    if (@class_exists('COM')) 
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
            // echo 'Exception: ' . $ex->getMessage();
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