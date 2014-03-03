<?php

/**
 *  Secure Ajax Layer Copyright (C) 2008 - 2009 Brad Broerman,  bbroerman@bbroerman.net
 *
 * RSA Public Key Cryptography Implemented in C processes and called from PHP.
 */

// The directories that the binaries 'gendhkeys' and 'getdhsec' are located in.
$rsabindir = "/www/sites/bbroerman.net/etc/";

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
    global $rsabindir;
    
    // Start off with putting the key length in the param list.
    $params = $keylen;
    
    // If we pass in the encryptKey parameter, add it to the params...
    if( null != $encryptKey )
    {
        $params .= " " . $encryptKey;
    }
    
    // Run the key generator process. It will return the key parts on it's stdout.	
	$message = runExternalProcess( $rsabindir.'rsakg ', $params,"");

    // If we got back the key parts, split them out and return the array.
    if( $message !== false )
    {
        $keyArr = explode("|", $message );
        
        $key['public'] = $keyArr[1];
        $key['private'] = $keyArr[0];
        $key['mod'] = $keyArr[2];
        $key['size'] = $keylen / 4;
     
        return $key;
    }
    
    // Otherwise, return false.
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
function encryptRSA( $buffer, $key, $hexEncode = true )
{
    global $rsabindir;
    $params = "";
    
    // If hexEncode is set to false, we need a switch for the process.
    if( false == $hexEncode )
	{
	    $params .= "-n";
	}    
	
	// Run the rsa process. The key and buffer are sent to it's stdin, and the cryptext comes from it's stdout.
	$message = runExternalProcess( $rsabindir.'rsa', "", $key['exp'] . "|" . $key['mod'] . "|" . $buffer);
	
	// return the cryptext (or false if there was an error)
    return $message;    
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
    global $rsabindir;
    
    // decrypt 
	$params = "-d";

	// If we don't want to convert the hex output to ascii, set the flag for that.
    if( false == $hexDecode )
	{
	    $params .= " -n";
	}
	
	// Run the rsa process. The key and cryptext are sent to it's stdin, and the plaintext comes from it's stdout.
	$message = runExternalProcess( $rsabindir.'rsa', $params, $key['exp'] . "|" . $key['mod'] . "|" . $buffer);
	
	// return the plaintext.
    return $message;    
}

/**
 * Call an external C process with arguments. Pass a string to the process through a pipe to it's
 * stdin, capture it's stdout through another pipe and return the string. Used to call processes
 * in a more secure manner than just passing all data in arguments.
 *
 * @param processName - String. The full path name of the process to call.
 * @param args - String. The parameter string to pass to the process (just as typed on the command line)
 * @param stdin - String. The string to pass to the process' stdin.
 *
 * @return Mixed - String if process compltes properly (the stdout of the process) or boolean false on error.
 */
function runExternalProcess( $processName, $args, $stdin)
{
    global $rsabindir;
    
	// Prepare the pipe descriptors.
    $descriptorspec = array(
        0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
        1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
        2 => array("pipe", "w")   // stderr will be discarded.
    );

	// Open the process, passing it the pipe descriptors.
    $process = proc_open($processName." ".$args, $descriptorspec, $pipes, NULL, NULL);
    
    // If we have a good process, write to it's stdin, and read it's stdout.
    if (is_resource($process)) 
    {
        fwrite($pipes[0], $stdin );
        fclose($pipes[0]);

        // Read StdOut
        $message = '';
        while(!feof($pipes[1])) 
        {
            $message .= fgets($pipes[1], 1024);
        }
        fclose($pipes[1]);
        
        $message = trim($message);
           
        // Read StdErr
        $StdErr = '';
        while(!feof($pipes[2]))    
        {
            $StdErr .= fgets($pipes[2], 1024);
        }        
        fclose($pipes[2]);
            
        // Make sure to close the process after we're all done. Get the return code.    
        $return_value = proc_close($process);
 
		// TODO: If we have a problem, print out the stderr adn return code. This should go to a log file in a production process.
        if( 0 !=  $return_value || strlen($StdErr) > 0)
        {
            print("<b> Error: " . $StdErr . " </b>\n" );
            print("<b> ReturnCode: " . $return_value . " </b>\n" );
            
            // return false if there is an error.
            return false;
        }
        
		// else return the message.
        return $message;
    }
    
	// If the process didn't start, log the error and return false. TODO: Print to a secure log file.
    print("<b> Error: process didn't run. </b>\n");   
    return false;
} 

?>
