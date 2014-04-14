<?php
/**
 * Secure Ajax Layer Copyright (c) 2008 - 2009 Brad Broerman. bbroerman@bbroerman.net
 * BigInt library Copyright 1998-2005 David Shapiro. dave@ohdave.com
 * RSA Javascript library Copyright 1998-2005 David Shapiro. dave@ohdave.com
 * SHA-1 Javascript library Copyright Paul Johnston 2000 - 2002. 
 *     Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet 
 *     Distributed under the BSD License See http://pajhome.org.uk/crypt/md5 for details.
 * AES Javascript library Copyright Chris Veness 2005-2008. Right of free use is granted for all.
 *
 * This file should be included at the head of all web visible applications. It includes methods used to retrieve, validate
 * and decode messages, print responses, page headers (to send proper XML), and start a session. You may modify portions of
 * this as needed to suit your needs.
 *
 * SecureAjaxConfig should be required before the include for this file.
 */
 
if( !isSet($secureAjaxConfig) || !is_Array($secureAjaxConfig) )
{
     trigger_error("SecureAjax config file was not loaded.", E_USER_ERROR);
}

/**
 * These requires are used to select which implementation of AES, RSA, and Diffie-Hellman to use.
 * Options are: aes (AES in pure php), aes-c (AES implemented in C), 
 *              rsa-gmp (RSA implemented in PHP with gmp plug-in), rsa-c (RSA implemented in C), rsa-php (RSA in pure PHP - slow!)
 *              diffie-hellman-gmp (Diffie Hellman in PHP using gmp plug-in), diffie-hellman-c (same, written in C), diffie-hellman-php (in Pure PHP)
 */
require_once( $secureAjaxConfig['INCDIR'] . "aes.php");
require_once( $secureAjaxConfig['INCDIR'] . "rsa-gmp.php");
require_once( $secureAjaxConfig['INCDIR'] . "diffie-hellman-gmp.php");

/**
 * This method retrieves the incoming encrypted SecureAjax message in the POST parameter msg, and returns the message unencrypted.
 * After this point, you can do what you want with it, including splitting parameters, json-decoding, etc. Since the JS send methods
 * just take what you give them, it's pretty much up to the application.
 *
 * @param None
 * @return Mixed - Decrypted message string (if valid) or boolean false if not.
 */
function getMessage()
{
    if( isSet($_POST['msg']) && strlen($_POST['msg']) > 0 )
    {
        $decoded = decryptMessage( $_POST['msg'] );
        return $decoded;
    }
    
    return false; 
}

/**
 * Decrypts an incoming SecureAjax message, and validates the message signature. 
 * This uses the methods included from the AES, and RSA libraries, and uses PHP's
 * built-in sha-1 implementation. This method should never be modified.
 *
 * @param String - message: The encrypted message string to decode (with signature).
 * @return Mixed - Descrypted message string (if valid) or boolean false if not.
 */
function decryptMessage( $message )
{
    // Find the locaiton of the message signature
    $idx = strpos( $message, "(" );
    $idx2 = strrpos( $message, ")" );
    
    // Make sure we have one, else return an error.
    if( $idx > -1 && $idx2 > -1 && $idx < $idx2 )
    {
        // Pull apart the message and signature.
        $signature = substr( $message, $idx + 1, $idx2 - $idx -1   );
        $message = substr( $message, 0, $idx );
        
        // Get the hash of the message itself
        $hash = sha1($message);
        
        // and decrypt the incoming hash (this validate the RSA key of the sender
        // as well as validating that the message wasn't messed with)
        $orig_hash = decryptRSA( $signature,
                                 makeKey( $_SESSION['RSA_SERVER_PRIVATE'], 
                                          $_SESSION['RSA_SERVER_MODULUS'] ) );               

		// Make sure the calculated hash matches the incoming one. 
        if( strcasecmp( $hash, $orig_hash ) == 0 )
        {
             // clean up message doing substitutions we had to do before to make the incoming string parameter safe.
            $message = strtr($message, '-_,', '+/=');
            
            // and decrypt the message.            
            $decoded = AESDecryptCtr($message, $_SESSION['AES_KEY'], 256);
            
            // finally, if all was good, send the message back.   
            return $decoded;
        }
        
        // Otherwise, on error, return false.
        return false;
    }   
    
    return false;
}

/**
 * This method encrypts and signs a response message to be sent back to the SecureAjax JS library on the client side.
 * It uses AES-256 and RSA to encrypt and then sign the message. The current AES and RSA keys are stored in the session 
 * for the current user. (They can be re-negotiated at any time). The message is retuned as the inner part of an XML message.
 *
 * @param message - String. The message to encrypt and sign.
 * @return Mixed - The string message if successful, or boolean false otherwise.
 */
function encryptResponse( $message )
{
	// Encrypt the incoming message,
    $encoded = AESEncryptCtr($message, $_SESSION['AES_KEY'], 256);
    
    // If all was good,
    if( false !== $encoded )
    {
		// Create the signature (replacing special base-64 characters with safer alternates)
        $encoded = strtr($encoded, '+/=', '-_,');
        
        // The signature is a SHA-1 hash of the message, which is then encrypted with the client's RSA Private key.
        $signature = encryptRSA( sha1($encoded),
                                 makeKey( $_SESSION['RSA_SERVER_PRIVATE'], 
                                           $_SESSION['RSA_SERVER_MODULUS'] ) );       
        // prepare the message.
        $returnMsg = "<response><![CDATA[" . $encoded . "(" . $signature . ")]]></response>";
  
		// and return it.
        return $returnMsg;
    }
    
    // Return false if there's a problem.
    return false;
}

/**
 * Prints headers necessary for the proper transmission of the response: disables client caching, 
 * sets the content type, and prints the opening XML statement.
 * 
 * @param None
 * @return None
 */
function printHeaders()
{
	header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
    header("Expires: Mon, 26 Jul 1997 05:00:00 GMT"); // Date in the past
	header("Pragma: no-cache");    
    header("Content-type: text/xml");    
    print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");  
}

/**
 * Starts session handling, and checks for session fixation attack.
 * If throwError is passed as true, the method will return an error and exit
 * instead of regenerating the ID and setting the proper session variable.
 *
 * @param throwError - (optional) boolean. If passed, and set to true, throws an error instead of resetting the session.
 * @return None
 */
function startSession( $throwError = false )
{
    session_start();

    if (!isset($_SESSION['secureajaxsessioninitiated']))
    {
        session_regenerate_id();
        
        if( false == $throwError )
        {
            $_SESSION['secureajaxsessioninitiated'] = true;
        }
        else
        {
            print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");  
            print("<response>\n <error> Invalid session. </error>\n </response>\n");
            exit();
        }
    }
}

/**
 * Print a response to the client. This method encrypts and prints the response.
 *
 * @param - String. the message to print.
 * @return boolean - true if successful, false otherwise.
 */
function sendResponse( $message )
{
    $responseData = encryptResponse( $message );
    
    if( false !== $responseData )
    {            
        print( $responseData );
        return true;
    }
    
    return false;
}

/**
 * Generate a random character string of the passed in length. 
 * Uses /dev/urandom, CAPICOM.Utilities, and finally mt_rand to provide better random numbers.
 *
 * @param length - Int. The length of the random string to generate.
 * @return String - The randomly generated string.
 */
function generateKey( $length ) {
  $pr_bits = '';

    // Unix/Linux platform?
    $fp = @fopen('/dev/urandom','rb');
    if ($fp !== FALSE) {
        $pr_bits .= @fread($fp,$length);
        @fclose($fp);
    }

    // MS-Windows platform?
    if (@class_exists('COM')) {
        // http://msdn.microsoft.com/en-us/library/aa388176(VS.85).aspx
        try {
            $CAPI_Util = new COM('CAPICOM.Utilities.1');
            $pr_bits .= $CAPI_Util->GetRandom($length,0);

            // if we ask for binary data PHP munges it, so we
            // request base64 return value.  We squeeze out the
            // redundancy and useless ==CRLF by hashing...
            if ($pr_bits) { $pr_bits = md5($pr_bits,TRUE); }
        } catch (Exception $ex) {
            // echo 'Exception: ' . $ex->getMessage();
        }
    }
    
    // Make sure we're base64 encoded and then all lower case (to make sure everything's safe for output),
    // and make sure we're limited by the length...
    $pr_bits = strtolower(substr(base64_encode($pr_bits),$length));
    
    // Now, remove special characters that we cant' have ( + = / )
    $pr_bits = str_replace(array("/", "+", "="),"", $pr_bits);

    // If the resultant string is not long enough, then use mt_rand to get the rest.
    if (strlen($pr_bits) <$length) {
        $possible = "abcdefghijklmnopqrstuvwxyz0123456789";
        for($i=strlen($pr_bits); $i < $length; ++$i )
            $pr_bits .= substr($possible, mt_rand(0, strlen($possible)-1), 1);
    } 
    
    // Finally, return the string.
    return $pr_bits;
}

/**
 * Return the current time (in microseconds) as a floating point value
 * of seconds, and fractional microseconds.
 *
 * @param None
 * @return Float - The current time in seconds since epoch and fractional microseconds.
 */
function microtime_float()
{
    list($usec, $sec) = explode(" ", microtime());
    return ((float)$usec + (float)$sec);
}

?>
