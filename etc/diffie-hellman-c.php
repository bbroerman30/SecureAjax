<?php
/**
 *  Secure Ajax Layer Copyright (C) 2008 - 2009 Brad Broerman,  bbroerman@bbroerman.net
 *  Utility functions used to prepare and process Diffie-Hellman Key Agreement messages.
 *
 *  Implemented in C processes and called from PHP.
 */
 
// The directories that the binaries 'gendhkeys' and 'getdhsec' are located in.
$binDir = "/www/sites/bbroerman.net/etc/";

/**
 * Generate the initial message to be sent to the client for a Diffie Hellman exchange. 
 * This method calls an external C process to generate and return the Generator, Exponent, Modulus, and 
 * the initial term for a Diffie Hellman exchange. It stores the results in a hash to be returned.
 * The message is what is sent to the client, and the rest is stored locally. (The exponent is kept secret)
 * the return message is sent to the calcDiffieHellmanSecret() method to generate the shared secret.
 * 
 * @param keylen - (Ignored for the C process) The length of the key to generate (in bits).
 * @return Mixed - A hash containing the generator, exponent, modulus, initial calculated term,and message for a Diffie Hellman exchange, or boolean false on error.
 */
function genDiffieHellmanMsg( $keylen )
{
    global $binDir;

	$message = runExternalProcess( $binDir.'gendhkeys', 128, "");
	
    if( $message !== false && strlen($message) > 0 )
    {
        $returnvals = explode("|", $message);
        $dhKeys = array();
        
        $dhKeys['gen'] = $returnvals[0];
        $dhKeys['exp'] = $returnvals[1];
        $dhKeys['mod'] = $returnvals[2];
        $dhKeys['calc'] = $returnvals[3];
        $dhKey['message'] = $dhKeys['gen'] . "|" . $dhKeys['mod'] . "|" . $dhKeys['calc'] ;
        return $dhKeys;
    }
    
    return false;
}

/**
 * Calculate the shared secret based on an input generator (or message), random exponent, and modulus.
 * This method calls an external C process to take the parameters passed in and generate the shared secret
 * to be used in a symmertric encryption. If a message is passed from the client, the method generates the 
 * shared secret, else the method will use the generator to create a message value to be sent to the client.
 * Note, message will be used when the client initiates the key agreement transaction.
 *
 * @param generator - String (Hexidecimal) Generator. Usually 3, 5, or other small prime. Chosen in genDiffieHellmanMsg() method.
 * @param exponent - String (Hexidecimal) Randomly generated secret number.
 * @param modulus - String (Hexidecimal) Prime number calculated by genDiffieHellmanMsg()
 * @param message - (optional) String (Hexidecimal) Message returned from the client.
 */
function calcDiffieHellmanSecret( $generator, $exponent, $modulus, $message = null)
{
    global $binDir;
    
    if( $message == null || !isSet($message) )
    {
        $message = "";
    }
    
    $stdin = $generator . "|" . $exponent  . "|" . $modulus . "|" . $message;

	$message = runExternalProcess( $binDir.'getdhsec', "", $stdin);
	
	// Make sure result is padded to byte size.
	if( strlen( $message ) % 2 == 1 )
	{
	    $message = "0" . $message;
	}
	
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
    global $binDir;
	
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