<?php
/**
 * Secure Ajax Layer Copyright (c) 2008 - 2009 Brad Broerman. bbroerman@bbroerman.net
 *
 *   This process is the Diffie-Hellman key server API. It is called by SecureAjax when the client first
 * logs in, and every time the session key needs to be reset.
 *   In the initial transaction, a DH message was already generated and sent to the client with the initial
 * login process (encrypted with the initial code and RSA key pair). In this case we expect a post parameter
 * called "msg" with the response and a signature. We take the message, validate it's signature, and then generate
 * the shared secret.
 *   In the follow-up renegotiation message, the client will generate a whole new secret exponent, generator, and modulus
 * and send this process the initial message (with an RSA signature). In this case, the POST parameter will be 'newmsg'. 
 * Again, we validate the signature, generate our secret random exponent, and send the response back to the client (signed,
 * of course).
 */

// load in the library.    
require_once("/www/etc/secureAjaxConfig.php");
require_once( $secureAjaxConfig['INCDIR'] . "secureajax_helper.php");

// Start the user session.
startSession(true);
    
// and print out the HTTP response headers (cache control)
printHeaders();   

// Initial transaction: We get a message of the form "msg=" + returnMsg + "(" + signature + ")";
// the signature is a SHA-1 of the returnMsg and encoded by the server's public RSA key. We only
// send back a success / fail to the message.
if( isSet($_POST['msg']) && strlen($_POST['msg']) > 0 )
{
    // Make sure we find the parens that surround the signature.
    $idx = strpos( $_POST['msg'], "(" );
    $idx2 = strrpos( $_POST['msg'], ")" );
    
    // If we have a valid signature block,
    if( $idx > -1 && $idx2 > -1 && $idx < $idx2 )
    {
        // Separate the signature and the message from the incoming param.
        $signature = substr( $_POST['msg'], $idx + 1, $idx2 - $idx -1   );
        $message = substr( $_POST['msg'], 0, $idx );
        
        // Get the hash for the message
        $hash = sha1($message);
        
        // and the hash that the client sent to us in the signature
        $orig_hash = decryptRSA( $signature,
                                 makeKey( $_SESSION['RSA_SERVER_PRIVATE'], 
                                          $_SESSION['RSA_SERVER_MODULUS'] ) );        

		// If they match, then we haven't been tampered with. We can generate our shared secret...
        if( strcasecmp( $hash, $orig_hash ) == 0 )
        {
            $secretKey = calcDiffieHellmanSecret( $_SESSION['DH_GENERATOR'], 
                                                  $_SESSION['DH_PRIVATE_EXPONENT'],
                                                  $_SESSION['DH_MODULUS'], 
                                                  $message );
                                                  
            // If we calculated the shared secret correctly, store it's hash. This will be our AES key for the session.                                      
            if( false !== $secretKey )
            {                                      
                $_SESSION['AES_KEY'] = sha1( $secretKey );
            
				// tell the client we got it ok.
                print("<response>\n<success/>");
                print("\n</response>\n");				
            }
            else
            {
                print("<response>\n <error> Error generating response: Can not call getdhsec. </error>\n </response>\n");
            }
        }
        else
        {
            print("<response>\n <error> Signature does not match. </error>\n </response>\n");
        }  
    }
    else
    {
        print("<response>\n <error> Invalid message format. </error>\n </response>\n");
    }
}

//
// Now, if we got a 'newmsg' parameter... that means that we're re-negotiating the AES key. The client chose their random
// exponent, The generator and modulus are known and the same as before. We need to generate our own random exponent, and send 
// the combined G^exp % mod to the client...
//
else if( isSet($_POST['newmsg']) && strlen($_POST['newmsg']) > 0 )
{
    // Make sure we get the signature portion of the incoming request
    $idx = strpos( $_POST['msg'], "(" );
    $idx2 = strrpos( $_POST['msg'], ")" );
    
    // If we have a valid signature block,
    if( $idx > -1 && $idx2 > -1 && $idx < $idx2 )
    {
        // Extract the signature and the message portions from the incoming parameter.
        $signature = substr( $_POST['msg'], $idx + 1, $idx2 - $idx -1   );
        $message = substr( $_POST['msg'], 0, $idx );
        
        // Get our calculation of the hash of the message
        $hash = sha1($message);
        
        // Decrypt the client's version of the hash from the signature
        $orig_hash = decryptRSA( $signature,
                                 makeKey( $_SESSION['RSA_SERVER_PRIVATE'], 
                                          $_SESSION['RSA_SERVER_MODULUS'] ) );        

		// If they match, then the message hasn't been tampered with, and we can continue.
        if( strcasecmp( $hash, $orig_hash ) == 0 )
        {
            // Generate our own random exponent, and store it.
            $tmpNewKey = genDiffieHellmanMsg( );
            $_SESSION['DH_PRIVATE_EXPONENT'] = $tmpNewKey['exp'];
        
			// Generate the return message ( G^exp % mod ) to send back to the client.
            $returnMessage= calcDiffieHellmanSecret( $_SESSION['DH_GENERATOR'], 
                                                     $_SESSION['DH_PRIVATE_EXPONENT'],
                                                     $_SESSION['DH_MODULUS'] );

			// and calculate the shared secret that we'll use for AES going forward (until the next re-negotiation)
            $secretKey= calcDiffieHellmanSecret( $_SESSION['DH_GENERATOR'], 
                                                 $_SESSION['DH_PRIVATE_EXPONENT'],
                                                 $_SESSION['DH_MODULUS'], 
                                                 $message );

			// If all went well, store the new secret key,  and send the response back to the client...
            if( false !== $secretKey && false !== $returnMessage )
            {                                      
                $_SESSION['AES_KEY'] = sha1( $secretKey );
            
                print("<response>\n<![CDATA[" . $returnMessage . "]]/>\n</response>\n");				
            }
            else
            {
                print("<response>\n <error> Error generating response: Can not call getdhsec. </error>\n </response>\n");
            }
        }
        else
        {
            print("<response>\n <error> Signature does not match. </error>\n </response>\n");
        }  
    }
    else
    {
        print("<response>\n <error> Invalid message format. </error>\n </response>\n");
    }
}
else
{
    print("<response>\n <error> Invalid message. </error>\n </response>\n");
}

?>