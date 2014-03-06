<?php

/**
 * Global configuration variables used everywhere else in the libaray. These point to special places (hopefully outside the doc root) 
 * where the library will find the files that it is looking for.
 */
 
// This is where to expect all include files (configuration and helper files)
$secureAjaxConfig['INCDIR'] = "/www/etc/";

// Where to find the binaries (if using the compiled AES, Sha-1, RSA programs)
$secureAjaxConfig['BINDIR'] = "/www/etc/";

// Where to look for scripts that are to be loaded securely by insertScript or execScript SecureAjax calls.
$secureAjaxConfig['SCRIPTDIR'] = "/www/secure_docs/";

// Where to look for documents (HTML, Images, and CSS) that are loaded by loadImage, loadPage, etc. SecureAjax calls.
$secureAjaxConfig['DOCDIR'] = "/www/secure_docs/";

// The base URL for the API calls (this is made part of the secureajax.js that is sent to the client.
$secureAjaxConfig['APIBASEURL'] = "http://archdev.localhost.com/";

/**
 * Used by SecureAjaxLogin process to retrieve the plain-text password. Note that this password is used by SecureAjax to 
 * prepare the login. This password is NEVER sent out over the wire. In production applications, you should store this 
 * in a database in an encrypted format (AES-256 or better. You could have a static portion of a key in code, and a per-password 
 * salt stored in the Database. Query the password/salt by userid, combine the salt with the static hard-coded key and
 * decrypt)
 *
 * @param username - String. The user's login name.
 * @return String - the user's plain text password.
 */
function getUserPassword( $username ) {

  // Stub for login password...
  if( $username == 'bbroerman' ) {
    return 'pass123';
  }
  
  return false;
}

/**
 * In the existing login popup, the dialog box is shown with a challenge text and a challenge image. These are used to
 * validate this server in the mind of the user. They should be prepared beforehand by the user through another channel
 * ( i.e. in person, over the phone, etc. ) and then stored in the database in an encrypted format. This includes a dummy
 * value to display when the login name isn't recognized, in an attempt to misdirect attackers. There should be a random
 * pool of challange texts chosen at random in that case.  
 *
 * @param username - String. The user's login name
 * @return String - The challenge text to display in the login dialog, next to the challenge image.
 */
function getUserChallengeText( $username ) {

  // Stub for challenge text. 
  $userChallengeMessage = "All warfare is based on deception. Hence, when we are able to attack, we must seem unable;";
  if( $username == 'bbroerman' ) {
    $userChallengeMessage = "This is my challenge text. There are many like it but this one is mine.";
  }

  return $userChallengeMessage;
}

/**
 * In the existing login popup, a challenge image is displayed. The image is in base-64 encoded format (recognizable by
 * the browser as a data url encoded image) The image, and the challenge text are used to validate this server in the mind 
 * of the user. They should be prepared beforehand by the user through another channel ( i.e. in person, over the phone, etc. )
 * and then stored in the database in an encrypted format. This includes a dummy value to display when the login name isn't 
 * recognized, in an attempt to misdirect attackers. There should be a random pool of challange images chosen at random in that case.  
 *
 */
function getUserChallengeImage( $username ) {

  // Stub for challenge image selection
  $userChallengeImage ="data:image/jpeg;base64,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";
  if( $username == 'bbroerman' ) {
    $userChallengeImage ="data:image/jpeg;base64,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";
  }

  return $userChallengeImage;
}

?>
