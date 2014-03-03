Secure Ajax Layer 
=================

  For a very long time now, internet transactions that require secure channels have relied on SSL and TLS implemented in the web browser and in the web server. These technologies rely on trusted third parties to provide and authenticate certificates which are used to validate the identity of the server that a given client is connecting to. For years now, these trusted parties have taken short cuts that have undermined the security of the internet, and have allowed numerous attackers to generate certificates that mimic valid sites and allow unsuspecting customers to be spied upon. TLS and SSL negotiation protocols have also been attacked with various success as well. Additionally, browsers have been attacked time and time again, most notably Internet Explorer, still used by over 50% of internet users, which employs a plug-in to provide secure communications. This plug-in can be replaced with a compromised version by viruses or other malware. Additionally other browsers, though much more secure, may also become infected with viruses and malware that could allow prying eyes to see private communications or allow attackers to gain access to ecommerce, banking, or other services that the users would think are secure. Finally, obtaining certificates are very expensive for small website developers.

  To help solve these problems, I have developed SecureAjax. This is a library that is loaded from a server in a secure manner, sits on top of all client-side installed code (browser, plugins, or operating system) to provide another layer of security. This library is cheaper than an SSL certificate, and provides real secure communications for web applications.

Point By Point
==============
<UL>
 <LI>	Does not rely on 3rd Party registrars.
 <LI>	No expensive certificates needed.
 <LI>	Provides encryption and authentication in the same atomic operation.
 <LI>	Encryption is done at the application level, before entering the browser, plug-ins, or the operating system, bypassing insecurities in these layers.
 <LI>	Not affected by known and exploitable hacks and breaks in TLS and SSL security.
 <LI>	Not affected by known and exploitable hacks and breaks in MS Internet Explorer XMLHttpRequest object vulnerabilities.
 <LI>	Cheap and effective.
</UL>

What it does
============
  The Secure Ajax Library provides an encrypted channel for your web application to use when talking to your server that is outside the web browser itself, at the level of the application. This protects your confidential communications from problems with the underlying browser, and problems with the communications channel. It also makes it possible to have mixed mode applications, where your web site is not secure, but certain portions of it, such as administration, are. It also provides extra security for your web services and servers, by allowing only properly authenticated and encrypted requests to reach your APIs.

  The Secure Ajax Library can be used to send secure communications between your client application and your web application servers, and can be used to dynamically load HTML pages, JavaScripts, and Stylesheets securely. On browsers that support Data URLs, that is all but Internet Explorer 7 and earlier, it can even be used to load images. All securely, and without the need of HTTPS, SSL, or TLS.
	
  In recent months, it has become increasingly known that the underlying functionality of the web browser that enables modern dynamic web sites can be tampered with. Some browsers implement this object outside the browser itself as a separate plug-in while some make it part of the browser itself. In those that keep it separate, it is possible for an attacker to replace this object with a malicious one using a virus or poisoned download. Those that have it internally can also be compromised, and in some instances the compromised object can persist from one web page to another. It has also been made known that the underlying security mechanisms of the secure web, HTTPS and SSL, are not as secure as most people believed. Numerous attacks against HTTPS and SSL have been demonstrated. Many of these are fundamental problems with the browsers, and some are because of inherent problems with the design of the SSL/HTTPS protocol itself. SSL certificates, necessary to provide a secure web server, are also expensive to obtain and maintain. Additionally, there are known attacks where a hacker may obtain a fraudulent certificate that can mimic your web site, with the user unaware of the deception.  Secure Ajax Layer can be used as an alternative to HTTPS and SSL encryption for your web applications, or may be used in concert with HTTPS to provide additional protection for your applications. 

Why did I make this?
=================
<UL>
 <LI>	HTTPS servers can be costly, and not all hosting providers can give it to you. 
 <LI>	Properly generated and authenticated certificates are very costly and must be renewed regularly. 
 <LI>	Most web applications cannot make use of secure and non-secure communications modes on the same page, breaking  the seamless experience of AJAX.
 <LI>	HTTPS and SSL have been under increasing attack, and there have been reports of many successful attacks! 
 <LI>	Your browser's XMLHTTPRequestObject, the object that enables AJAX, can be compromised outside of your web application, and can funnel data to other destinations EVEN IF YOU USE SSL AND HTTPS.
 <LI>	HTTPS and SSL only authenticate the server to the client, not the client to the server. This library authenticates both at the same time. 
</UL>

Features:
=================
<UL>
 <LI>	Uses AES-256 for communications, with 128 bit RSA signatures. 
 <LI>	Encryption keys are randomly generated per session, and can be renegotiated as needed. 
 <LI>	Distribution of encryption keys and code is performed with a process that is immune to man-in-the-middle attacks.  
 <LI>	Shared secrets DO NOT pass through the communications channel. 
 <LI>	Does NOT use SSL or third party certificates, but may be used on top of SSL/HTTPS for added security.
 <LI>	Written entirely in PHP on the server and JavaScript on the client. 
 <LI>	Provides authentication of the user. 
 <LI>	Secures your transaction data. 
 <LI>	Secures your application server from prying. 
 <LI>	Secures your client from man-in-the-middle attacks on JavaScript code loading. 
 <LI>	Cheap, effective, and simple to use!
</UL>

Libraries Used 
===============
In the making of this project, I used several JavaScript and C open-source libraries and application examples.
The original copyright notices have been kept in the C source, or in the Javascript files in the js_src directory
<ul>
 <li>AES implementation in JavaScript (c) Chris Veness 2005-2008 
 <li>BarrettMu, a class for performing Barrett modular reduction computations in JavaScript. Copyright 2004-2005 David Shapiro
 <li>BigInt, a suite of routines for performing multiple-precision arithmetic in JavaScript. Copyright 2004-2005 David Shapiro
 <li>Clearlooks 2 CSS for popup dialog Copyright © 2004-2008, Moxiecode Systems AB, All rights reserved.
 <li>RSA, a suite of routines for performing RSA public-key computations in JavaScript. Copyright 1998-2005 David Shapiro
 <li>JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined in FIPS PUB 180-1. Version 2.1a Copyright Paul Johnston 2000 - 2002. Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
</ul>

How it Works 
=================
  The Secure Ajax Library is comprised of 4 PHP webservices, a PHP library, and a PHP server template that can be used as the model for your secure webservices. These scripts together implement the Secure Ajax Layer protocol. 
  
  The 4 webservices are the login script bootloader, the SecureAjax code server, the key server, and an API service for loading pages, scripts, stylesheets, and images securely.
  
  The Web Application begins by calling a PHP webservice to request the SecureAjax login bootloader. This service generates a randomly obfuscated and compressed JavaScript that starts the login process. Each time it is delivered to a client, each method and variable name is randomly renamed to a 4 – 6 character string, and each method is randomly reordered within the javaScript class. Included within this class are several strings (placed in a random order) that are pieced together to form the 1st level of a symmetric encryption key.  This key is then used on login to load the second portion of the bootloader. When a user logs in to begin a secure session, this javascript (once unpacked) calls the Secure Ajax Layer login webservice, to begin the secure communications session. The script sends the user name, and the webservice responds with all javascript and html necessary to display a login box and proceed with login, encrypted with the 1st symmetric encryption key above (with id and classes randomly named, and the entire package randomly placed within the pages DOM). The login box includes a user selected challenge string and optional image (set up through separate channels) as an additional validation. 
  
  Once the user enters his password into the box, the SecureAjax Login webservice is called, using only the user name. The webservice generates a random 128 bit RSA key pair, and a portion of a random AES key (using Diffie-Hellman type negiotiation). It then takes this information, along with the JavaScript code for the AJAX communications layer itself, packages it all up, compresses and randomizes the code (as in the initial bootloader), and then encrypts it using a salted hash of the users password, and sends the encrypted package to the client. The size of the salt is programmatically determined based on the size and content of the user’s password. The client, using the JavaScript object decrypted and instantiated in the login box by the original bootloader, decrypts this package using its own copy of the salted password, a secret known only to the server and the user. This provides the dual role of validating and authenticating the user, and decrypting the actual SecureAjax JavaScript code. Once unpackaged, the Secure Communications object is created, overwriting a known top-level browser window object and initializes. 
  
  Once everything is validated, the Secure Communications object negotiates with the key server webservice for the sessions AES encryption key using the RSA keys and the partial key sent with the initial transaction for validation (Diffie-Hellman negotiation with RSA signatures). If authentication and validation are all successful, it then begins secure communication. At various times through the users session, this webservice may be called again to generate a new AES encryption key. The frequency of this is entirely determined by the application.
  
  The Secure Ajax Layer can transmit XML, JSON, JavaScript, style sheets, images, HTML pages, and plain text back and forth between the client and the server. Only encrypted and signed messages are read and interpreted by the server, ensuring that nobody can call your APIs without being authenticated and authorized by the Secure Ajax Layer. Additionally, only properly encrypted and signed messages are interpreted by the client, protecting your client from scripts or data being modified in transit.

What are in the directories
===========================

  When downloaded, the following directories will be present: c_src, js_src, etc, htdocs, and secure_docs.  
  The c_src directory contains the source for the C applications that may be used for AES, RSA, and Diffie-Hellman routines. These are useful if you have a slow server, or can not install the GMP plug-in on your server. These files can be compiled with your standard C++ compiler, but you will need the GNU GMP library to link them.  
  
  The js_src directory contains the non-compressed original versions of the various JavaScript used in SecureAjax. Some of these are open source libraries that are used in the project, and are included here with their original headers and licence blocks. They are expanded out and commented sufficiently for you to read through and understand the code. Also included are expanded and commented versions of the SecureAjax login script, and the SecureAjax communications script.
  
  The etc directory contains helper scripts and files that should be outside the document root of your server. These include the configuration files, the optional pre-generated RSA Key list, code files for AES, RSA, Diffie-Hellman, Arbitrary Precision Math, and other utilities used for the application. Each of these are fully commented and fairly easy to understand.
  
  The htdocs directory contains the files that belong in the document root: The webservices, the Secure Ajax login service, Diffie Hellman key server, etc. These should be placed in your document root.
  
  The secure_docs directory is a default location (but it is configurable and can be moved) for secure scripts, pages, images, stylesheets, etc. that will be loaded and served up by the SecureAjax webservices.

Installation
============
The Secure Ajax Layer currently consists of 4 PHP files that go into your server’s document root (usually htdocs, http, etc.).  These files are 
<UL>
 <LI>	dhkeyserver.php – The Diffie-Hellman Key exchange service, used to negotiate AES session keys.
 <LI>	secureAjaxLogin.js.php – The login server called by the javascript when the user tries to log in.
 <LI>	secureajax.js.php - the javascript generator. This is the 1st level bootloader script.
 <LI>	SecureAjaxAPIs.php – Contains several internal Secure Ajax helper APIs. 
</UL>

These are the core of the SecureAjax system.  

Additionally, there are a set of files (contained in the etc directory) that are placed outside your servers document root that contain helper functions, and configuration information.
<UL>
 <LI>	secureAjaxConfig.php – Contains service level configuration information, such as where binaries for the C versions are kept, locations of helper files, and functions that are called by the login service to retrieve user names, passwords, challenge images, and challenge text. This is the primary place where you would configure / modify the configuration.
 <LI>	Secureajax_helper.php – Includes internal methods used to encode / decode messages and to validate them. Also contains includes that define whether to use pure PHP code, PHP/GMP code, or compiled C code when performing operations; Other than these top level includes, this file should not need to be modified.
 <LI>	makeRSAkeys.php – a command line PHP script used to pre-generate RSA keys (kept in rsakeys.php) to be used when using the pure PHP implementations of the cryptography primitives. (The Pure PHP version of the key generator is too slow to be used in production) 
 <LI>	rsa-<x>.php – The RSA primitives. This includes a pure PHP version, a PHP version that uses the Gnu Multi-Precision Math plug-in, and a PHP version that calls external compiled C applications for RSA primitives.
 <LI>	Diffie-hellman-<x>.php – The Diffie Hellman Key exchange primitives. This includes a pure PHP version, a PHP version that uses the Gnu Multi-Precision Math plug-in, and a PHP version that calls external compiled C applications
 <LI>	Aes-php.php – The AES encryption primitives. Since this is more than fast enough in PHP, there was no need to generate GMP or C versions. 
 <LI>	BigInt.php – A multi-precision math library written entirely in PHP for the RSA-php.php and Diffie-hellman-php.php files.
 <LI>	Class.JavaScriptPacker.php – An open source library used to to the compacting of the delivered javascript. This reduces the size of the delivered script, and increases the complexity of reverse engineering it.
In addition, the GIT repository includes the C source code for the C applications that may be used for the primitives, as well as the original versions of open source JavaScript libraries used to create SecureAjax. It also includes a non-compacted version of the main Secure Ajax JS script for your viewing. 
To configure SecureAjax, simply 
 <LI>	Copy the 4 scripts into your servers document root.
 <LI>	Copy the files from /etc into an area of your server outside your document root.
 <LI>	Update the 1st 4 files to point to the correct location of secureAjaxConfig.php and secureajax_helper.php
 <LI>	Update the secureAjaxConfig.php to point to the correct locations for the binary directory, include directory, secure scripts directory, secure documents directory, and the base URL for your API server.
 <LI>	Implement the methods getUserPassword(),getUserChallengeText(), and getUserChallengeImage() located in secureAjaxConfig.php
 <LI>	Optionally, modify the includes in secureajax_helper.php to use either the pure PHP, PHP/GMP, or C versions of the encryption primitives.
 <LI>	Optionally, if using the C versions of encryption primitives, compile the C sources files, and place them in the configured binary directory.
</UL>

Optionally, if you are using the pure PHP implementation on your server (that is, you can not install the GMP plug-in library, and you can not use the C applications for RSA, and Diffie Hellman) you should consider pre-generating your RSA keys. There is a file in the etc directory called makeRSAkeys.php. You should use this on your development box, or on the command line of your server, to pre-generate your RSA keys. This script may be configured to use a GMP based version of the key generator, the C version, or a pure PHP version. If using windows, you should download and configure WampServer (a PHP server for windows) or configure a linux virtual box. Either way, once configured, you call the makeRSAkeys.php with the number of key entries to be generated as a command line argument. It will output a PHP script to STDOUT.  You can run it in this configuration for testing, and once satisfied, you can redirect the output to rsakeys.php (the default file for pre-generated RSA keys). Please make sure to generate a LARGE array (lots of keys). The more keys you have, the more secure your application and the less often you will need to regenerate the file. If using pre-generated keys, this file should be regenerated periodically.

SecureAjax comes with a test application. To use this application, update the script include in index.html in the htdocs directory to point to your server name:
<PRE>
&LT;script type='text/javascript' src='http://archdev.localhost.com/secureAjaxLogin.js.php'&GT; &LT;/script&GT;
</PRE>
You will also need to update the require_once in the SecureAjaxTestSvr.php script to point to the proper location for secureAjaxConfig.php.

Writing your own APIs 
=====================
Constructing APIs in SecureAjax is very simple. The JavaScript library makes no assumptions about the contents of a message. It can be JSON, XML, Text or any other format. The message is sent to the server by calling window.secureAjax.sendSecureMessage() and passing a string message ( either XML string, or JSON formatted string ) and a callback function. On the server side, call either the helper function getMessage() to retrieve the string send by the client, or you can do it yourself with:
<PRE>
if( isSet($_POST['msg']) && strlen($_POST['msg']) > 0 )    {
    $decoded = decryptMessage( $_POST['msg'] );
    return $decoded;
}
return false;
</PRE>

Sending the response back to the client is fairly simple as well. You can either use the helper method sendResponse() or you can do it yourself with:
<PRE>
$responseData = encryptResponse( $message );
if( false !== $responseData ) {
    print( $responseData );
    return true;
}
return false;
</PRE>

The helper functions are defined in secureajax_helper.php and can be renamed to anything that meets your needs.

Public Javascript Methods:
==========================

  The SecureAjax javascript object provides several public methods that may be used to re-negotiate session keys, log out, send and receive messages, load images, pages and scripts securely, and more. The initial login script is loaded at window.top.secureAjaxLogin, and contains one public method: loginEx( x, y, login, callback ).  X and Y define the location for the popup password dialog, login is the user name, and callback is a function to be executed when login is completed. The callback will be passed either Boolean true or false depending on the success of the login. Upon successful login, the API will be accessed through the object window.secureAjax

The public methods are:
<UL>
 <LI>	getNewSecureKey() – Re-negotiate the session key. Makes a call to dhkeyserver.php. Returns when the new key has successfully been negotiated.
 <LI>	isReady() – Returns true if the object is ready to communicate (code is all loaded and the session key has been retrieved).
 <LI>	setReadyCallback( func ) – Sets a callback that is called when the system is ready. Used instead of polling isReady. 
 <LI>	sendSecureMessage( serviceUrl, parms, callback) – Send a secure message to the named service. The callback is called with the response message if successful (or false if there was an error).
 <LI>	insertScript( scrptname, divid, id, required ) – Load a JavaScript and insert it inside the specified element (divid). If id is set, and required is set to true, the script will wait in a queue until the script with the divid of id has been loaded before loading itself. This can be used to ensure pre-requisite scripts to be loaded first. The script is loaded from the secure documents directory defined in secureAjaxConfig.php
 <LI>	execScript ( scrptname ) – Load and immediately execute the named script. The script is loaded from the secure documents directory defined in secureAjaxConfig.php
 <LI>	loadStylesheet( scrptname ) – Load the named stylesheet, and append to the end of the <head>. Images defined in the stylesheet can not yet be loaded securely, though.  The script is loaded from the secure documents directory defined in secureAjaxConfig.php
 <LI>	loadImage( imgname, target ) – Load the named image file, and insert as a DATA URL at the specified target object. The script is loaded from the secure documents directory defined in secureAjaxConfig.php
 <LI>	loadPage( pagename ) – Securely load a page (and it’s scripts and stylesheets if tagged.). This replaces the current page. SecureAjax session is re-loaded and re-negotiated on each load. To tag a script or style sheet as being loaded securely, use “secure:\\” as the protocol in the URL. For scripts, if you want to ensure a specific load order, add the attribute required='<prereq id>'. Currently, images are not loaded securely with this message (work in progress). See the example page. The script is loaded from the secure documents directory defined in secureAjaxConfig.php
<UL>

The use of loadPage, loadImage, loadStylesheet, execScript, and insertScript require the secureAjaxAPIs.php to be present.

Example Usage
=============

Example JavaScript API call (With XML response):
<PRE>
window.secureAjax.sendSecureMessage( "/SecureAjaxTestSvr.php", 
  "input=" + text, 
  function( doc ) {
    if(doc) {
      var resp = doc.getElementsByTagName("response")[0];
      document.getElementById('form').echo.value = getTextNode(resp);
    }
  } );
</PRE>

Example page with login:
<PRE>
&LT;PRE&GT;
&LT;html&GT;
  &LT;head&GT;
    &LT;title&GT; Secure Ajax Communications Test &LT;/title&GT;
    &LT;script type='text/javascript' src='http://archdev.localhost.com/secureAjaxLogin.js.php'&GT;&LT;/script&GT;
    &LT;script type='text/javascript'&GT;
function doLogin() {
   	  var username = document.getElementById('loginform').username.value;        
        showWaitCursor();
        window.secureAjaxLogin.loginEx(100,100,username,function(success) {
    hideWaitCursor();
          if( false == success ) {
            alert("Invalid Login.");
            return;
          }
          window.secureAjax.loadPage("Admin_files/securepage.html");
        }
      };
    &LT;/script&GT;
  &LT;/head>
  &LT;body>
    &LT;form id='loginform' method='#' type='post' onSubmit='doLogin(); return false;'>
      &LT;h4> Please Log In &LT;/h4>
      &LT;table&GT;
        &LT;tr&GT;&LT;td&GT;&LT;b&GT; Username &LT;/b&GT;&LT;/td&GT;&LT;td&GT;&LT;input type='text' name='username'&GT;&LT;/td&GT;&LT;/tr&GT;      
        &LT;tr&GT;&LT;td colspan=2 align='top'&GT;&LT;input type='submit' name='Login' value='Login' onClick='doLogin(); return false;'&GT;&LT;/td&GT;&LT;/tr&GT;
      &LT;/table&GT;
    &LT;/form&GT;
  &LT;/body&GT;
&LT;/html&GT;  
&LT;/PRE&GT;
</PRE>
Example secure page (with loadable scripts/stylesheet):
<PRE>
&LT;PRE&GT;
&LT;html&GT;
  &LT;head&GT;
    &LT;!-- This loads first, from &LT;secure docs&GT;/Admin_files/xaramenu.js --&GT;
    &LT;script id='xaramenu' type='text/javascript' src='secure://Admin_files/xaramenu.js'&GT;&LT;/script&GT;
    &LT;!-- This loads next, from docs&GT;/Admin_files/admin.css --&GT;
    &LT;link rel='stylesheet' href='secure://Admin_files/admin.css'/&GT;
  &LT;/head&GT;
  &LT;body onLoad='alert("doc onload");'&GT;

    &LT;div&GT;  Main body content here &LT;/div&GT; 


    &LT;div id='menutgt'&GT;
      &LT;!-- This loads after xaramenu above is all loaded --&GT;
      &LT;script id='admin_navbar' required='xaramenu' type='text/javascript' src='secure://Admin_files/admin_hnavbar.js'&GT;&LT;/script&GT;                            
    &LT;/div&GT;	
  &LT;/body&GT;
&LT;/html&GT;
</PRE>
