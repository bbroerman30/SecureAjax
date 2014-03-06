htdocs
======
This directory contains the main webservices used for SecureAjax:
<ul>   
 <li>dhkeyserver.php – The Diffie-Hellman Key exchange service, used to negotiate AES session keys. </li>
 <li>secureAjaxLogin.js.php – The login server called by the javascript when the user tries to log in.</li>
 <li>secureajax.js.php - the javascript generator. This is the 1st level bootloader script.</li>
 <li>SecureAjaxAPIs.php – Contains several internal Secure Ajax helper APIs.</li>
</ul>

The other files are a demo process for testing your configuration:
<ul>
 <li> index.html - Main entry page. Performs a login, and on successful login shows the test form </li>
 <li> SecureAjaxTestSvr.php - Example simple webservice showing how to receive, translate, and respond to requests </li>
 <li> loading.gif - Simple throbber gif. </li>
</ul>
 
The test app also loads pages from the secure_docs directory. Specifically, a JavaScript, an image, and a web page.
