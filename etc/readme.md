etc
===

  This directory contains helper scripts and files that should be outside the document root of your server. 
These include the configuration files, the optional pre-generated RSA Key list, code files for AES, RSA, Diffie-Hellman,Arbitrary Precision Math, and other utilities used for the application. 
Each of these are fully commented and fairly easy to understand.

<b>List of files</b>
<ul>
  <li>secureAjaxConfig.php – Contains service level configuration information, such as where binaries for the C versions are kept, locations of helper files, and functions that are called by the login service to retrieve user names, passwords, challenge images, and challenge text. This is the primary place where you would configure / modify the configuration.</li>
  <li>Secureajax_helper.php – Includes internal methods used to encode / decode messages and to validate them. Also contains includes that define whether to use pure PHP code, PHP/GMP code, or compiled C code when performing operations; Other than these top level includes, this file should not need to be modified.</li>
  <li>makeRSAkeys.php – a command line PHP script used to pre-generate RSA keys (kept in rsakeys.php) to be used when using the pure PHP implementations of the cryptography primitives. (The Pure PHP version of the key generator is too slow to be used in production)</li>
  <li>rsa-.php – The RSA primitives. This includes a pure PHP version, a PHP version that uses the Gnu Multi-Precision Math plug-in, and a PHP version that calls external compiled C applications for RSA primitives.</li>
  <li>Diffie-hellman.php – The Diffie Hellman Key exchange primitives. This includes a pure PHP version, a PHP version that uses the Gnu Multi-Precision Math plug-in, and a PHP version that calls external compiled C applications</li>
  <li>Aes-php.php – The AES encryption primitives. Since this is more than fast enough in PHP, there was no need to generate GMP or C versions.</li>
  <li>BigInt.php – A multi-precision math library written entirely in PHP for the RSA-php.php and Diffie-hellman-php.php files.</li>
  <li>Class.JavaScriptPacker.php – An open source library used to to the compacting of the delivered javascript. This reduces the size of the delivered script, and increases the complexity of reverse engineering it. In addition, the GIT repository includes the C source code for the C applications that may be used for the primitives, as well as the original versions of open source JavaScript libraries used to create SecureAjax. It also includes a non-compacted version of the main Secure Ajax JS script for your viewing. To configure SecureAjax, simply </li>
</ul>
