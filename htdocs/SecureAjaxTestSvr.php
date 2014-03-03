<?php
session_start();

header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT"); // Date in the past
header("Pragma: no-cache");

require_once("/www/etc/secureAjaxConfig.php");
require_once( $secureAjaxConfig['INCDIR'] . "secureajax_helper.php");

header("Content-type: text/xml");
print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");

$message = getMessage();

// action=getImg
if( false !== $message  && strpos( $message, "action=getImg" ) > -1 ) {
  $filename = "test.jpg";
  $fh = fopen( "/www/secure_docs/images/" . $filename, "rb" );
  $contents = "";

  while( !feof( $fh ) ) {
    $contents .= fread( $fh, 8192 );
  }

  fclose( $fh );

  $newMessage = "<response mimetype='image/jpeg'><![CDATA[" . base64_encode( $contents ) . "]]></response>\n";

  $responseData = encryptResponse( $newMessage );

  print( $responseData );
} elseif( false !== $message ) {
  $newMessage = "<response> <![CDATA[" . $message . "]]></response>\n";

  $responseData = encryptResponse( $newMessage );

  print( $responseData );
} else {
  print("<response>\n <error> Invalid message. Bad Signature </error>\n </response>\n");
}

?>
