<?php
    //
    // Secure Ajax Layer Copyright (c) 2008 - 2009 Brad Broerman. bbroerman@bbroerman.net
    // BigInt library Copyright 1998-2005 David Shapiro. dave@ohdave.com
    // RSA Javascript library Copyright 1998-2005 David Shapiro. dave@ohdave.com
    // SHA-1 Javascript library Copyright Paul Johnston 2000 - 2002. 
    //     Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet 
    //     Distributed under the BSD License See http://pajhome.org.uk/crypt/md5 for details. */
    // AES Javascript library Copyright Chris Veness 2005-2008. Right of free use is granted for all.
    // 
    // This library is free software; you can redistribute it and/or
    // modify it under the terms of the GNU Lesser General Public
    // License as published by the Free Software Foundation.
    // 
    // This library is distributed in the hope that it will be useful,
    // but WITHOUT ANY WARRANTY; without even the implied warranty of
    // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    // Lesser General Public License for more details. 
    // 
    // You should have received a copy of the GNU Lesser General Public
    // License along with this library; if not, write to the Free Software
    // Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
    //
   
    // load in the library.    
    require_once("/www/etc/secureAjaxConfig.php");
    require_once( $secureAjaxConfig['INCDIR'] . "secureajax_helper.php");

    // Start the user session.
    startSession();
    
    // and print out the HTTP response headers (cache control)
    printHeaders();   
    
    // Get and decode the message, and validate it.
    $message = getMessage();
    $response = "<error> Invalid Function call </error>";
    if( false !== $message )
    {
        $xml = null;
		
		    try 
		    {
		        $filename = false;
            $xml = new SimpleXMLElement( $message, LIBXML_NOCDATA  );
        	
			      $response = "<error> Invalid Function call ". $xml->getName() ."</error>";
			
            // Check the main element type. It should be either loadPage or loadScript.
            if( $xml->getName() == "loadScript" )
            {
			          $response = "<error> error getting script ". $xml->getName() ."</error>";

                if( isSet( $xml['name'] ) ) 
                {           
                    $filename = $secureAjaxConfig['SCRIPTDIR'].$xml['name'] ;

					          $newMessage = loadFile( $filename );
                
					          if( $newMessage !== false )
					          {
						            $response = "<script type='text/javascript'><![CDATA[".$newMessage."]]></script>";
					          }
                }
            }
            elseif( $xml->getName() == "loadStyle" )
            {
			          $response = "<error> error getting CSS Style sheet ". $xml['name'] ."</error>";

                if( isSet( $xml['name'] ) ) 
                {           
                    $filename = $secureAjaxConfig['SCRIPTDIR'].$xml['name'] ;

					          $newMessage = loadFile( $filename );
                
					          if( $newMessage !== false )
					          {
						            $response = "<script type='text/css'><![CDATA[".$newMessage."]]></script>";
					          }
                }
            }
            elseif( $xml->getName() == "loadPage" )
            {
			    $response = "<error> error processing file ". $xml['name'] ."</error>";
			
                if( isSet( $xml['name'] ) ) 
                {           
                    $filename = $secureAjaxConfig['DOCDIR'] . $xml['name'];

			        $filecontents = loadFile( $filename );
					
			        if( $filecontents !== false )
                    {
                        $header = "";
                        $body = "";
                        
                        // Separate out the head and body sections of the page.
                        $start = stripos($filecontents, "<head");
                        if( $start !== false )
                        {
                            $start = stripos($filecontents, ">", $start) + 1;					    
					    
                            $end = stripos($filecontents, "</head", $start);
                            if( $end !== false )
                            {
                                $headTxt = trim(substr( $filecontents, $start, $end - $start ));
                                $header = "<head><![CDATA[". $headTxt. "]]></head>";
                            }
                            else
                            {
					                      // TODO: Error finding the end of the HEAD tag.
                            }					
                        } 
					
                        $start = stripos($filecontents, "<body");
                        if( $start !== false )
                        {
						                $tagend = stripos($filecontents, ">", $start) + 1;                            
							
                            $onLoadTxt = "";
                            if(stripos($filecontents, "onload", $start) )
                            {                                
                                $olStart = stripos($filecontents, "onload", $start);
                                $olStart += strcspn( substr($filecontents, $olStart, $tagend - $olStart + 1 ), ">\"'" );
                                
                                if( $olStart < $tagend )
                                {
                                    $dblqt = true;
                                    if( substr( $filecontents, $olStart, 1) == "'" )
                                    {
                                        $dblqt = false;
                                    }
                                
                                    $olEnd = false;
                                    if( $dblqt == true )
                                    {
                                        $olEnd = stripos($filecontents, "\"", $olStart + 1);                                 
                                    }
                                    else
                                    {
                                        $olEnd = stripos($filecontents, "'", $olStart + 1);                                 
                                    }
                                
                                    if( $olStart !== false && $olStart < $tagend && 
                                        $olEnd !== false && $olEnd < $tagend )
                                    {
                                        $onLoadTxt = " onLoad=" . trim(substr( $filecontents, $olStart, $olEnd - $olStart + 1 ));
                                    }                                
                                }
                            }
							
                            $end = stripos($filecontents, "</body", $start);                            
                                                        			    					    
                            if( $end !== false )
                            {
                                $bodyTxt = trim(substr( $filecontents, $tagend, $end - $tagend ));
    
                                $body = "<body".$onLoadTxt."><![CDATA[".$bodyTxt."]]></body>";
                            }
                            else
                            {
                                // TODO: handle error finding end of body tag.
                            }					
                        } 
                        
						            $response = "<document type='text/html'>". $header. $body . "</document>";
				            }
                }    
            }    
		    }
		    catch( Exception $e )
		    {
			      $response = "<error> Unable to parse message. Please ensure it is valid XML. </error>";
		    }

        $newMessage = "<response>".$response."</response>\n";

        // Encrypt and prepare the return message. Then send it.
        sendResponse( $newMessage );
    }
    else
    {
        print("<response>\n <error> Invalid message. Bad Signature </error>\n </response>\n");
    }
    
    function loadFile( $filename )
    {         
        if ( file_exists($filename) ) 
        {
            $fh = fopen($filename, "rb");
            $contents = "";
            
            if( $fh !== false )
            {		
                while (!feof($fh)) 
                {   
                    $contents .= fread($fh, 8192);
                }
		
                fclose($fh);
                
                return $contents;
            }
        }
        return false;    
    }    
?>
