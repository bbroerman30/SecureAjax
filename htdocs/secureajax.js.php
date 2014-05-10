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

    require_once("/www/sites/secureajaxtest/etc/secureAjaxConfig.php");
    require_once( $secureAjaxConfig['INCDIR'] . "secureajax_helper.php");
    require_once( $secureAjaxConfig['INCDIR'] . "class.JavaScriptPacker.php");

    session_start();

    header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
    header("Expires: Mon, 26 Jul 1997 05:00:00 GMT"); // Date in the past
    header("Pragma: no-cache");
    header("Content-type: text/xml");

    if (!isset($_SESSION['secureajaxsessioninitiated']))
    {
        session_regenerate_id();
        $_SESSION['secureajaxsessioninitiated'] = true;
    }

    //
    // Based on the input parameter, get either the user validation form, the main script,
    // or the helper script.
    //
    $generatedoutput = "";
    if( !isSet( $_POST['action'] ) || $_POST['action'] != 'helper' )
    {
        //
        // Now, see if there is a post variable called "user".
        // If not, just send back an alert saying invalid user name
        // Else, get the password for the user, take the sha-1 hash of it,
        // and use that to encrypt the buffer with AES 256.
        //
        // Send back an XML message with the encrypted javascript as the payload...
        // This will be decrypted on the client, and used there...
        //
        if( isSet($_POST['user']) && strlen($_POST['user']) > 0 )
        {
            $password = getUserPassword( $_POST['user'] );

            if( $password !== false )
            {
                 $generatedoutput = getMainAjaxScript();
                
                $passwordLength = strlen($password);
                $padding = generateKey( $passwordLength );
                $password = $password . $padding;

                
                $hash = hash("sha256", $password);
                
                for($i = 0; $i < (40 * $passwordLength); ++$i)
                  $hash = hash("sha256", $hash); 
                
                $encoded = AESEncryptCtr($generatedoutput, $hash, 256);
                $encoded = strtr($encoded, '+/=', '-_,');
                $encoded = $padding . $encoded;

                print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
                print("<response><![CDATA[" . $encoded . "]]></response>\n");
            }
            else
            {
                print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
                print("<response><error>Invalid Login Attempt</error></response>\n");
            }
        }
        else if( isSet($_POST['valid']) && strlen($_POST['valid']) > 0 )
        {
            $username = $_POST['valid'];   

            $userChallengeMessage = getUserChallengeText( $username );
            $userChallengeImage = getUserChallengeImage( $username );
                
            $generatedoutput = "<html><head><style></style></head>" .
                               "<body width='392' height='200'>" .
                               "<form onsubmit='return false;' id='fm' action='#'>" .
                               "<div>" .
                               "<table class='properties'>" .
                               "<tr><td colspan='3' style='text-align:center;'><span style='font-size:12px; font-weight:bold;'> Please validate your security question and image, <br> and then enter your password below: </span></td></tr>" .
                               "<tr><td colspan='3'><span style='font-size:12px;font-weight:bold;display:inline-block;width:241px;padding-top:5px;padding-bottom:5px;'>" . $userChallengeMessage . "</span> <img src='" . $userChallengeImage . "' alt='Security Image' width='90' height='68' align='middle' style='float:right'/></td></tr>" .
                               "<tr><td class='column1' style='width:90px;padding-top:5px;'><label id='pwdlabel' for='pass'>Password:</label></td><td colspan='2' style='padding-top:5px;'><input id='pass' name='pass' type='password' value='' style='width:250px'/></td></tr>" .
                               "</table>".
                               "</div><br>" .
                               "<div class='mceActionPanel'>" .
                               "<div style='float:left'><input type='submit' id='ok' name='Ok' value='Ok' onClick='login();return false;'/></div>" .
                               "<div style='float:right'><input type='button' id='cancel' name='cancel' value='Cancel' onclick='cancelLogin();return false;'/></div>" .
                               "</div></form>" .
                               "<script type='text/javascript'>" .
                               "function login(){var pwd=document.getElementById('pass').value;var callbackFn=".$_SESSION["inlinePopup"].".getWindowArg('".$_SESSION["logincallback"]."');callbackFn('".$username."',pwd);".$_SESSION["inlinePopup"].".close();}\n" .
                               "function cancelLogin(){var callbackFn=".$_SESSION["inlinePopup"].".getWindowArg('".$_SESSION["cancelcallback"]."'); ".$_SESSION["inlinePopup"].".close(); if(callbackFn){callbackFn('','',null);}}\n" .
                               "setTimeout(function(){document.getElementById('pass').focus();},250);" .
                               "</script>" .
                               "</body>" .
                               "</html>";

            $encoded = AESEncryptCtr($generatedoutput, $_SESSION['EXTENDED_LOGIN_ENDODING_KEY'], 256);
            $encoded = strtr($encoded, '+/=', '-_,');
            
            print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
            print("<response><![CDATA[" . $encoded . "]]></response>\n");
        }
        else
        {
            print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");            
            print("<response><error>Invalid Login Attempt</error></response>\n");
        }
    }
    else if( isSet( $_POST['action'] ) && $_POST['action'] == 'helper' )
    {
        if( isSet($_SESSION['HELPER_SCRIPT_ENDODING_KEY']) && strlen($_SESSION['HELPER_SCRIPT_ENDODING_KEY']) > 0 )
        {
            $generatedoutput = getHelperScritps();
            $encoded = AESEncryptCtr($generatedoutput, $_SESSION['HELPER_SCRIPT_ENDODING_KEY'], 256);
            $encoded = strtr($encoded, '+/=', '-_,');

            print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
            print("<response><![CDATA[" . $encoded . "]]></response>\n");
        }
        else
        {
            print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
            print("<response><error>Invalid Login Attempt</error></response>\n");
        }

        unset($_SESSION['HELPER_SCRIPT_ENDODING_KEY']);
    }    
    else
    {
        print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
        print("<response><error>Invalid Login Attempt</error></response>\n");
    }

function getMainAjaxScript()
{
    global $secureAjaxConfig;

    //
    // Select an RSA-128 key. Generated before hand.
    // We can use 1 key for this process, because each connection
    // to the server has it's own random key, therefore we know which
    // client we are talking to, and the client knows only the server has
    // the private key for this public key. (assuming no man-in-the-middle at
    // setup) Note that the script should probably be sent to the client over HTTPS
    // even though that won't guarantee to protect from MITM attacks.
    //
    $rsaKey = false;
    for( $idx = 0; $idx < 10 && $rsaKey == false; ++$idx )
      $rsaKey = genRSAKey( 128 );

    if( false == $rsaKey ) {
            print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");            
            print("<response><error>Error initializing communications</error></response>\n");
            exit();
        }
      
      
    //
    // Now, generate the message to send to the client for the Diffie Hellman exchange.
    //
    $dhKeys = array();
    $returnCode = genDiffieHellmanMsg( 64 );
    if( false !== $returnCode )
    {
        $dhKeys['gen'] = $returnCode['gen'];
        $dhKeys['exp'] = $returnCode['exp'];
        $dhKeys['mod'] = $returnCode['mod'];
        $dhKeys['message'] = $returnCode['calc'];
    } else {
       print("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");            
       print("<response><error>Error initializing communications</error></response>\n");
       exit();
    }
 
    //
    // Now, store the keys that we need on the server...
    //
    $_SESSION['RSA_SERVER_PRIVATE'] = $rsaKey['private'];
    $_SESSION['RSA_SERVER_MODULUS'] = $rsaKey['mod'];

    $_SESSION['DH_PRIVATE_EXPONENT'] =  $dhKeys['exp'];
    $_SESSION['DH_GENERATOR'] = $dhKeys['gen'];
    $_SESSION['DH_MODULUS'] = $dhKeys['mod'];

    $_SESSION['HELPER_SCRIPT_ENDODING_KEY'] = sha1(generateKey(20));

    ob_start();
?>
function bbSecureAjaxLayer(){var that=this;
var serverPublicKey={exp:"<?php print($rsaKey['public']) ?>",mod:"<?php print($rsaKey['mod']) ?>"};
var diffieHellman={gen:"<?php print($dhKeys['gen']) ?>",mod:"<?php print($dhKeys['mod']) ?>",msg:"<?php print($dhKeys['message']) ?>" };
var scriptDecodeKey="<?php print($_SESSION['HELPER_SCRIPT_ENDODING_KEY']) ?>";
var serverURL="<?php print($secureAjaxConfig['APIBASEURL']); ?>";
var channelReadyCallbackFn=null;
var sharedSecretKey=null;
var DHNegotiationInProgress=true;
var scriptDependencyCache=new Array();
function aesObj(){
var Sbox=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22];
var Rcon=[[0,0,0,0],[1,0,0,0],[2,0,0,0],[4,0,0,0],[8,0,0,0],[16,0,0,0],[32,0,0,0],[64,0,0,0],[128,0,0,0],[27,0,0,0],[54,0,0,0]];
var b64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
String.prototype.encodeBase64=function(a){a=(typeof a=="undefined")?false:a;var b,c,d,e,f,g,h,i,j=[],k="",l,m,n;m=a?this.encodeUTF8():this;l=m.length%3;if(l>0){while(l++<3){k+="=";m+="\x00";}}for(l=0;l<m.length;l+=3){b=m.charCodeAt(l);c=m.charCodeAt(l+1);d=m.charCodeAt(l+2);e=b<<16|c<<8|d;f=e>>18&63;g=e>>12&63;h=e>>6&63;i=e&63;j[l/3]=b64.charAt(f)+b64.charAt(g)+b64.charAt(h)+b64.charAt(i);}n=j.join("");n=n.slice(0,n.length-k.length)+k;return n;};
String.prototype.decodeBase64=function(a){a=(typeof a=="undefined")?false:a;var b,c,d,e,f,g,h,i,j=[],k,l;l=a?this.decodeUTF8():this;for(var m=0;m<l.length;m+=4){e=b64.indexOf(l.charAt(m));f=b64.indexOf(l.charAt(m+1));g=b64.indexOf(l.charAt(m+2));h=b64.indexOf(l.charAt(m+3));i=e<<18|f<<12|g<<6|h;b=i>>>16&255;c=i>>>8&255;d=i&255;j[m/4]=String.fromCharCode(b,c,d);if(h==64){j[m/4]=String.fromCharCode(b,c);}if(g==64){j[m/4]=String.fromCharCode(b);}}k=j.join("");return a?k.decodeUTF8():k;};
String.prototype.encodeUTF8=function(){var a=this.replace(/[\u0080-\u07ff]/g,function(c){var b=c.charCodeAt(0);return String.fromCharCode(192|b>>6,128|b&63);});a=a.replace(/[\u0800-\uffff]/g,function(c){var b=c.charCodeAt(0);return String.fromCharCode(224|b>>12,128|b>>6&63,128|b&63);});return a;};
String.prototype.decodeUTF8=function(){var a=this.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g,function(c){var b=(c.charCodeAt(0)&31)<<6|c.charCodeAt(1)&63;return String.fromCharCode(b);});a=a.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,function(c){var b=((c.charCodeAt(0)&15)<<12)|((c.charCodeAt(1)&63)<<6)|(c.charCodeAt(2)&63);return String.fromCharCode(b);});return a;};
function Cipher(a,w){var b=4;var c=w.length/b-1;var d=[[],[],[],[]];for(var i=0;i<4*b;i++){d[i%4][Math.floor(i/4)]=a[i];}d=AddRoundKey(d,w,0,b);for(var e=1;e<c;e++){d=SubBytes(d,b);d=ShiftRows(d,b);d=MixColumns(d,b);d=AddRoundKey(d,w,e,b);}d=SubBytes(d,b);d=ShiftRows(d,b);d=AddRoundKey(d,w,c,b);var f=new Array(4*b);for(var i=0;i<4*b;i++){f[i]=d[i%4][Math.floor(i/4)];}return f;};
function SubBytes(s,a){for(var r=0;r<4;r++){for(var c=0;c<a;c++){s[r][c]=Sbox[s[r][c]];}}return s;};
function ShiftRows(s,a){var t=new Array(4);for(var r=1;r<4;r++){for(var c=0;c<4;c++){t[c]=s[r][(c+r)%a];}for(var c=0;c<4;c++){s[r][c]=t[c];}}return s;};
function MixColumns(s,a){for(var c=0;c<4;c++){var b=new Array(4);var d=new Array(4);for(var i=0;i<4;i++){b[i]=s[i][c];d[i]=s[i][c]&128?s[i][c]<<1^283:s[i][c]<<1;}s[0][c]=d[0]^b[1]^d[1]^b[2]^b[3];s[1][c]=b[0]^d[1]^b[2]^d[2]^b[3];s[2][c]=b[0]^b[1]^d[2]^b[3]^d[3];s[3][c]=b[0]^d[0]^b[1]^b[2]^d[3];}return s;};
function AddRoundKey(a,w,b,c){for(var r=0;r<4;r++){for(var d=0;d<c;d++){a[r][d]^=w[b*4+d][r];}}return a;};
function KeyExpansion(a){var b=4;var c=a.length/4;var d=c+6;var w=new Array(b*(d+1));var e=new Array(4);for(var i=0;i<c;i++){var r=[a[4*i],a[4*i+1],a[4*i+2],a[4*i+3]];w[i]=r;}for(var i=c;i<(b*(d+1));i++){w[i]=new Array(4);for(var t=0;t<4;t++){e[t]=w[i-1][t];}if(i%c==0){e=SubWord(RotWord(e));for(var t=0;t<4;t++){e[t]^=Rcon[i/c][t];}}else{if(c>6&&i%c==4){e=SubWord(e);}}for(var t=0;t<4;t++){w[i][t]=w[i-c][t]^e[t];}}return w;};
function SubWord(w){for(var i=0;i<4;i++){w[i]=Sbox[w[i]];}return w;};
function RotWord(w){var a=w[0];for(var i=0;i<3;i++){w[i]=w[i+1];}w[3]=a;return w;};
this.AESEncryptCtr=function(a,b,c){var d=16;if(!(c==128||c==192||c==256)){return "";}a=a.encodeUTF8();b=b.encodeUTF8();var e=c/8;var f=new Array(e);for(var i=0;i<e;i++){f[i]=isNaN(b.charCodeAt(i))?0:b.charCodeAt(i);}var g=Cipher(f,KeyExpansion(f));g=g.concat(g.slice(0,e-16));var h=new Array(d);var j=(new Date()).getTime();var k=Math.floor(j/1000);var l=j%1000;for(var i=0;i<4;i++){h[i]=(k>>>i*8)&255;}for(var i=0;i<4;i++){h[i+4]=l&255;}var m="";for(var i=0;i<8;i++){m+=String.fromCharCode(h[i]);}var n=KeyExpansion(g);var o=Math.ceil(a.length/d);var p=new Array(o);for(var q=0;q<o;q++){for(var r=0;r<4;r++){h[15-r]=(q>>>r*8)&255;}for(var r=0;r<4;r++){h[15-r-4]=(q/4294967296>>>r*8);}var s=Cipher(h,n);var t=q<o-1?d:(a.length-1)%d+1;var u=new Array(t);for(var i=0;i<t;i++){u[i]=s[i]^a.charCodeAt(q*d+i);u[i]=String.fromCharCode(u[i]);}p[q]=u.join("");}var v=m+p.join("");v=v.encodeBase64();v=v.replace(/\+/g,"-");v=v.replace(/\//g,"_");v=v.replace(/=/g,",");return v;};
this.AESDecryptCtr=function(a,b,c){var d=16;if(!(c==128||c==192||c==256)){return "";}a=a.replace(/\-/g,"+");a=a.replace(/_/g,"/");a=a.replace(/\,/g,"=");a=a.decodeBase64();b=b.encodeUTF8();var e=c/8;var f=new Array(e);for(var i=0;i<e;i++){f[i]=isNaN(b.charCodeAt(i))?0:b.charCodeAt(i);}var g=Cipher(f,KeyExpansion(f));g=g.concat(g.slice(0,e-16));var h=new Array(8);var ctrTxt=a.slice(0,8);for(var i=0;i<8;i++){h[i]=ctrTxt.charCodeAt(i);}var j=KeyExpansion(g);var k=Math.ceil((a.length-8)/d);var l=new Array(k);for(var m=0;m<k;m++){l[m]=a.slice(8+m*d,8+m*d+d);}a=l;var n=new Array(a.length);for(var m=0;m<k;m++){for(var o=0;o<4;o++){h[15-o]=((m)>>>o*8)&255;}for(var o=0;o<4;o++){h[15-o-4]=(((m+1)/4294967296-1)>>>o*8)&255;}var p=Cipher(h,j);var q=new Array(a[m].length);for(var i=0;i<a[m].length;i++){q[i]=p[i]^a[m].charCodeAt(i);q[i]=String.fromCharCode(q[i]);}n[m]=q.join("");}var r=n.join("");r=r.decodeUTF8();return r;}};
var aesFuncs=new aesObj();var rsaFuncs=null;var sha1Funcs=null;
function createXHRObject(){if(typeof XMLHttpRequest!="undefined"){return new XMLHttpRequest();}else if (typeof ActiveXObject!="undefined"){return new ActiveXObject("Microsoft.XMLHTTP");}else{throw new Error("XMLHttpRequest not supported");}};
function trim(str){return str.replace(/^\s+|\s+$/g,"");};
function getTextNode(element){var returnedText="";if(element){if(element.textContent){returnedText=element.textContent;}else if(element.text){returnedText=element.text;}if(returnedText.indexOf("[CDATA[")>-1){returnedText=returnedText.substring(7);}if(returnedText.lastIndexOf("]]")>-1){returnedText=returnedText.substring(0,returnedText.lastIndexOf("]]"));}}return returnedText;};
function parseXML(xmlData){if(window.ActiveXObject){var xmlDoc=new ActiveXObject("Microsoft.XMLDOM");xmlDoc.async="false";xmlDoc.loadXML(xmlData);return xmlDoc;}else if(document.implementation && document.implementation.createDocument){var p=new DOMParser();var xmlDoc=p.parseFromString(xmlData,"text/xml");return xmlDoc;}};
function sendAjax(apiName,params,callbackFn){var xhrObject=createXHRObject();xhrObject.open("POST",apiName,true);xhrObject.onreadystatechange=function(){if(xhrObject.readyState==4){callbackFn(xhrObject.status,xhrObject.responseXML);}};xhrObject.setRequestHeader("Content-type","application/x-www-form-urlencoded");xhrObject.setRequestHeader("Content-length",params.length);xhrObject.setRequestHeader("Connection","close");xhrObject.send(params);};
function signMessage(messageToSign){return encodeRSA(serverPublicKey,sha1Funcs.hexSHA1(messageToSign));};
function proveSignature(signature,message){var sign2=decodeRSA(serverPublicKey,signature);var hash=sha1Funcs.hexSHA1(message);if(hash==sign2){return true;}return false;};
function encodeRSA(key,message){key=rsaFuncs.makeRSAKey(key.exp,"00",key.mod);return rsaFuncs.RSAEncryptString(key,message);};
function decodeRSA(key,cryptext){key=rsaFuncs.makeRSAKey("00",key.exp,key.mod);return rsaFuncs.RSADecryptString(key,cryptext);};
function encodeAES(message){return aesFuncs.AESEncryptCtr(message,sharedSecretKey,256);};
function decodeAES(cryptext){return aesFuncs.AESDecryptCtr(cryptext,sharedSecretKey,256);};
function doInit(){sendAjax(serverURL+"secureajax.js.php","action=helper",function(stt,doc){if(doc.getElementsByTagName('response')[0]){var scr=getTextNode(doc.getElementsByTagName('response')[0]);scr=aesFuncs.AESDecryptCtr(scr,scriptDecodeKey,256);if(scr.indexOf('text/javascript')>0){eval(scr);}else{channelReadyCallbackFn(false);}}else{channelReadyCallbackFn( false );}});that.getSecretKeyDH();};
function doSetHelpers(key,rsahelper,sha1helper){if(key==scriptDecodeKey){rsaFuncs=rsahelper;sha1Funcs=sha1helper;}};
function doGetDHKey(){DHNegotiationInProgress=true;if(null==rsaFuncs||null==sha1Funcs){setTimeout('window.secureAjax.getSecretKeyDH();',100);return;}var randomExponent=rsaFuncs.makeRandomKey(16);var sharedSecretStr=rsaFuncs.getDHSecret(diffieHellman.msg,diffieHellman.mod,randomExponent);var messageToSign=rsaFuncs.getDHSecret(diffieHellman.gen,diffieHellman.mod,randomExponent);var signature=signMessage(messageToSign);var params="msg="+messageToSign+"("+signature+")";sendAjax('/dhkeyserver.php',params,function(stt,doc){if(doc.getElementsByTagName('success')[0]){sharedSecretKey=sha1Funcs.hexSHA1(sharedSecretStr);DHNegotiationInProgress=false;if(null!=channelReadyCallbackFn){channelReadyCallbackFn(true);}}else{alert("Error in setting up secure communication.");if(null!=channelReadyCallbackFn){channelReadyCallbackFn(false);}}}); };
function doGetNewKey(callbackFn){DHNegotiationInProgress=true;if(null==rsaFuncs||null==sha1Funcs){DHNegotiationInProgress=false;callbackFn(false);return;}var randomExponent=rsaFuncs.makeRandomKey(16);var messageToSign=rsaFuncs.getDHSecret(diffieHellman.gen,diffieHellman.mod,randomExponent);var signature=signMessage(messageToSign);var params="newmsg="+newMessageStr+"("+signature+")";sendAjax('/dhkeyserver.php',params,function(stt,doc){if(doc.getElementsByTagName('response').length>0){var message=getTextNode(doc.getElementsByTagName('response')[0]);message=trim(message);var signature="";var idx1=message.indexOf("(");if(idx1>-1){var idx2=message.lastIndexOf(")");signature=message.substring(idx1+1,idx2);message=message.substring(0,idx1);}if(proveSignature(signature,message)==true){var sharedSecretStr=rsaFuncs.getDHSecret(message,diffieHellman.mod,randomExponent);sharedSecretKey=sha1Funcs.hexSHA1(sharedSecretStr);DHNegotiationInProgress=false;if(null!=callbackFn){callbackFn(true);}return;}else{alert("Error in negotiating new key. Message was altered");}}else{alert("Error in negotiating new key. Invalid response from server.");}if(null!=callbackFn){callbackFn(false);}DHNegotiationInProgress=false;});};
function doSendSecure(serviceUrl,parms,callback){if(null==sharedSecretKey){alert('Secure communications not set up.');callback(null);return;}var encodedMsg=encodeAES(parms);var signature=signMessage(encodedMsg);var params="msg="+encodedMsg+"("+signature+")";sendAjax(serviceUrl,params,function(stt,doc){if(doc.getElementsByTagName('response').length>0){var cryptext=getTextNode(doc.getElementsByTagName('response')[0]);cryptext=trim(cryptext);var signature="";var idx1=cryptext.indexOf("(");if(idx1>-1){var idx2=cryptext.lastIndexOf(")");signature=cryptext.substring(idx1+1,idx2);cryptext=cryptext.substring(0,idx1);}if(proveSignature(signature,cryptext)==true){var plaintext=decodeAES(cryptext);var doc=parseXML(plaintext);if(doc.getElementsByTagName('error').length>0){alert(getTextNode(doc.getElementsFromTagName('error')[0]));}callback(doc);}else{alert("Error: Message has been interfered with. Signatures do not match.");callback(null);}}else{alert("Error: Invalid response from server.");callback(null);}});};
function doLoadScpt(scriptname,id,reqScr,callback){var msg="<loadScript name='"+scriptname+"'/>";if(id==null||id==""){id=scriptDependencyCache.length+1;}scriptDependencyCache[id]=false;doSendSecure(serverURL+"SecureAjaxAPIs.php",msg,function(doc){if(doc!=null){var scr=doc.getElementsByTagName('script')[0];if(scr&&scr.getAttribute('type')){var t=scr.attributes.getNamedItem('type').value;if(t.indexOf('text/javascript')>-1){if(requiredScriptsLoaded(reqScr)){callback(getTextNode(scr));scriptDependencyCache[id]=true;checkForScriptsReady();}else{scriptDependencyCache[id]={req:reqScr,text:getTextNode(scr),callback:callback};}}}}});};
function checkForScriptsReady(){for(var i in scriptDependencyCache){if(scriptDependencyCache[i]!==true&&scriptDependencyCache[i]!==false){if(requiredScriptsLoaded(scriptDependencyCache[i].req)){scriptDependencyCache[i].callback(scriptDependencyCache[i].text);scriptDependencyCache[i]=true;}else{setTimeout(checkForScriptsReady,250);}}}};
function requiredScriptsLoaded(req){if(req===null||req==""){return true;}var requiredScriptIds=req.split(' ');var foundScript=false;for(var i=0;i<requiredScriptIds.length;++i){if(scriptDependencyCache[requiredScriptIds[i]]!==true){foundScript=true;break;}}return (foundScript==false);};
function scriptStillLoading(){var foundScript=false;checkForScriptsReady();for(var i in scriptDependencyCache){if(scriptDependencyCache[i]!==true){foundScript=true;break;}}return foundScript;};
function getScriptCacheIds(){var keys="";for(var i in scriptDependencyCache){keys+=i+" ";}return trim(keys);};
function doLoadImageFromServer(imgname,target){var msg="<loadImage name='"+imgname+"'/>";doSendSecure("<?php print($secureAjaxConfig['APIBASEURL']); ?>SecureAjaxAPIs.php",msg,function(doc){if(doc!=null){var scr=doc.getElementsByTagName('img')[0];var type=scr.attributes.getNamedItem('mimetype').value;var data=getTextNode(scr);document.getElementById(target).src="data:"+mimetype+";base64,"+base64rep;}});};
function doLoadStyle(scriptname){var msg="<loadStyle name='"+scriptname+"'/>";doSendSecure(serverURL+"SecureAjaxAPIs.php",msg,function(doc){if(doc!=null){var scr=doc.getElementsByTagName('script')[0];if(scr&&scr.getAttribute('type')){var t=scr.attributes.getNamedItem('type').value;if(t.indexOf('text/css')>-1){var s=document.createElement('style');s.setAttribute("type","text/css");s.setAttribute("saexec","no");var st=getTextNode(scr);if(s.styleSheet){s.styleSheet.cssText=st;}else{s.appendChild(document.createTextNode(st));}document.getElementsByTagName('head')[0].appendChild(s);}}}else{alert("Error: Invalid response from server.");}});};
function insScrptAt(scr,p,e){var s=document.createElement('script');s.setAttribute("type","text/javascript");s.text=scr;p.insertBefore(s,e);};
function doLoadPage(pagename){var msg="<loadPage name='"+pagename+"'/>";doSendSecure(serverURL+"SecureAjaxAPIs.php",msg,function(doc){if(doc!=null){var scr=doc.getElementsByTagName('document')[0];if(scr){insHdrScr(scr.getElementsByTagName('head')[0]);document.body.innerHTML = getTextNode(scr.getElementsByTagName('body')[0]);runScripts(document.body);if(scr.getElementsByTagName('body')[0].getAttribute('onLoad')){var contents = scr.getElementsByTagName('body')[0].getAttribute('onLoad');if(scriptStillLoading()){scriptDependencyCache['body_onload']={req:getScriptCacheIds(), text:contents, callback:function(scr){eval(scr);}};}else{eval(contents);}}}}});};
function insHdrScr(src){var hdr=document.getElementsByTagName('head')[0];if(hdr.hasChildNodes()){while(hdr.childNodes.length>=1){hdr.removeChild(hdr.firstChild);}}if(!src){return;}var dn=document.createElement('div');dn.innerHTML="<div>&nbsp;</div>"+getTextNode(src);var n=dn.firstChild;while(n){if(n.nodeType==1){var s=null;if(n.tagName.toLowerCase()=='script'){s=createScriptNode(n,hdr,null);}else if(n.tagName.toLowerCase()=='style'){if(!n.getAttribute("saexec")){s=document.createElement('style');s.setAttribute("type","text/css");var st=getTextNode(n);if(!st)st=n.innerHTML;if(s.styleSheet){s.styleSheet.cssText=st;}else{s.appendChild(document.createTextNode(st));}}}else if(n.tagName.toLowerCase()=='link'){s=document.createElement('link');if(n.getAttribute('type')){s.type =n.type;}if(n.getAttribute('media')){s.media=n.media;}if(n.getAttribute('rel')){s.rel=n.rel;}if(n.getAttribute('href')){var src=n.href;var strt = src.indexOf("secure://");if(strt==0){doLoadStyle(src.substring(strt+9));s=null;}else{s.setAttribute("src",src);}}}if(s!=null){hdr.appendChild(s);s=null;}}n=n.nextSibling;}};
function runScripts(e){if(e.nodeType!=1){return;}if(e.tagName.toLowerCase()=='script'){s=createScriptNode(e,e.parentNode,e);if(s!=null){e.parentNode.insertBefore(s,e);}}else{var n=e.firstChild;while(n){if(n.nodeType==1){runScripts(n);}n=n.nextSibling;}}};
function createScriptNode(n,insrt,instbef){var s=document.createElement('script');s.setAttribute("type","text/javascript");if(n.getAttribute('src')){var src=n.getAttribute('src');var strt=src.indexOf("secure://");if(strt==0){var id=n.getAttribute('id');var req=n.getAttribute('required');doLoadScpt(src.substring(strt+9),id,req,function(scr){insScrptAt(scr,insrt,instbef);});s=null;}else{s.setAttribute("src",src);var id=n.getAttribute('id');if(id){scriptDependencyCache[id]=true;}}}else{s.text=getTextNode(n);var id=n.getAttribute('id');if(id){scriptDependencyCache[id]=true;}}return s;};
this.getSecretKeyDH=function(){doGetDHKey();};
this.getNewSecureKey=function(callbackFn){doGetNewKey(callbackFn);};
this.isReady=function(){return(DHNegotiationInProgress==false);};
this.setReadyCallback=function(func){if(func){channelReadyCallbackFn=func;}};
this.sendSecureMessage=function(serviceUrl,parms,callback){doSendSecure(serviceUrl,parms,callback);};
this.insertScript=function(scrptname,divid,id,required){id=((id)?id:"");required=((required)?required:"");doLoadScpt(scrptname,id,required,function(scr){insScrptAt(scr,document.getElementById(divid),null);});};
this.execScript=function(scrptname){doLoadScpt(scriptname,null,null,function(scr){eval(scr);});};
this.loadStylesheet=function(scrptname){doLoadStyle(scrptname);};
this.loadImage=function(imgname,target){doLoadImageFromServer(imgname,target);};
this.loadPage=function(pagename){doLoadPage(pagename);};
this.setHelpers=function(key,rsahelper,sha1helper){doSetHelpers(key,rsahelper,sha1helper);};
this.init=function(){doInit();}};
self.top.secureAjax=new bbSecureAjaxLayer();
<?php

    $generatedoutput = ob_get_contents();
    ob_end_clean();
    
    //
    // this is the list of key words that we will randomly change:
    //
    $keywords = array( "that","serverPublicKey","diffieHellman","scriptDecodeKey","serverURL","channelReadyCallbackFn","DHNegotiationInProgress","returnedText",
                       "scriptDependencyCache","Sbox","Rcon","encodeBase64","decodeBase64","encodeUTF8","decodeUTF8","Cipher","SubBytes","ShiftRows","sha1Funcs",
                       "MixColumns","AddRoundKey","KeyExpansion","aesObj","SubWord","RotWord","AESEncryptCtr","AESDecryptCtr","createXHRObject","trim","rsaFuncs",
                       "getTextNode","parseXML","xmlData","sendAjax","callbackFn","signMessage","messageToSign","proveSignature","signature","message","aesFuncs",
                       "encodeRSA","decodeRSA","cryptext","doInit","doSetHelpers","doGetDHKey","doGetNewKey","doSendSecure","serviceUrl","parms","callback","sharedSecretKey",
                       "doLoadScpt","scriptname","reqScr","checkForScriptsReady","requiredScriptsLoaded","scriptStillLoading","getScriptCacheIds","randomExponent",
                       "doLoadImageFromServer","doLoadStyle","insScrptAt","doLoadPage","insHdrScr","runScripts","createScriptNode","sharedSecretStr","newMessageStr",
                       "requiredScriptIds","foundScript","rsahelper","sha1helper","xhrObject","plaintext","encodeAES","decodeAES","apiName","encodedMsg","pagename",
                       "xmlDoc","imgname","target","params","idx1","idx2" );

    //
    // Now, for each keyword, generate a unique 6 digit hexidecimal name
    //
    $originalOutput = $generatedoutput;  // Keep a copy of the original just for debugging purposes...
    
    $encodedSet["v".generateKey(6)] = true;
    while( count($encodedSet) < count($keywords) )
    {
        $nextKey = "v".generateKey(rand(3,6));
        if( !isSet($encodedSet[$nextKey] ) )
        {
            $encodedSet[$nextKey] = true;
        }
    }

    $idx = 0;
    foreach (array_keys($encodedSet) as $key)
    {
        $encodedSet[$key] = $keywords[$idx];
        
        $idx++;
    }    
    
    foreach ($encodedSet as $encoded => $original) 
    {
       $generatedoutput = str_replace($original,$encoded,$generatedoutput);
    }
    
    //
    // Now, compress the generated output...
    //
    //$packer = new JavaScriptPacker($generatedoutput, 62, true, false);
    //$packed = $packer->pack();
    $packed = $generatedoutput;
    
    return "//<script type='text/javascript'>\n".$packed."\n//</script>";
}

function getHelperScritps()
{
    global $secureAjaxConfig;

ob_start();
?>
//<script type='text/javascript'>
function sha1(){var hexcase=0;var chrsz=8;
function sha1_ft(t,b,c,d){if(t<20){return (b&c)|((~b)&d)}if(t<40){return b^c^d}if(t<60){return (b&c)|(b&d)|(c&d)}return b^c^d}
function sha1_kt(t){return (t<20)?1518500249:(t<40)?1859775393:(t<60)?-1894007588:-899497514}
function safe_add(x,y){var a=(x&65535)+(y&65535);var b=(x>>16)+(y>>16)+(a>>16);return (b<<16)|(a&65535)}
function rol(a,b){return (a<<b)|(a>>>(32-b))}
function str2binb(a){var b=Array();var c=(1<<chrsz)-1;for(var i=0;i<a.length*chrsz;i+=chrsz){b[i>>5]|=(a.charCodeAt(i/chrsz)&c)<<(32-chrsz-i%32)}return b}
function binb2hex(a){var b=hexcase?"0123456789ABCDEF":"0123456789abcdef";var c="";for(var i=0;i<a.length*4;i++){c+=b.charAt((a[i>>2]>>((3-i%4)*8+4))&15)+b.charAt((a[i>>2]>>((3-i%4)*8))&15)}return c}
function core_sha1(x,a){x[a>>5]|=128<<(24-a%32);x[((a+64>>9)<<4)+15]=a;var w=Array(80);var b=1732584193;var c=-271733879;var d=-1732584194;var e=271733878;var f=-1009589776;for(var i=0;i<x.length;i+=16){var g=b;var h=c;var j=d;var k=e;var l=f;for(var m=0;m<80;m++){if(m<16){w[m]=x[i+m]}else{w[m]=rol(w[m-3]^w[m-8]^w[m-14]^w[m-16],1)}var t=safe_add(safe_add(rol(b,5),sha1_ft(m,c,d,e)),safe_add(safe_add(f,w[m]),sha1_kt(m)));f=e;e=d;d=rol(c,30);c=b;b=t}b=safe_add(b,g);c=safe_add(c,h);d=safe_add(d,j);e=safe_add(e,k);f=safe_add(f,l)}return Array(b,c,d,e,f)}
this.hexSHA1 = function(s){var c = binb2hex(core_sha1(str2binb(s),s.length*chrsz));return c;}}
function Sha256(){
var Utf8={};
Utf8.decode=function(strUtf){var strUni=strUtf.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,function(c){var cc=((c.charCodeAt(0)&15)<<12)|((c.charCodeAt(1)&63)<<6)|(c.charCodeAt(2)&63);return String.fromCharCode(cc);});strUni=strUni.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g,function(c){var cc=(c.charCodeAt(0)&31)<<6|c.charCodeAt(1)&63;return String.fromCharCode(cc);});return strUni;};
Utf8.encode=function(strUni){var strUtf=strUni.replace(/[\u0080-\u07ff]/g,function(c){var cc=c.charCodeAt(0);return String.fromCharCode(192|cc>>6,128|cc&63);});strUtf=strUtf.replace(/[\u0800-\uffff]/g,function(c){var cc=c.charCodeAt(0);return String.fromCharCode(224|cc>>12,128|cc>>6&63,128|cc&63);});return strUtf;};
function toHexStr(n){var s="",v;for(var i=7;i>=0;i--){v=(n>>>(i*4))&15;s+=v.toString(16);}return s;}
function ROTR(n,x){return(x>>>n)|(x<<(32-n));}
function Sigma0(x){return ROTR(2,x)^ROTR(13,x)^ROTR(22,x);}
function Sigma1(x){return ROTR(6,x)^ROTR(11,x)^ROTR(25,x);}
function sigma0(x){return ROTR(7,x)^ROTR(18,x)^(x>>>3);}
function sigma1(x){return ROTR(17,x)^ROTR(19,x)^(x>>>10);}
function Ch(x,y,z){return(x&y)^(~x&z);}
function Maj(x,y,z){return(x&y)^(x&z)^(y&z);}
function hash(msg,utf8encode){utf8encode=(typeof utf8encode=="undefined")?true:utf8encode;if(utf8encode){msg=Utf8.encode(msg);}var K=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];var H=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225];msg+=String.fromCharCode(128);var l=msg.length/4+2;var N=Math.ceil(l/16);var M=new Array(N);for(var i=0;i<N;i++){M[i]=new Array(16);for(var j=0;j<16;j++){M[i][j]=(msg.charCodeAt(i*64+j*4)<<24)|(msg.charCodeAt(i*64+j*4+1)<<16)|(msg.charCodeAt(i*64+j*4+2)<<8)|(msg.charCodeAt(i*64+j*4+3));}}M[N-1][14]=((msg.length-1)*8)/Math.pow(2,32);M[N-1][14]=Math.floor(M[N-1][14]);M[N-1][15]=((msg.length-1)*8)&4294967295;var W=new Array(64);var a,b,c,d,e,f,g,h;for(var i=0;i<N;i++){for(var t=0;t<16;t++){W[t]=M[i][t];}for(var t=16;t<64;t++){W[t]=(sigma1(W[t-2])+W[t-7]+sigma0(W[t-15])+W[t-16])&4294967295;}a=H[0];b=H[1];c=H[2];d=H[3];e=H[4];f=H[5];g=H[6];h=H[7];for(var t=0;t<64;t++){var T1=h+Sigma1(e)+Ch(e,f,g)+K[t]+W[t];var T2=Sigma0(a)+Maj(a,b,c);h=g;g=f;f=e;e=(d+T1)&4294967295;d=c;c=b;b=a;a=(T1+T2)&4294967295;}H[0]=(H[0]+a)&4294967295;H[1]=(H[1]+b)&4294967295;H[2]=(H[2]+c)&4294967295;H[3]=(H[3]+d)&4294967295;H[4]=(H[4]+e)&4294967295;H[5]=(H[5]+f)&4294967295;H[6]=(H[6]+g)&4294967295;H[7]=(H[7]+h)&4294967295;}return toHexStr(H[0])+toHexStr(H[1])+toHexStr(H[2])+toHexStr(H[3])+toHexStr(H[4])+toHexStr(H[5])+toHexStr(H[6])+toHexStr(H[7]);}
this.hexSHA256=function(msg,utf8encode){return hash(msg,utf8encode);};}
function rsa(){var biRadixBase=2;var biRadixBits=16;var bitsPerDigit=biRadixBits;var biRadix=1<<16;var biHalfRadix=biRadix>>>1;var biRadixSquared=biRadix*biRadix;
var maxDigitVal=biRadix-1;var maxInteger=9999999999999998;var maxDigits=20;var ZERO_ARRAY=Array(20);var bigZero=null;
var bigOne=null;var dpl10=15;var lr10=biFromNumber(1000000000000000);var hexToChar=new Array("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f");
function BigInt(a){if(typeof a=="boolean"&&a==true){this.digits=null}else{this.digits=ZERO_ARRAY.slice(0)}this.isNeg=false}
function setMaxDigits(a){maxDigits=a;ZERO_ARRAY=new Array(maxDigits);for(var b=0;b<ZERO_ARRAY.length;b++){ZERO_ARRAY[b]=0}bigZero=new BigInt();bigOne=new BigInt();bigOne.digits[0]=1}
function biCopy(a){var b=new BigInt(true);b.digits=a.digits.slice(0);b.isNeg=a.isNeg;return b}
function biFromNumber(i){var a=new BigInt();a.isNeg=i<0;i=Math.abs(i);var j=0;while(i>0){a.digits[j++]=i&maxDigitVal;i=Math.floor(i/biRadix)}return a}
function reverseStr(s){var a="";for(var i=s.length-1;i>-1;--i){a+=s.charAt(i)}return a}var hexatrigesimalToChar=new Array("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z");
function digitToHex(n){var a=15;var b="";for(var i=0;i<4;++i){b+=hexToChar[n&a];n>>>=4}return reverseStr(b)}
function biToHex(x){var a="";var n=biHighIndex(x);for(var i=biHighIndex(x);i>-1;--i){a+=digitToHex(x.digits[i])}return a}
function charToHex(c){var a=48;var b=a+9;var d=97;var e=d+25;var f=65;var g=65+25;var h;if(c>=a&&c<=b){h=c-a}else{if(c>=f&&c<=g){h=10+c-f}else{if(c>=d&&c<=e){h=10+c-d}else{h=0}}}return h}
function hexToDigit(s){var a=0;var b=Math.min(s.length,4);for(var i=0;i<b;++i){a<<=4;a|=charToHex(s.charCodeAt(i))}return a}
function biFromHex(s){var a=new BigInt();var b=s.length;for(var i=b,j=0;i>0;i-=4,++j){a.digits[j]=hexToDigit(s.substr(Math.max(i-4,0),Math.min(i,4)))}return a}
function biAdd(x,y){var a;if(x.isNeg!=y.isNeg){y.isNeg=!y.isNeg;a=biSubtract(x,y);y.isNeg=!y.isNeg}else{a=new BigInt();var c=0;var n;for(var i=0;i<x.digits.length;++i){n=x.digits[i]+y.digits[i]+c;a.digits[i]=n%biRadix;c=Number(n>=biRadix)}a.isNeg=x.isNeg}return a}
function biSubtract(x,y){var a;if(x.isNeg!=y.isNeg){y.isNeg=!y.isNeg;a=biAdd(x,y);y.isNeg=!y.isNeg}else{a=new BigInt();var n,c;c=0;for(var i=0;i<x.digits.length;++i){n=x.digits[i]-y.digits[i]+c;a.digits[i]=n%biRadix;if(a.digits[i]<0){a.digits[i]+=biRadix}c=0-Number(n<0)}if(c==-1){c=0;for(var i=0;i<x.digits.length;++i){n=0-a.digits[i]+c;a.digits[i]=n%biRadix;if(a.digits[i]<0){a.digits[i]+=biRadix}c=0-Number(n<0)}a.isNeg=!x.isNeg}else{a.isNeg=x.isNeg}}return a}
function biHighIndex(x){var a=x.digits.length-1;while(a>0&&x.digits[a]==0){--a}return a}
function biNumBits(x){var n=biHighIndex(x);var d=x.digits[n];var m=(n+1)*bitsPerDigit;var a;for(a=m;a>m-bitsPerDigit;--a){if((d&32768)!=0){break}d<<=1}return a}
function biMultiply(x,y){var a=new BigInt();var c;var n=biHighIndex(x);var t=biHighIndex(y);var u,b,k;for(var i=0;i<=t;++i){c=0;k=i;for(var j=0;j<=n;++j,++k){b=a.digits[k]+x.digits[j]*y.digits[i]+c;a.digits[k]=b&maxDigitVal;c=b>>>biRadixBits}a.digits[i+n+1]=c}a.isNeg=x.isNeg!=y.isNeg;return a}
function biMultiplyDigit(x,y){var n,c,a;var result=new BigInt();n=biHighIndex(x);c=0;for(var j=0;j<=n;++j){a=result.digits[j]+x.digits[j]*y+c;result.digits[j]=a&maxDigitVal;c=a>>>biRadixBits}result.digits[1+n]=c;return result}
function arrayCopy(a,b,c,d,n){var m=Math.min(b+n,a.length);for(var i=b,j=d;i<m;++i,++j){c[j]=a[i]}}var highBitMasks=new Array(0,32768,49152,57344,61440,63488,64512,65024,65280,65408,65472,65504,65520,65528,65532,65534,65535);
function biShiftLeft(x,n){var a=Math.floor(n/bitsPerDigit);var b=new BigInt();arrayCopy(x.digits,0,b.digits,a,b.digits.length-a);var c=n%bitsPerDigit;var d=bitsPerDigit-c;for(var i=b.digits.length-1,e=i-1;i>0;--i,--e){b.digits[i]=((b.digits[i]<<c)&maxDigitVal)|((b.digits[e]&highBitMasks[c])>>>(d))}b.digits[0]=((b.digits[i]<<c)&maxDigitVal);b.isNeg=x.isNeg;return b}var lowBitMasks=new Array(0,1,3,7,15,31,63,127,255,511,1023,2047,4095,8191,16383,32767,65535);
function biShiftRight(x,n){var a=Math.floor(n/bitsPerDigit);var b=new BigInt();arrayCopy(x.digits,a,b.digits,0,x.digits.length-a);var c=n%bitsPerDigit;var d=bitsPerDigit-c;for(var i=0,e=i+1;i<b.digits.length-1;++i,++e){b.digits[i]=(b.digits[i]>>>c)|((b.digits[e]&lowBitMasks[c])<<d)}b.digits[b.digits.length-1]>>>=c;b.isNeg=x.isNeg;return b}
function biMultiplyByRadixPower(x,n){var a=new BigInt();arrayCopy(x.digits,0,a.digits,n,a.digits.length-n);return a}
function biDivideByRadixPower(x,n){var a=new BigInt();arrayCopy(x.digits,n,a.digits,0,a.digits.length-n);return a}
function biModuloByRadixPower(x,n){var a=new BigInt();arrayCopy(x.digits,0,a.digits,0,n);return a}
function biCompare(x,y){if(x.isNeg!=y.isNeg){return 1-2*Number(x.isNeg)}for(var i=x.digits.length-1;i>=0;--i){if(x.digits[i]!=y.digits[i]){if(x.isNeg){return 1-2*Number(x.digits[i]>y.digits[i])}else{return 1-2*Number(x.digits[i]<y.digits[i])}}}return 0}
function biDivideModulo(x,y){var a=biNumBits(x);var b=biNumBits(y);var c=y.isNeg;var q,r;if(a<b){if(x.isNeg){q=biCopy(bigOne);q.isNeg=!y.isNeg;x.isNeg=false;y.isNeg=false;r=biSubtract(y,x);x.isNeg=true;y.isNeg=c}else{q=new BigInt();r=biCopy(x)}return new Array(q,r)}q=new BigInt();r=x;var t=Math.ceil(b/bitsPerDigit)-1;var d=0;while(y.digits[t]<biHalfRadix){y=biShiftLeft(y,1);++d;++b;t=Math.ceil(b/bitsPerDigit)-1}r=biShiftLeft(r,d);a+=d;var n=Math.ceil(a/bitsPerDigit)-1;var e=biMultiplyByRadixPower(y,n-t);while(biCompare(r,e)!=-1){++q.digits[n-t];r=biSubtract(r,e)}for(var i=n;i>t;--i){var f=(i>=r.digits.length)?0:r.digits[i];var g=(i-1>=r.digits.length)?0:r.digits[i-1];var h=(i-2>=r.digits.length)?0:r.digits[i-2];var j=(t>=y.digits.length)?0:y.digits[t];var k=(t-1>=y.digits.length)?0:y.digits[t-1];if(f==j){q.digits[i-t-1]=maxDigitVal}else{q.digits[i-t-1]=Math.floor((f*biRadix+g)/j)}var l=q.digits[i-t-1]*((j*biRadix)+k);var m=(f*biRadixSquared)+((g*biRadix)+h);while(l>m){--q.digits[i-t-1];l=q.digits[i-t-1]*((j*biRadix)|k);m=(f*biRadix*biRadix)+((g*biRadix)+h)}e=biMultiplyByRadixPower(y,i-t-1);r=biSubtract(r,biMultiplyDigit(e,q.digits[i-t-1]));if(r.isNeg){r=biAdd(r,e);--q.digits[i-t-1]}}r=biShiftRight(r,d);q.isNeg=x.isNeg!=c;if(x.isNeg){if(c){q=biAdd(q,bigOne)}else{q=biSubtract(q,bigOne)}y=biShiftRight(y,d);r=biSubtract(y,r)}if(r.digits[0]==0&&biHighIndex(r)==0){r.isNeg=false}return new Array(q,r)}
function BarrettMu(m){this.mod=biCopy(m);this.k=biHighIndex(this.mod)+1;var a=new BigInt();a.digits[2*this.k]=1;this.mu=biDivideModulo(a,this.mod)[0];this.bkplus1=new BigInt();this.bkplus1.digits[this.k+1]=1;this.modulo=BarrettMu_modulo;this.multiplyMod=BarrettMu_multiplyMod;this.powMod=BarrettMu_powMod}
function BarrettMu_modulo(x){var a=biDivideByRadixPower(x,this.k-1);var b=biMultiply(a,this.mu);var c=biDivideByRadixPower(b,this.k+1);var d=biModuloByRadixPower(x,this.k+1);var e=biMultiply(c,this.mod);var f=biModuloByRadixPower(e,this.k+1);var r=biSubtract(d,f);if(r.isNeg){r=biAdd(r,this.bkplus1)}var g=biCompare(r,this.mod)>=0;while(g){r=biSubtract(r,this.mod);g=biCompare(r,this.mod)>=0}return r}
function BarrettMu_multiplyMod(x,y){var a=biMultiply(x,y);return this.modulo(a)}
function BarrettMu_powMod(x,y){var a=new BigInt();a.digits[0]=1;var b=x;var k=y;while(true){if((k.digits[0]&1)!=0){a=this.multiplyMod(a,b)}k=biShiftRight(k,1);if(k.digits[0]==0&&biHighIndex(k)==0){break}b=this.multiplyMod(b,b)}return a}
function Arcfour(){this.i=0;this.j=0;this.S=new Array()}
function ARC4init(a){var i,j,t;for(i=0;i<256;++i){this.S[i]=i}j=0;for(i=0;i<256;++i){j=(j+this.S[i]+a[i%a.length])&255;t=this.S[i];this.S[i]=this.S[j];this.S[j]=t}this.i=0;this.j=0}
function ARC4next(){var t;this.i=(this.i+1)&255;this.j=(this.j+this.S[this.i])&255;t=this.S[this.i];this.S[this.i]=this.S[this.j];this.S[this.j]=t;return this.S[(t+this.S[this.i])&255]}
Arcfour.prototype.init=ARC4init;Arcfour.prototype.next=ARC4next;
function prng_newstate(){return new Arcfour()}var rng_psize=256;var rng_state;var rng_pool;var rng_pptr;
function rng_seed_int(x){rng_pool[rng_pptr++]^=x&255;rng_pool[rng_pptr++]^=(x>>8)&255;rng_pool[rng_pptr++]^=(x>>16)&255;rng_pool[rng_pptr++]^=(x>>24)&255;if(rng_pptr>=rng_psize){rng_pptr-=rng_psize}}
function rng_seed_time(){rng_seed_int(new Date().getTime())}if(rng_pool==null){rng_pool=new Array();rng_pptr=0;var t;if(navigator.appName=="Netscape"&&navigator.appVersion<"5"&&window.crypto){var z=window.crypto.random(32);for(t=0;t<z.length;++t){rng_pool[rng_pptr++]=z.charCodeAt(t)&255}}while(rng_pptr<rng_psize){t=Math.floor(65536*Math.random());rng_pool[rng_pptr++]=t>>>8;rng_pool[rng_pptr++]=t&255}rng_pptr=0;rng_seed_time()}
function rng_get_byte(){if(rng_state==null){rng_seed_time();rng_state=prng_newstate();rng_state.init(rng_pool);for(rng_pptr=0;rng_pptr<rng_pool.length;++rng_pptr){rng_pool[rng_pptr]=0}rng_pptr=0}return rng_state.next()}
function d2h(d){return d.toString(16)}function h2d(h){return parseInt(h,16)}
function RSAKeyPair(enc,dec,mod){this.e=biFromHex(enc);this.d=biFromHex(dec);this.m=biFromHex(mod);this.keybits=biNumBits(this.m)*2;if(this.keybits%16!=0){this.keybits=(Math.floor(this.keybits/16)+1)*16;}this.keyLen=this.keybits/8;if(this.keyLen%2!=0){this.keyLen++;}this.chunkSize=Math.floor(this.keyLen/2)-12;this.barrett=new BarrettMu(this.m);}
function pkcs1unpad2(d,n){var b=new Array();var a=0;for(var idx=0;idx<d.length;++idx){b[idx]=d.charCodeAt(idx)}var i=0;while(i<b.length&&b[i]=="0".charCodeAt(0)){++i}if(i==0){a=1}if(b.length-i-a!=n-1||b[i]!="2".charCodeAt(0)){return null}++i;while(b[i]!="0".charCodeAt(0)){if(++i>=b.length){return null}}var c="";while(++i<b.length){c+=String.fromCharCode(b[i])}c=c.substring(0,c.length-1);return c}
function pkcs1pad2(s,a){var b=new Array();var i=s.length-1;var n=a;b[--n]="0".charCodeAt(0);while(i>=0&&n>0){b[--n]=s.charCodeAt(i--)}b[--n]="0".charCodeAt(0);var x=new Array();while(n>2){var c=Math.floor(Math.random()*16)+1;b[--n]=d2h(c).charCodeAt(0)}b[--n]="2".charCodeAt(0);b[--n]="0".charCodeAt(0);var d="";while(++i<b.length){d+=String.fromCharCode(b[i])}return d}
function doEnc(a,s){if(a.keyLen<s.length+11){alert("Message too long for RSA");return null}var b=pkcs1pad2(s,a.keyLen);var c=biFromHex(b);var d=a.barrett.powMod(c,a.e);return biToHex(d)}
function doDec(a,c){var b=biFromHex(c);var d=a.barrett.powMod(b,a.d);var s=biToHex(d);var e=pkcs1unpad2(s,a.keyLen);return e}
this.makeRandomKey=function(bits){var ba=new Array();bits=bits/8;for(var idx=0;idx<bits;++idx){ba[idx]=rng_get_byte();}var hexstring="";for(var idx=0;idx<bits;++idx){hexstring+=ba[idx].toString(16);}return hexstring;}
this.makeRSAKey=function(a,b,c){setMaxDigits(38); return new RSAKeyPair(a,b,c); }
this.RSAEncryptString=function(a,s){setMaxDigits(38); var b=new Array();var c=s.length;var i=0;while(i<c){b[i]=s.charCodeAt(i);i++}while(b.length%a.chunkSize!=0){b[i++]=0}var d=b.length;var e="";var j,k,f;for(i=0;i<d;i+=a.chunkSize){f="";for(k=i;k<i+a.chunkSize;++j){f+=d2h(b[k++])}var text=doEnc(a,f);e+=text+" "}return e.substring(0,e.length-1)}
this.RSADecryptString=function(a,s){setMaxDigits(38); var b=s.split(" ");var c="";var i,j,d;d="";for(i=0;i<b.length;++i){d+=doDec(a,b[i])}for(j=0;j<=d.length;j+=2){c+=String.fromCharCode(h2d(d.substring(j,j+2)))}while(c.length>0&&c.charCodeAt(c.length-1)==0){c=c.substring(0,c.length-1)}return c}
this.getDHSecret=function(msg,mod,exp){var randomExponent=new biFromHex(exp);var mod=biFromHex(mod);var barrettMu=new BarrettMu(mod);var dhMessage=biFromHex(msg);var sharedSecret=barrettMu.powMod(dhMessage,randomExponent);var sharedSecretStr=biToHex(sharedSecret);if(sharedSecretStr.length%2==1){shar0edSecretStr="0"+sharedSecretStr;}return sharedSecretStr;}
setMaxDigits(20);}
self.top.secureAjax.setHelpers("<?php print($_SESSION['HELPER_SCRIPT_ENDODING_KEY']) ?>",new rsa(),new sha1());
//</script>
<?php
$generatedoutput = ob_get_contents();
ob_end_clean();
return $generatedoutput;
}

?>
