<?php
    //
    // Secure Ajax Layer Copyright (c) 2008 - 2009 Brad Broerman. bbroerman@bbroerman.net released under the LGPL 2.1 license
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

	// Start the session.
    session_start();

	// Make sure the calling page (and any routers, proxies, etc) don't cache the output at all.
    header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
    header("Expires: Mon, 26 Jul 1997 05:00:00 GMT"); // Date in the past
    header("Pragma: no-cache");
    header("Content-type: text/javascript");

	// Session Fixation check and countermeasure.
    if (!isset($_SESSION['secureajaxsessioninitiated']))
    {
        session_regenerate_id();
        $_SESSION['secureajaxsessioninitiated'] = true;
    }

    // The key the server will use when sending back the login challenge text / image
    // this will be split up and randomly seeded in the JavaScript.
    $_SESSION['EXTENDED_LOGIN_ENDODING_KEY'] = sha1(generateKey(20));

    //
    // This function is inserted into the header of the document (top window) when the
    // user attempts to log in. It is encrypted with a random AES key each time the script
    // is sent, so that an attacker can not latch onto it and change it en-route.
    //
    //  the helper function will encrypt every other line, so program keywords that are going
    // to be obfuscated will not be encrypted here, but with the obfuscation routine...
    //
    $executeScriptKey = sha1(generateKey(20));
    $evalFuncStr = array( "function ",
                          "executeScript",
                          "(",
                          "docScrText,callbackFn",
                          "){eval(",
                          "docScrText",
                          ");if(window.secureAjax){window.secureAjax.setReadyCallback(",
                          "callbackFn",
                          ");window.secureAjax.init();}}" );
   //
   // This is the HTML for the popup dialog. It's processed the same way as the above script, with 
   // variables refrenced as {0} - {x} which will be used in a format call to insert later.
   //
   $popupDomStr = array( "<div id='",
                         "{0}_wrapper' ",
                         "class='",
                         "mceWrapper mceFocus'",
                         "><div class='",
                         "mceTop",
                         "' style='zIndex:30006;'><div class='",
                         "mceLeft",
                         "'></div><div class='",
                         "mceCenter",
                         "'></div><div class='",
                         "mceRight",
                         "'></div><span style='padding-left: 10px;'>",
                         "{1}",
                         "</span></div><div class='",
                         "mceMiddle",
                         "'><div class='",
                         "mceLeft",
                         "'></div><span class='",
                         "mceContent",
                         "' style='border:0px none; width:",
                         "{2}",
                         "px; height:", 
                         "{3}",
                         "px;'><iframe id='", 
                         "{0}_detailcontent",
                         "' style='border:0px none; width:",
                         "{2}",
                         "px; height:", 
                         "{3}",
                         "px;' src='about:blank'></iframe></span><div class='",
                         "mceRight",
                         "'></div></div><div class='",
                         "mceBottom",
                         "'><div class='",
                         "mceLeft",
                         "'></div><div class='",
                         "mceCenter",
                         "'></div><div class='",
                         "mceRight",
                         "'></div></div></div>" );
   //
   // The CSS for the above HTML. Again, processed in the same way, with every other string encrypted
   //
   $popupDomCss = array( " ", 
                         ".clearlooks2, .clearlooks2 ",
                         "div, ",
                         ".clearlooks2 ",
                         "span, ",
                         ".clearlooks2 ",
                         "a {vertical-align:baseline; text-align:left; position:absolute; border:0; padding:0; margin:0; background:transparent; font-family:Arial,Verdana; font-size:11px; color:#000; text-decoration:none; font-weight:normal; width:auto; height:auto; overflow:hidden; display:block}",
                         "clearlooks2 ",
                         "{position:absolute; direction:ltr} ",
                         ".clearlooks2 .mceWrapper ",
                         "{position:static} ",
                         ".mceEventBlocker ",
                         "{position:absolute; left:0; top:0; background:url(img/horizontal.gif) no-repeat 0 -75px; width:100%; height:100%}",
                         ".clearlooks2 .mcePlaceHolder ",
                         "{border:1px solid #000; background:#888; top:0; left:0; opacity:0.3; filter:alpha(opacity=30)}",
                         ".clearlooks2_modalBlocker ",
                         "{position:absolute; left:0; top:0; width:100%; height:100%; background:#FFF; opacity:0.3; filter:alpha(opacity=30); display:none}",
                         ".clearlooks2 .mceTop, .clearlooks2 .mceTop ",
                         "div {top:0; width:100%; height:23px}",
                         ".clearlooks2 .mceTop .mceLeft ",
                         "{width:6px; background:url(img/corners.gif)}",
                         ".clearlooks2 .mceTop .mceCenter ",
                         "{right:6px; width:100%; height:23px; background:url(img/horizontal.gif) 12px 0; clip:rect(auto auto auto 12px)}",
                         ".clearlooks2 .mceTop .mceRight ",
                         "{right:0; width:6px; height:23px; background:url(img/corners.gif) -12px 0}",
                         ".clearlooks2 .mceTop span ",
                         "{width:100%; padding-left: 10px; text-align:left; vertical-align:middle; line-height:23px; font-weight:bold}",
                         ".clearlooks2 .mceFocus .mceTop .mceLeft ",
                         "{background:url(img/corners.gif) -6px 0}",
                         ".clearlooks2 .mceFocus .mceTop .mceCenter ",
                         "{background:url(img/horizontal.gif) 0 -23px}",
                         ".clearlooks2 .mceFocus .mceTop .mceRight ",
                         "{background:url(img/corners.gif) -18px 0}",
                         ".clearlooks2 .mceFocus .mceTop ",
                         "span {color:#FFF}",
                         ".clearlooks2 .mceMiddle, .clearlooks2 .mceMiddle",
                         " div {top:0}",
                         ".clearlooks2 .mceMiddle ",
                         "{width:100%; height:100%; clip:rect(23px auto auto auto)}",
                         ".clearlooks2 .mceMiddle .mceLeft ",
                         "{left:0; width:5px; height:100%; background:url(img/vertical.gif) -5px 0}",
                         ".clearlooks2 .mceMiddle ",
                         "span {top:23px; left:5px; width:100%; height:100%; background:#FFF}",
                         ".clearlooks2 .mceMiddle .mceRight ",
                         "{right:0; width:5px; height:100%; background:url(img/vertical.gif)}",
                         ".clearlooks2 .mceMiddle .mceContent ",
                         "span { position: static; display:inline; top:0px; left:0px; width:100%; height:100%; background:#FFFFFF}",
                         ".clearlooks2 .mceMiddle .mceContent ",
                         "div { position: static; display:block; top:0px; left:0px; width:100%; height:100%; background:#FFFFFF}",
                         ".clearlooks2 .mceBottom, .clearlooks2 .mceBottom ",
                         "div {height:6px}",
                         ".clearlooks2 .mceBottom ",
                         "{left:0; bottom:0; width:100%}",
                         ".clearlooks2 .mceBottom ",
                         "div {top:0}",
                         ".clearlooks2 .mceBottom .mceLeft ",
                         "{left:0; width:5px; background:url(img/corners.gif) -34px -6px}",
                         ".clearlooks2 .mceBottom .mceCenter ",
                         "{left:5px; width:100%; background:url(img/horizontal.gif) 0 -46px}",
                         ".clearlooks2 .mceBottom .mceRight ",
                         "{right:0; width:5px; background: url(img/corners.gif) -34px 0}",
                         ".clearlooks2 .mceBottom ",
                         "span {display:none}",
                         ".clearlooks2 .mceStatusbar .mceBottom, .clearlooks2 .mceStatusbar .mceBottom ",
                         "div {height:23px}",
                         ".clearlooks2 .mceStatusbar .mceBottom .mceLeft ",
                         "{background:url(img/corners.gif) -29px 0}",
                         ".clearlooks2 .mceStatusbar .mceBottom .mceCenter ",
                         "{background:url(img/horizontal.gif) 0 -52px}",
                         ".clearlooks2 .mceStatusbar .mceBottom .mceRight ",
                         "{background:url(img/corners.gif) -24px 0}",
                         ".clearlooks2 .mceStatusbar .mceBottom ",
                         "span {display:block; left:7px; font-family:Arial, Verdana; font-size:11px; line-height:23px}" );

   //
   // The Javascript for the popup dialog. Again, processed in the same way, with every other string encrypted
   //
   $popupHelperJS = array(  "<script type='text/javascript'>var ", 
                            "inlinePopup",
                            "={",
                            "init:",
                            "function(){this.win=opener||parent||top;this.",
                            "parameters",
                            "=null;this.isOpera=window.opera&&opera.buildNumber;},",
                            "setWindowArgs",
                            ":function(n){this.",
                            "parameters",
                            "=n;this.",
                            "popupObj",
                            "=this.",
                            "parameters",
                            "['inline_popup_Obj'];},getWindowArg:function(n){return this.",
                            "parameters",
                            "[n];},close:function(){var ",
                            "that",
                            "=this;function close(){",
                            "that.popupObj.close",
                            "();",
                            "that.parameters=that.popupObj",
                            "=null;};if(this.isOpera){this.win.setTimeout(close, 0);}else{close();}}};",
                            "inlinePopup.init()",
                            ";</script>" );

   //
   // This header JavaScript will be at the front of the randomized output. It will always be in this order
   // and at the beginning of the output JavaScript.
   //
   ob_start();
?>
function SecureAjaxLoginObject(){
var that=this;
var ExtendedLoginKey2="<?php print(sha1(generateKey(20)));?>";
var ExtendedLoginKey3="<?php print(chunkString(sha1(generateKey(20))));?>";
var ExtendedLoginKey4="<?php print(sha1(generateKey(20)));?>";
var b64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
String.prototype.decode64=function(a){a=(typeof a=="undefined")?false:a;var b,c,d,e,f,g,h,i,j=[],k,l;l=a?this.decodeUTF8():this;for(var m=0;m<l.length;m+=4){e=b64.indexOf(l.charAt(m));f=b64.indexOf(l.charAt(m+1));g=b64.indexOf(l.charAt(m+2));h=b64.indexOf(l.charAt(m+3));i=e<<18|f<<12|g<<6|h;b=i>>>16&255;c=i>>>8&255;d=i&255;j[m/4]=String.fromCharCode(b,c,d);if(h==64){j[m/4]=String.fromCharCode(b,c)}if(g==64){j[m/4]=String.fromCharCode(b)}}k=j.join("");return a?k.decodeUTF8():k};
<?php

	// Get the header contents from the buffer.
    $generatedHeader = ob_get_contents();
    ob_end_clean();

    //
    // This JavaScript will be randomly re-ordered each time the script is delivered to the client.
    // For the randomizer to work properly, each function needs to be on a line (as it splits the string into an array on newline)
    //
    ob_start();
?>
var ApiUrlStr="secureajax.js.php";
var ScriptNameStr="secureAjaxLogin.js";
var responseStr="cmVzcA==".decode64()+"b25zZQ==".decode64();
var textJavaScriptStr='dGV4dA=='.decode64()+'/'+'amF2YXNjcmlwdA=='.decode64();
var PasswordTextStr=("<?php print(chunkString(base64_encode("Password")))?>").decode64();
String.prototype.decodeBase64=function(msg){var wk4,wk1,wk2,wk3,wk5,wk6,wk7,wk8,wk9=[],wka,wkb;wkb=msg?this.decodeUTF8():this;for(var wkc=0;wkc<wkb.length;wkc+=4){wk3=b64.indexOf(wkb.charAt(wkc));wk5=b64.indexOf(wkb.charAt(wkc+1));wk6=b64.indexOf(wkb.charAt(wkc+2));wk7=b64.indexOf(wkb.charAt(wkc+3));wk8=wk3<<18|wk5<<12|wk6<<6|wk7;wk4=wk8>>>16&0xff;wk1=wk8>>>8&0xff;wk2=wk8&0xff;wk9[wkc/4]=String.fromCharCode(wk4,wk1,wk2);if(wk7==64){wk9[wkc/4]=String.fromCharCode(wk4,wk1)}if(wk6==64){wk9[wkc/4]=String.fromCharCode(wk4)}}wka=joinstub(wk9,"");return msg?wka.decodeUTF8():wka};
String.prototype.encodeBase64=function(msg){var wk4,wk1,wk2,wk3,wk5,wk6,wk7,wk8,wk9=[],wka="",wkb,wkc,wkd;wkc=msg?this.encodeUTF8():this;wkb=wkc.length%3;if(wkb>0){while(wkb++<3){wka+="=";wkc+="\x00"}}for(wkb=0;wkb<wkc.length;wkb+=3){wk4=wkc.charCodeAt(wkb);wk1=wkc.charCodeAt(wkb+1);wk2=wkc.charCodeAt(wkb+2);wk3=wk4<<16|wk1<<8|wk2;wk5=wk3>>18&V63;wk6=wk3>>12&V63;wk7=wk3>>6&V63;wk8=wk3&V63;wk9[wkb/3]=b64.charAt(wk5)+b64.charAt(wk6)+b64.charAt(wk7)+b64.charAt(wk8)}wkd=wk9.join("");wkd=wkd.slice(0,wkd.length-wka.length)+wka;return wkd};
String.prototype.encodeUTF8=function(){var msg=this.replace(/[\u0080-\u07ff]/g,function(wk2){var wk4=wk2.charCodeAt(0);return String.fromCharCode(192|wk4>>6,V128|wk4&V63)});msg=msg.replace(/[\u0800-\uffff]/g,function(wk2){var wk4=wk2.charCodeAt(0);return String.fromCharCode(224|wk4>>12,V128|wk4>>6&V63,V128|wk4&V63)});return msg};
String.prototype.decodeUTF8=function(){var msg=this.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g,function(wk2){var wk3=(wk2.charCodeAt(0)&V31)<<6|wk2.charCodeAt(1)&V63;return String.fromCharCode(wk3)});msg=msg.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,function(wk2){var wk3=((wk2.charCodeAt(0)&V15)<<12)|((wk2.charCodeAt(1)&V63)<<6)|(wk2.charCodeAt(2)&V63);return String.fromCharCode(wk3)});return msg};
String.prototype.StrFormat=function(){var formatted=this;for(var wk1=0;wk1<arraylen(arguments);wk1++){var regexp=new RegExp('\\{'+wk1+'\\}','gi');formatted=formatted.replace(regexp,arguments[wk1]);}return formatted;};
var hexcase=0;
var chrsz=8;
var V15=15;
var V10=0x10;
var Vx40=40;
var V31=31;
var V40=0x40;
var V63=63;
var V128=128;
var V283=283;
var V4294967296=4294967296;
var V909522486=909522486;
var V1549556828=1549556828;
var HexCharStr="0123456789abcdef";
var encrStringSplitToken="*";
var DialogBoxHeight=230;
var DialogBoxWidth=380;
var horizontalGif=("<?php print(chunkString(base64_encode("data:image/gif;base64,R0lGODlhLQBQANUAAAAAAP///yQlJ4KVpYGUpI+hsJOks5eot56vvaKywKa2w6q5xnWJmX2RoYCUpH+To36SooeaqYuercvV3P39/Ozo4Ovn3+rm3vXz7/v6+Pn49u7q4+3p4uzo4evm3url3fPw6/Hu6bOnlff18uzn4PTx7c3DudHIv+/r5/z7+tjPx7WmnD06OAEBAf///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAC4ALAAAAAAtAFAAAAb/wJZwSCwaj8gkZclsOp/QqHRKrVZT2Kx2y+16v5mweEwum89ojXrNbrvf8PhoTq/b7/i8HsPv+/+AgYKDJYWGh4iJiouMII6PkJGSk5SVIZeYmZqbnJ2eH6ChoqOkpaanqKmqqhetrq+wsbKztB62t7i5uru8vRa/wMHCw8TFxiTIycrLzM3OzxXR0tPU1dbX2B3a29zd3t/g4Rzj5OXm5+jp6uvs7e0b8PHy8/T19vci+fr7/P3+/wAFCBxIsKDBgwgTTljIsKHDhxAjSlxAsaLFixgzatyooKPHjyBDihxJMoHJkyhTqlzJsiWClzBjypxJs6bNAzhz6tzJs6fP/58GggodSrSo0aNICyhdyrSp06dQo0qYSrWq1atYs2qNwLWr169gw4od26Cs2bNo06pdy7at27dvIcidS7eu3bt48+rdy5fvg7+AAwseTLiw4cOIEyd2wLix48eQI0ueTKCy5cuYM2vezHmA58+gQ4seTbq06dOoUTNYzbq169ewY8sGQLu27du4c+vevaK379/AgwsfThyF8ePIkytfzry58+fQo0ufPt2E9evYs2vfzr07i+/gw4sfT768+RPo06tfz769+/df4sufn4W6/fv48+vfz7+///8ABijggAQWaOCBCCao4IIMNujggxAKqMKEFFZo4YUYZqiheRx26B4heC6EKOKIJJZo4okopqjiiiy26OKLMMYo44wuBgEAOw==")))?>").decode64(); 
var verticalGif=("<?php print(chunkString(base64_encode("data:image/gif;base64,R0lGODlhCgAOAKIAAO/r5wAAALWmnNzUzP///wAAAAAAAAAAACH5BAAAAAAALAAAAAAKAA4AAAMhKAATQUso5iCQq704tcXUdnUVl5XjKYKeGX7kGsMq/UYJADs=")))?>").decode64(); 
var cornersGif=("<?php print(chunkString(base64_encode("data:image/gif;base64,R0lGODlhJwAXAOZJAO/r5wAAAD06ONjPx////wkJCX2Roe3p4url3YKVpX6Son+To+7q4/Tx7fPw6/f18vXz756vvezn4Ovm3ouerZeot+vn3/Hu6YeaqZOks4+hsMvV3HWJmerm3vn49uzo4ezo4ICUpIGUpM3DuaKywPv6+P39/Ka2w/z7+rWmnLO/yP7+/bO+yPTy7rG9xvLv67OnlfTx7PXy7rK+x/38+7K9x8XP1/n49fj287zG0Pr597rEzrfCzLS/yfv7+vPx7B8lK77I0q24wsjR2bTAycHL1PLw68rT2/j39P///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAEkALAAAAAAnABcAAAf/gEmCggWDhIWGAYZJKQAAAwIBBI4pjQAjAoMFBSaaBRsmm4MbAYqCk4+RqKiXmUkFKyudrxu1JrGItaSCjqmSvb2YryYoxa9HJ8nFKKFJySdHir2Qv8CtrzQl2q9DJN7aJTSF3iRD0o7UrCPrAAIFPh7xHgU2EfYR8h4+BfcRNgHTVPUSQJBgAR0PEj4oUKSCwwoKH+go8LBCEYDoBDqqlqLADQggIQQIkqFkhpAQbhQwmSEIRl+sqgEAgqSBzQYBcmjYqeFmAyRAeGrI8TJdL5kBcDhY6iDADgpQKTB1gCNAVAo7imoEgPTBha8XAvDAQBYD2AsPApTFwEMrUgID7OIGeIGgLoIALgzoNWAXwYsAew24cBuzlGG6dvEG7vs38OCAMhcFMNKhcocANRRoVmC5gxHAm2sQ7iXZwYTTEwLM2KwA9YSmBjbPGO1I8g8LuC0EYLGg94LcFn4A9s2CNgDJMSQol7Db94LlEmIM710cMivkILKDCKAihPcQ2kFIN/BdhXHJDT6o/8BdhHsR6z/gNPDevHXSiVoc2H8gQI8EACbA3wEtBBBgAj2cl9+AARBx4IAFHkiEgoMEIAMDGDIQgBAcdMhBhgzIEICHHAgRQFxxqYKiZBcyAAMMhhn2IoYixlhKQQTZuEggADs=")))?>").decode64(); 
var imgBaseDirName="aW1nLw==".decode64();
var imgTypeSuffix="LmdpZg==".decode64();
var imgHoriz="aG9yaXpvbnRhbA==".decode64();
var imgVert="dmVydGljYWw=".decode64();
var imgCorners="Y29ybmVycw==".decode64();
var basedir=getPopupScriptBase();
var validateStrText="dmFsaWQ9".decode64();
var iframeStrText='aWZyYW1l'.decode64();
var contentTypeHdrStr='Q29udGVudC10eXBl'.decode64();
var contentTypeStr='YXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVk'.decode64();
var contentLenHdrStr='Q29udGVudC1sZW5ndGg='.decode64();
var connectionHdrStr='Q29ubmVjdGlvbg=='.decode64();
var connectionStr='Y2xvc2U='.decode64();
function splitOnAsterisk(wk1){return wk1.split(encrStringSplitToken)}
function getMsgLen2div4(msglen){return msglen/4+2}
function joinstub(msg, glue){return msg.join(glue)}
function arraylen(wk2){return wk2.length}
function getDomDocument(){return document}
function getByTagName(wk1){return getByTagElem(getDomDocument(),wk1)};
function getByTagElem(wk1,wk2){return wk1.getElementsByTagName(wk2)};
function createDomElement(wk1,wk2){return wk1.createElement(wk2)}
function getBody(){return getDomDocument().body}
function appenBodyChild(wk1){return getBody().appendChild(wk1)}
function appenDomChild(wk1,wk2){return wk1.appendChild(wk2)}
var inserttextstr="<?php print(printEncryptOdd($evalFuncStr,$executeScriptKey));?>";
var insertPopupTextStr="<?php print(printEncryptOdd($popupDomStr,$executeScriptKey));?>";
var insertPopupCssStr="<?php print(printEncryptOdd($popupDomCss,$executeScriptKey));?>";
var insertPopupHelperJS="<?php print(printEncryptOdd($popupHelperJS,$executeScriptKey));?>";
function hex_sha1(wk1){return binb2hex(core_sha1(str2binb(wk1),arraylen(wk1)*chrsz))}
function Cipher(wk1,wk3){var wk4=4;var wk5=arraylen(wk3)/wk4-1;var wk7=[[],[],[],[]];for(var wk8=0;wk8<4*wk4;wk8++){wk7[wk8%4][Math.floor(wk8/4)]=wk1[wk8]}wk7=AddRoundKey(wk7,wk3,0,wk4);for(var wk8=1;wk8<wk5;wk8++){wk7=SubBytes(wk7,wk4);wk7=ShiftRows(wk7,wk4);wk7=MixColumns(wk7,wk4);wk7=AddRoundKey(wk7,wk3,wk8,wk4)}wk7=SubBytes(wk7,wk4);wk7=ShiftRows(wk7,wk4);wk7=AddRoundKey(wk7,wk3,wk5,wk4);var wk9=new Array(4*wk4);for(var wk8=0;wk8<4*wk4;wk8++){wk9[wk8]=wk7[wk8%4][Math.floor(wk8/4)]}return wk9}
function SubBytes(wk2,wk1){for(var wk6=0;wk6<4;wk6++){for(var wk5=0;wk5<wk1;wk5++){wk2[wk6][wk5]=Sbox[wk2[wk6][wk5]]}}return wk2}
function ShiftRows(wk2,wk1){var wkc=new Array(4);for(var wk6=1;wk6<4;wk6++){for(var wk5=0;wk5<4;wk5++){wkc[wk5]=wk2[wk6][(wk5+wk6)%wk1]}for(var wk5=0;wk5<4;wk5++){wk2[wk6][wk5]=wkc[wk5]}}return wk2}
function MixColumns(wk2,wk1){for(var wk5=0;wk5<4;wk5++){var wk4=new Array(4);var wk7=new Array(4);for(var wk8=0;wk8<4;wk8++){wk4[wk8]=wk2[wk8][wk5];wk7[wk8]=wk2[wk8][wk5]&V128?wk2[wk8][wk5]<<1^V283:wk2[wk8][wk5]<<1}wk2[0][wk5]=wk7[0]^wk4[1]^wk7[1]^wk4[2]^wk4[3];wk2[1][wk5]=wk4[0]^wk7[1]^wk4[2]^wk7[2]^wk4[3];wk2[2][wk5]=wk4[0]^wk4[1]^wk7[2]^wk4[3]^wk7[3];wk2[3][wk5]=wk4[0]^wk7[0]^wk4[1]^wk4[2]^wk7[3]}return wk2}
function AddRoundKey(wk1,wk3,wk4,wk5){for(var wk6=0;wk6<4;wk6++){for(var wk7=0;wk7<wk5;wk7++){wk1[wk6][wk7]^=wk3[wk4*4+wk7][wk6]}}return wk1}
function KeyExpansion(wk1){var wk2=4;var wk3=arraylen(wk1)/4;var wk4=wk3+6;var wk5=new Array(wk2*(wk4+1));var wk6=new Array(4);for(var wk7=0;wk7<wk3;wk7++){var wk9=[wk1[4*wk7],wk1[4*wk7+1],wk1[4*wk7+2],wk1[4*wk7+3]];wk5[wk7]=wk9}for(var wk7=wk3;wk7<(wk2*(wk4+1));wk7++){wk5[wk7]=new Array(4);for(var wka=0;wka<4;wka++){wk6[wka]=wk5[wk7-1][wka]}if(wk7%wk3==0){wk6=SubWord(RotWord(wk6));for(var wka=0;wka<4;wka++){wk6[wka]^=Rcon[wk7/wk3][wka]}}else{if(wk3>6&&wk7%wk3==4){wk6=SubWord(wk6)}}for(var wka=0;wka<4;wka++){wk5[wk7][wka]=wk5[wk7-wk3][wka]^wk6[wka]}}return wk5}
function SubWord(wk1){for(var wk3=0;wk3<4;wk3++){wk1[wk3]=Sbox[wk1[wk3]]}return wk1}
function RotWord(wk1){var wk2=wk1[0];for(var wk3=0;wk3<3;wk3++){wk1[wk3]=wk1[wk3+1]}wk1[3]=wk2;return wk1}
var Sbox=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22];
var Rcon=[[0,0,0,0],[1,0,0,0],[2,0,0,0],[4,0,0,0],[8,0,0,0],[16,0,0,0],[32,0,0,0],[64,0,0,0],[128,0,0,0],[27,0,0,0],[54,0,0,0]];
function FixBase64Encode(wk1){wk1=wk1.replace(/\-/g,"+");wk1=wk1.replace(/_/g,"/");wk1=wk1.replace(/\,/g,"=");return wk1}
function AESEncryptCtr(wk1,wk2,wk3){var wk4=16;wk1=wk1.encodeUTF8();wk2=wk2.encodeUTF8();var wk6=wk3/chrsz;var wk8=new Array(wk6);for(var wk7=0;wk7<wk6;wk7++){wk8[wk7]=isNaN(wk2.renCharCodeAt(wk7))?0:wk2.renCharCodeAt(wk7)}var wk5=Cipher(wk8,KeyExpansion(wk8));wk5=wk5.concat(wk5.slice(0,wk6-16));var wkb=new Array(wk4);var wkf=(new Date()).getTime();var wkc=Math.floor(wkf/1000);var wke=wkf%1000;for(var wk7=0;wk7<4;wk7++){wkb[wk7]=(wkc>>>wk7*chrsz)&0xff}for(var wk7=0;wk7<4;wk7++){wkb[wk7+4]=wke&0xff}var wkd="";for(var wk7=0;wk7<chrsz;wk7++){wkd+=String.fromCharCode(wkb[wk7])}var wkhj=KeyExpansion(wk5);var wkh=renMathCeil(arraylen(wk1)/wk4);var wkh=new Array(wkh);for(var wkhi=0;wkhi<wkh;wkhi++){for(var wk9=0;wk9<4;wk9++){wkb[V15-wk9]=(wkhi>>>wk9*chrsz)&0xff}for(var wk9=0;wk9<4;wk9++){wkb[V15-wk9-4]=(wkhi/V4294967296>>>wk9*chrsz)}var wkg=Cipher(wkb,wkhj);var wka=wkhi<wkh-1?wk4:(arraylen(wk1)-1)%wk4+1;var wkf=new Array(wka);for(var wk7=0;wk7<wka;wk7++){wkf[wk7]=wkg[wk7]^wk1.renCharCodeAt(wkhi*wk4+wk7);wkf[wk7]=String.fromCharCode(wkf[wk7])}wkh[wkhi]=joinstub(wkf,"")}var wkg=wkd+joinstub(wkh,"");wkg=wkg.encodeBase64();return wkg}
function AESDecryptCtr(wk1,wk2,wk3){var wk4=chrsz+chrsz;wk1=FixBase64Encode(wk1);wk1=wk1.decodeBase64();wk2=wk2.encodeUTF8();var wk6=wk3/chrsz;var wk8=new Array(wk6);for(var wk7=0;wk7<wk6;wk7++){wk8[wk7]=isNaN(wk2.renCharCodeAt(wk7))?0:wk2.renCharCodeAt(wk7)}var wk5=Cipher(wk8,KeyExpansion(wk8));wk5=wk5.concat(wk5.slice(0,wk6-16));var wkb=new Array(chrsz);var ctrTxt=wk1.slice(0,chrsz);for(var wk7=0;wk7<chrsz;wk7++){wkb[wk7]=ctrTxt.renCharCodeAt(wk7)}var wkf=KeyExpansion(wk5);var wkc=renMathCeil((arraylen(wk1)-chrsz)/wk4);var wke=new Array(wkc);for(var wkd=0;wkd<wkc;wkd++){wke[wkd]=wk1.slice(chrsz+wkd*wk4,chrsz+wkd*wk4+wk4)}wk1=wke;var wkhj=new Array(arraylen(wk1));for(var wkd=0;wkd<wkc;wkd++){for(var wkh=0;wkh<4;wkh++){wkb[V15-wkh]=((wkd)>>>wkh*chrsz)&0xff}for(var wkh=0;wkh<4;wkh++){wkb[V15-wkh-4]=(((wkd+1)/V4294967296-1)>>>wkh*chrsz)&0xff}var wkh=Cipher(wkb,wkf);var wkhi=new Array(arraylen(wk1[wkd]));for(var wk7=0;wk7<arraylen(wk1[wkd]);wk7++){wkhi[wk7]=wkh[wk7]^wk1[wkd].renCharCodeAt(wk7);wkhi[wk7]=String.fromCharCode(wkhi[wk7])}wkhj[wkd]=joinstub(wkhi,"")}var wk9=joinstub(wkhj,"");wk9=wk9.decodeUTF8();return wk9}
var usrStrText="dXNlcj0=".decode64();
function initJSInsert(){var headerDomObj=getByTagName('aGVhZA=='.decodeBase64())[0];var newScriptObj=createDomElement(getDomDocument(),'c2NyaXB0'.decodeBase64());newScriptObj.setAttribute("type",textJavaScriptStr);newScriptObj.text=processString(inserttextstr);headerDomObj.insertBefore(newScriptObj,null);}
function safe_add(wk7,wk8){var wk1=(wk7&65535)+(wk8&65535);var wk3=(wk7>>16)+(wk8>>16)+(wk1>>16);return (wk3<<16)|(wk1&65535)}
function rol(wk2,wk3){return (wk2<<wk3)|(wk2>>>(32-wk3))}
function toHexStr(cryptext){var chrsz="",wk3;for(var wk2=7;wk2>=0;wk2--){wk3=(cryptext>>>(wk2*4))&0xf;chrsz+=wk3.toString(16);}return chrsz;}
function ROTR(wk2,wk3){return(wk3>>>wk2)|(wk3<<(32-wk2));}
function Sigma0(wk3){return ROTR(2,wk3)^ROTR(13,wk3)^ROTR(22,wk3);}
function Sigma1(wk4){return ROTR(6,wk4)^ROTR(11,wk4)^ROTR(25,wk4);}
function sigma0(wk4){return ROTR(7,wk4)^ROTR(18,wk4)^(wk4>>>3);}
function sigma1(wk5){return ROTR(17,wk5)^ROTR(19,wk5)^(wk5>>>10);}
function Ch2(wk5,wk4,wk3){return(wk5&wk4)^(~wk5&wk3);}
function Maj(wk5,wk4,wk3){return(wk5&wk4)^(wk5&wk3)^(wk4&wk3);}
function addCharCode(){return String.fromCharCode(0x80);}
function getMsgLength(cryptext){return arraylen(cryptext);}
var Konstants=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
var InitHashTable = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
function hexSHA256(msg){msg=msg.encodeUTF8()+addCharCode();var msglen=getMsgLength(msg);var msgln2=getMsgLen2div4(msglen);var NumBlocks=renMathCeil(msgln2/V10);var MsgBlocks=prepareMsgBlks(NumBlocks,msg,msglen);var HashTable=renSlice(InitHashTable,0);var MsgSched=new Array(V40);var wk1,wk2,wk3,wk4,wk5,wk6,wk7,wk8;for(var indx=0;indx<NumBlocks;indx++){for(var innridx=0;innridx<V10;innridx++){MsgSched[innridx]=MsgBlocks[indx][innridx]}for(var innridx=V10;innridx<V40;innridx++){MsgSched[innridx]=limitPrm(sigma1(MsgSched[innridx-2])+MsgSched[innridx-7]+sigma0(MsgSched[innridx-V15])+MsgSched[innridx-16])}wk1=HashTable[0];wk2=HashTable[1];wk3=HashTable[2];wk4=HashTable[3];wk5=HashTable[4];wk6=HashTable[5];wk7=HashTable[6];wk8=HashTable[7];for(var wk9=0;wk9<V40;wk9++){var TMP1=wk8+Sigma1(wk5)+Ch2(wk5,wk6,wk7)+Konstants[wk9]+MsgSched[wk9];var TMP2=Sigma0(wk1)+Maj(wk1,wk2,wk3);wk8=wk7;wk7=wk6;wk6=wk5;wk5=limitPrm(wk4+TMP1);wk4=wk3;wk3=wk2;wk2=wk1;wk1=limitPrm(TMP1+TMP2)}HashTable[0]=limitPrm(HashTable[0]+wk1);HashTable[1]=limitPrm(HashTable[1]+wk2);HashTable[2]=limitPrm(HashTable[2]+wk3);HashTable[3]=limitPrm(HashTable[3]+wk4);HashTable[4]=limitPrm(HashTable[4]+wk5);HashTable[5]=limitPrm(HashTable[5]+wk6);HashTable[6]=limitPrm(HashTable[6]+wk7);HashTable[7]=limitPrm(HashTable[7]+wk8)}return toHexStr(HashTable[0])+toHexStr(HashTable[1])+toHexStr(HashTable[2])+toHexStr(HashTable[3])+toHexStr(HashTable[4])+toHexStr(HashTable[5])+toHexStr(HashTable[6])+toHexStr(HashTable[7])};
function renMathPow(wk1,wk2){return Math.pow(wk1,wk2)};
function renMathCeil(wk1){return Math.ceil(wk1)};
String.prototype.renCharCodeAt=function(wk1){return this.charCodeAt(wk1)};
function prepareMsgBlks(NumBlocks,msg,msglen){var MsgBlocks=new Array(NumBlocks);for(var indx=0;indx<NumBlocks;indx++){MsgBlocks[indx]=new Array(V10);for(var innridx=0;innridx<V10;innridx++){MsgBlocks[indx][innridx]=(msg.renCharCodeAt(indx*V40+innridx*4)<<24)|(msg.renCharCodeAt(indx*V40+innridx*4+1)<<V10)|(msg.renCharCodeAt(indx*V40+innridx*4+2)<<chrsz)|(msg.renCharCodeAt(indx*V40+innridx*4+3))}}MsgBlocks[NumBlocks-1][14]=((msglen-1)*chrsz)/renMathPow(2,32);MsgBlocks[NumBlocks-1][14]=Math.floor(MsgBlocks[NumBlocks-1][14]);MsgBlocks[NumBlocks-1][V15]=limitPrm((msglen-1)*chrsz);return MsgBlocks;};
function limitPrm(wk2){return wk2&0xffffffff;};
function renSlice(InitHashTable,wk3){return InitHashTable.slice(wk3)};
function str2binb(wk1){var wk2=Array();var wk4=(1<<chrsz)-1;for(var wk3=0;wk3<arraylen(wk1)*chrsz;wk3+=chrsz){wk2[wk3>>5]|=(wk1.charCodeAt(wk3/chrsz)&wk4)<<(32-chrsz-wk3%32)}return wk2}
function binb2hex(wk1){var wk2=HexCharStr;var wk4="";for(var wk3=0;wk3<arraylen(wk1)*4;wk3++){wk4+=wk2.charAt((wk1[wk3>>2]>>((3-wk3%4)*chrsz+4))&V15)+wk2.charAt((wk1[wk3>>2]>>((3-wk3%4)*chrsz))&V15)}return wk4}
function createXHRObject(){if (typeof XMLHttpRequest!="undefined"){return new XMLHttpRequest();}else if(typeof ActiveXObject!="undefined"){return new ActiveXObject("Microsoft.XMLHTTP");}else{throw new Error("XMLHttpRequest not supported");}}
function getTextNode(element){var returnedText="";if(element){if(element.textContent){returnedText=element.textContent;}else if(element.text){returnedText=element.text;}}if(returnedText.indexOf("[CDATA[")>-1){returnedText=returnedText.substring(7);}if(returnedText.lastIndexOf("]]")>-1){returnedText=returnedText.substring(0,returnedText.lastIndexOf("]]"));}return returnedText;}
function sendAjaxRequest(applName,params,callbackFn){var xhrObject=createXHRObject();xhrObject.open("POST",applName,true);xhrObject.onreadystatechange=function(){if (xhrObject.readyState==4){if(xhrObject.responseXML!=null){callbackFn(xhrObject.responseXML);}}};xhrObject.setRequestHeader(contentTypeHdrStr,contentTypeStr);xhrObject.setRequestHeader(contentLenHdrStr,arraylen(params));xhrObject.setRequestHeader(connectionHdrStr,connectionStr);xhrObject.send(params);}
function decryptJavascript(cryptext,password){cryptext=FixBase64Encode(cryptext);var pwl=arraylen(password);var padText=cryptext.substr(0,pwl);password=password+padText;cryptext=cryptext.substr(pwl);var key=hexSHA256(password);for(var wk1=0;wk1<Vx40*pwl;++wk1)key=hexSHA256(key);return AESDecryptCtr(cryptext,key,256);}
function getPopupScriptBase(scriptname){var scriptObjs=getByTagName("script");for(var idx=0;idx<arraylen(scriptObjs);++idx){if(scriptObjs[idx]&&scriptObjs[idx].src&&scriptObjs[idx].src.indexOf(ScriptNameStr)>-1){var index=scriptObjs[idx].src.indexOf(ScriptNameStr);var baseUrl="";if(index>0){baseUrl=scriptObjs[idx].src.substring(0,index);}return baseUrl;}}}
ExtendedLoginKey3+="<?php print(chunkString(sha1(generateKey(20))));?>";
function getRandomDomItem(){var domElementList=[];var nodeList=getByTagName("div");for(var i=0, ll=arraylen(nodeList);i!=ll;domElementList.push(nodeList[i++]));nodeList=getByTagName("span");for(i=0,ll=arraylen(nodeList);i!=ll;domElementList.push(nodeList[i++]));nodeList=getByTagName("p");for(i=0,ll=arraylen(nodeList);i!=ll;domElementList.push(nodeList[i++]));var randomnumber=Math.floor(Math.random()*arraylen(domElementList));return domElementList[randomnumber];}
function insertAfterDom(newElement,targetElement){var parentDomNode = targetElement.parentNode;if(parentDomNode.lastchild==targetElement){appenDomChild(parentDomNode,newElement);}else{parentDomNode.insertBefore(newElement, targetElement.nextSibling);}}
function prepareCssImages(){var ClerLooks2Style=processString(insertPopupCssStr);ClerLooks2Style.replace(imgBaseDirName+imgHoriz+imgTypeSuffix,horizontalGif);ClerLooks2Style.replace(imgBaseDirName+imgVert+imgTypeSuffix,verticalGif);ClerLooks2Style.replace(imgBaseDirName+imgCorners+imgTypeSuffix,cornersGif);return ClerLooks2Style}
function LoginPopup(wk1,wk2,wk3,wk4,wk5,contentHtml,parameters){var that=this;var ClerLooks2Style=prepareCssImages();var styleElement=createDomElement(getDomDocument(),'style');styleElement.setAttribute("type","text/css");styleElement.setAttribute("id","clearlooks2");if(styleElement.styleSheet){styleElement.styleSheet.cssText=ClerLooks2Style;}else{appenDomChild(styleElement,getDomDocument().createTextNode(ClerLooks2Style));}appenDomChild(getByTagName('head')[0],styleElement);var popupDiv=createDomElement(getDomDocument(),"div");popupDiv.id="mce_login";popupDiv.className="clearlooks2";popupDiv.style.overflow="auto";popupDiv.style.left=wk1+"px";popupDiv.style.top=wk2+"px";popupDiv.style.width=wk3+"px";popupDiv.style.height=wk4+"px";popupDiv.style.zIndex=30005;insertAfterDom(popupDiv,getRandomDomItem());var mdlbkrdv=createDomElement(getDomDocument(),"div");mdlbkrdv.id='inlinepopups_modalblocker';mdlbkrdv.className='clearlooks2_modalBlocker';mdlbkrdv.style.display='none';mdlbkrdv.style.zIndex=parseInt(popupDiv.style.zIndex)-1;appenBodyChild(mdlbkrdv);parameters.inline_popup_Obj=that;popupDiv.innerHTML=processString(insertPopupTextStr).StrFormat(popupDiv.id,wk5,(wk3-10),(wk4-29));var helperJs=processString(insertPopupHelperJS);var idx=contentHtml.indexOf('</head>');if(idx>0){contentHtml=contentHtml.substring(0,idx)+helperJs+contentHtml.substring(idx);}else{contentHtml="<head>"+helperJs+"</head>";}setTimeout( function(){var pcntw=getByTagElem(popupDiv,iframeStrText)[0].contentWindow;pcntw.document.write(contentHtml);pcntw.inlinePopup.setWindowArgs(parameters);}, 500 );this.show=function(){popupDiv.style.display = 'block';mdlbkrdv.style.display = 'block';};this.close=function(){popupDiv.style.display = 'none';mdlbkrdv.style.display = 'none';popupDiv.parentNode.removeChild(popupDiv);mdlbkrdv.parentNode.removeChild(mdlbkrdv);}};
function doDummyMethod1(username,password2,callbackFn){var that=this;var cryptext=getTextNode(getByTagElem(username,password2)[0]);var rstxt=AESDecryptCtr(cryptext,ExtendedLoginKey3,512);callbackFn(rstxt);};
function doDummyMethod2(username,password3,callbackFn){var that=this;var cryptext=getTextNode(getByTagElem(username,password3)[0]);var rstxt=AESDecryptCtr(cryptext,ExtendedLoginKey3,512);callbackFn(rstxt);};
function doLogin(username,password,callbackFn){sendAjaxRequest(ApiUrlStr,usrStrText+username,function(DocVerStr){if(getByTagElem(DocVerStr,responseStr)[0]){var docScrText=decryptJavascript(getTextNode(getByTagElem(DocVerStr,responseStr)[0]),password);if(docScrText.indexOf(textJavaScriptStr)>0){executeScript(docScrText,callbackFn);}else{callbackFn(false);}}else{callbackFn(false);}});};
function doLoginEx(wk1,wk2,username,callbackFn){sendAjaxRequest(ApiUrlStr,validateStrText+username,function(DocVerStr){loginAjaxCallback(wk1,wk2,DocVerStr,callbackFn);});}
<?php

	// get the buffer contents
    $generatedBody = ob_get_contents();
    ob_end_clean();

    //
    // And this last little bit of script is always at the end, and in order.
    //
    ob_start();
?>
var ExtendedLoginKey5="<?php print(sha1(generateKey(20)));?>";
this.loginEx=function(wk1,wk2,username,callbackFn){initJSInsert();doLoginEx(wk1,wk2,username,callbackFn);};
}window.top.secureAjaxLogin=new SecureAjaxLoginObject();
<?php
	// Get the buffer contents.
    $generatedFooter = ob_get_contents();
    ob_end_clean();


    //
    // Now, we want to take the middle section of JavaScript, break it into an array, and then re-order it randomly.
    //
    $jsLinesArray = explode("\n",$generatedBody);
    shuffle($jsLinesArray);


    //
    // now, some parts HAVE to be inserted in order... let's do those here...
    //
    $insPt = rand(5, count($jsLinesArray)/2 -1 );
    array_splice($jsLinesArray, $insPt, 0, "var ExtendedLoginKey4=\"\";");

    $insPt = rand($insPt+3, count($jsLinesArray)-10 );
    array_splice($jsLinesArray, $insPt, 0, "ExtendedLoginKey4+=\"".chunkString(substr($executeScriptKey,0,20) )."\";");

    $insPt = rand($insPt+3, count($jsLinesArray)-5 );
    array_splice($jsLinesArray, $insPt, 0, "ExtendedLoginKey4+=\"".chunkString(substr($executeScriptKey,20) )."\";");

    $insPt = rand($insPt+1, count($jsLinesArray)-1 );
    array_splice($jsLinesArray, $insPt, 0, "function processString(cryptext){var StringParts=splitOnAsterisk(cryptext);var returnedText='';for(var i=0;i<arraylen(StringParts);i++){if(i%2==0){returnedText+=AESDecryptCtr(StringParts[i],ExtendedLoginKey4,256);}else{returnedText+=StringParts[i];}}return returnedText;}");

    $insPt = rand(5, count($jsLinesArray)/2 -1 );
    array_splice($jsLinesArray, $insPt, 0, "var ExtendedLoginKey2=\"\";");

    $insPt = rand($insPt+3, count($jsLinesArray)-10 );
    array_splice($jsLinesArray, $insPt, 0, "ExtendedLoginKey2+=\"".chunkString(substr($_SESSION['EXTENDED_LOGIN_ENDODING_KEY'],0,20) )."\";");

    $insPt = rand($insPt+3, count($jsLinesArray)-5 );
    array_splice($jsLinesArray, $insPt, 0, "ExtendedLoginKey2+=\"".chunkString(substr($_SESSION['EXTENDED_LOGIN_ENDODING_KEY'],20) )."\";");

    $insPt = rand($insPt+2, count($jsLinesArray)-1 );

    //
    // This code contains the callback functions for the login popup. They will be randomized as well (by themselves) and inserted into the script.
    // Note there is extra "dummy" code inserted in these methods that are not used. This is to confuse anyone trying to piece together the script, so
    // the lines look almost exactly the same when obfuscated.
    //
    $strings= array('logincallback:function(username,password1){if(password1!=null&&password1!=""){doLogin(username,password1,callbackFn);}else{callbackFn(false);}},',
                   'cancelcallback:function(username,password2){if(password2!=null&&password2!=""){doDummyMethod1(username,password2,callbackFn);}else{callbackFn(false);}callbackFn(false);},',
                   'dummycallback:function(username,password3){if(password3!=null&&password3!=""){doDummyMethod1(username,password3,callbackFn);}else{callbackFn(false);}callbackFn(false);},');

    $loginLine = "function loginAjaxCallback(popuplocx,popuplocy,DocVerStr,callbackFn){if(getByTagElem(DocVerStr,responseStr)[0]){var cryptext=getTextNode(getByTagElem(DocVerStr,responseStr)[0]);var rstxt=AESDecryptCtr(cryptext,ExtendedLoginKey2,256);var newPopup=new LoginPopup(popuplocx,popuplocy,DialogBoxWidth,DialogBoxHeight,PasswordTextStr,rstxt,{";
    $loginLine .= printRandom($strings);
    $loginLine .= "});newPopup.show();}};";

    array_splice($jsLinesArray, $insPt, 0, $loginLine);


     //
     // Now, create the final output string with all the parts put together...
     //
    $generatedoutput = $generatedHeader . implode("\n",$jsLinesArray) ."\n". $generatedFooter;

    //
    // Obfuscate the JavaScript code above, changing function and variable names to random strings
    //

    //
    // this is the list of key words that we will randomly change:
    //
    $keywords = array( "that","Cipher","SubBytes","Sbox","ShiftRows","MixColumns","AddRoundKey","ExtendedLoginKey2","ExtendedLoginKey3","ExtendedLoginKey4","docScrText","InitHashTable","DialogBoxHeight","DialogBoxWidth","StrFormat","formatted","regexp",
                       "KeyExpansion","SubWord","RotWord","Rcon","AESEncryptCtr","AESDecryptCtr","encodeBase64","decode64","decodeBase64","newPopup","newPopup","usrStrText","StringParts","b64","ExtendedLoginKey5","_wrapper","_detailcontent","insertPopupCssStr",
                       "encodeUTF8","decodeUTF8","hexcase","chrsz","hex_sha1","binb2hex","core_sha1","sha1_ft","newSS","responseStr","password1","iframeStrText","loginAjaxCallback","initJSInsert","createDomElement","HexCharStr","insertPopupTextStr",
                       "sha1_kt","core_hmac_sha1","str2binb","safe_add","rol","str2bin","binb2str","binb2hex","padText","textJavaScriptStr","SecureAjaxLoginObject","popuplocx","popuplocy","processString","pwl","V1549556828","getByTagElem","prepareCssImages",
                       "createXHRObject","getTextNode","element","returnedText","sendAjaxRequest","applName","mce_login","PasswordTextStr","doDummyMethod1","doDummyMethod2","logincallbackFn","getDomDocument","appenBodyChild","encrStringSplitToken","V128",
                       "params","callbackFn","xhrObject","decryptJavascript","cryptext","password","basedir","inlinepopups_modalblocker","validateStrText","password2","password3","executeScript","getByTagName","getBody","V4294967296","V15","V31","V63",
                       "getPopupScriptBase","scriptname","scriptObjs","baseUrl","LoginPopup","contentHtml","parameters","detailcontent","evalcallback","inserttextstr","headerDomObj","newScriptObj","rstxt","arraylen","appenDomChild","splitOnAsterisk",
                       "popupDiv","mdlbkrdv","helperJs","pcntw","doLoginEx","username","doLogin","ApiUrlStr","ScriptNameStr","DocVerStr","logincallback","cancelcallback","dummycallback","insertAfterDom","FixBase64Encode","V283","V909522486","inlinePopup",
                       "newElement","targetElement","parentDomNode","getRandomDomItem","domElementList","nodeList","randomnumber","ClerLooks2Style","clearlooks2","mceWrapper", "mceEventBlocker","getMsgLen2div4","V10","V40","Vx40","joinstub","glue",
                       "mcePlaceHolder", "clearlooks2_modalBlocker","mceTop", "mceLeft", "mceCenter", "mceRight", "mceFocus", "mceMiddle", "mceContent", "mceBottom", "mceStatusbar","horizontalGif","verticalGif","cornersGif","renSlice","_modalBlocker",
                       "toHexStr","ROTR","Sigma0","Sigma1","sigma0","sigma1","Ch2","Maj","hash","msg","utf8encode","hexSHA256","HashTable","NumBlocks","Konstants","key","ctrTxt","renMathPow","renMathCeil","renCharCodeAt","prepareMsgBlks","limitPrm",
                       "MsgBlocks","indx","innridx","MsgSched","TMP1","TMP2","wk1","wk2","wk3","wk4","wk5","wk6","wk7","wk8","wk9","wka","wkb","wkc","wkd","wke","wkf","wkg","wkhi","wkhj","msglength","rounds","addCharCode","getMsgLength",
                       "imgBaseDirName","imgTypeSuffix","imgHoriz","imgVert","imgCorners","insertPopupHelperJS","init","popupObj","setWindowArgs","show","close","contentTypeHdrStr","contentTypeStr","contentLenHdrStr","connectionHdrStr","connectionStr");

    //
    // Now, for each keyword, generate a unique 6 digit hexidecimal name
    //
    $originalOutput = $generatedoutput;  // Keep a copy of the original just for debugging purposes...

    // For each keyword above, generate a rancom 6 digit hex string. Place them into a hash. (start each one with a known character to satisfy PHP naming rules)
    $encodedSet["v".generateKey(8)] = true;
    while( count($encodedSet) < count($keywords) )
    {
        $nextKey = "v".generateKey(rand(3,8));
        if( !isSet($encodedSet[$nextKey] ) )
        {
            $encodedSet[$nextKey] = true;
        }
    }

	// Go through the key set, and associate each entry with a keyword.
    $idx = 0;
    foreach (array_keys($encodedSet) as $key)
    {
        $encodedSet[$key] = $keywords[$idx];

        $idx++;
    }

    //
    // These need to be called by the login popup Javascript, and need to be known to the
    // program that generates that code... So, save the obfuscated names of these.
    //
    $_SESSION["logincallback"] = array_search("logincallback",$encodedSet);
    $_SESSION["cancelcallback"] = array_search("cancelcallback",$encodedSet);
    $_SESSION["inlinePopup"] = array_search("inlinePopup",$encodedSet);
    

    //
    // Now, go through and make the substitutions.
    //
    foreach ($encodedSet as $encoded => $original)
    {
       $generatedoutput = str_replace($original,$encoded,$generatedoutput);
    }

    //
    // Now, compress the generated output...
    //
    $packer = new JavaScriptPacker($generatedoutput, 62, true, false);
    $packed = $packer->pack();

    //
    // Finally print it out for consumption...
    //
    print $generatedoutput;

    //
    //  --------- Helper Functions ------------
    //

    /**
     * Split the input string into chunks of 5 characters, each separated as strings to be concatenated together.
     * This is so that the compactor moves them around in small chunks in strange places to make it harder to hack.
     *
     * @param inputString - String: The string to be split into chunks
     * @return String - The input string, split into chunks of 5 characters, with JS code to concatenate them together.
     */
    function chunkString( $inputString )
    {
        $outputStr = "";
        for($idx = 0; $idx < strlen( $inputString ); $idx += 5 )
        {
            $outputStr .= substr($inputString, $idx, 5) . "\"+\"";
        }
        return $outputStr;
    }

	/**
	 * Returns a string containing all of the lines of in lineList in a random order.
	 *
	 * @param lineList - Array: The lines that are to be concatentated together in random order.
	 * @return String - ALL of the lines in lineList, rearranged randomly, and concatenated together
	 */
    function printRandom( $lineList )
    {
        $outputStr = "";

        while( count( $lineList ) > 0 )
        {
            $currLine = getShift( $lineList, rand(0, count($lineList)-1) );
            $outputStr = $outputStr . $currLine;
        }

        return $outputStr;
    }

	/**
	 * Remove and return a given line from the passed in array.
	 *
	 * @param array - Array (i/o): The array that will have the line removed and returned.
	 * @param index - Integer: The index of the above array to remove and return.
	 * @return: String - The line taken out of the passed in array.
	 */
    function getShift( &$array, $index )
    {
        $value = $array[$index];
        unset($array[$index]);
        $array = array_values($array);

        return $value;
    }

	/**
	 * Encrypts every other line in an input array, and returns the concatenated string.
	 * An asterisk is used as an indicator for the line end (it should seem innocuous).
     *
     * @param lineList - Array: The input strings. This will be JavaScript code that will be semi-encrypted.
     * @param key - String: The AES encryption key to use.
     * @return String - The returned line list, each other line encrypted, and concatenated together.
	 */
    function printEncryptOdd( $lineList, $key )
    {
      $outputStr = "";
      for($idx = 0;$idx < count( $lineList ); ++$idx )
      {
        if($idx%2 == 0)
        {
          $outputStr .= AESEncryptCtr($lineList[$idx], $key, 256) . "*";
        }
        else
        {
          $outputStr .= $lineList[$idx] . "*";
        }
      }

       return $outputStr;
    }

?>
