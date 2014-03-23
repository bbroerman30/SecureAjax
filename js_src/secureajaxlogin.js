//
// Secure Ajax Layer Copyright (c) 2008 - 2009 Brad Broerman. bbroerman@bbroerman.net released under the LGPL 2.1 license
// BigInt library Copyright 1998-2005 David Shapiro. dave@ohdave.com
// RSA Javascript library Copyright 1998-2005 David Shapiro. dave@ohdave.com
// SHA-1 Javascript library Copyright Paul Johnston 2000 - 2002.
// Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
// Distributed under the BSD License See http://pajhome.org.uk/crypt/md5 for details. */
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

function SecureAjaxLoginObject() {

	var that=this;

	// The API to call to receive the SecureAjax script
	var ApiUrlStr = "secureajax.js.php";

	// The name of this script.
	var ScriptNameStr = "secureAjaxLogin.js";

	// These are broken up and made variables to make it harder to find in the compacted script.
	var responseStr = "resp"+"onse";
	var textJavaScriptStr = 'text/ja'+'vascript';
	var PasswordTextStr = "Pas"+"sword";

	// These are *possible* keys to use for decrypting the login popup code (which includes the eval)
	// There are extras here, and one is even chunked to distract and confuse an attacker.
	// Key 2 will be re-inserted in the randomized output, and will eventually be the real key.
	var ExtendedLoginKey2 = "<?php print(sha1(generateKey(20)));?>";
	var ExtendedLoginKey3 = "<?php print(chunkString(sha1(generateKey(20))));?>";
	var ExtendedLoginKey4 = "<?php print(sha1(generateKey(20)));?>";

	// Thesd scrings are base64 encoded so they're harder to find. More misdirection.
	var usrStrText = "dXNlcj0=".decodeBase64();
	var validateStrText = "dmFsaWQ9".decodeBase64();
	var iframeStrText = 'aWZyYW1l'.decodeBase64();

	// This takes the eval script and holds it in an encrypted and chunked format.
	var inserttextstr = "<?php print(printEncryptOdd($evalFuncStr,$executeScriptKey));?>";

	// Holds the base location of the script (taken from the script tag itself.
	var basedir = getPopupScriptBase();

	// Another extra key to misdirect attackers
	var ExtendedLoginKey5 = "<?php print(sha1(generateKey(20)));?>";

	// Adding more pieces to one of the dummy login keys.
	ExtendedLoginKey3 += "<?php print(chunkString(sha1(generateKey(20))));?>";

	// The images for the ClearLooks2 Style sheet. These are Base64 encoded and converted into Data URIs for insertion.
	var horizontalGif = "data:image/gif;base64,R0lGODlhLQBQANUAAAAAAP///yQlJ4KVpYGUpI+hsJOks5eot56vvaKywKa2w6q5xnWJmX2RoYCUpH+To36SooeaqYuercvV3P39/Ozo4Ovn3+rm3vXz7/v6+Pn49u7q4+3p4uzo4evm3url3fPw6/Hu6bOnlff18uzn4PTx7c3DudHIv+/r5/z7+tjPx7WmnD06OAEBAf///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAC4ALAAAAAAtAFAAAAb/wJZwSCwaj8gkZclsOp/QqHRKrVZT2Kx2y+16v5mweEwum89ojXrNbrvf8PhoTq/b7/i8HsPv+/+AgYKDJYWGh4iJiouMII6PkJGSk5SVIZeYmZqbnJ2eH6ChoqOkpaanqKmqqhetrq+wsbKztB62t7i5uru8vRa/wMHCw8TFxiTIycrLzM3OzxXR0tPU1dbX2B3a29zd3t/g4Rzj5OXm5+jp6uvs7e0b8PHy8/T19vci+fr7/P3+/wAFCBxIsKDBgwgTTljIsKHDhxAjSlxAsaLFixgzatyooKPHjyBDihxJMoHJkyhTqlzJsiWClzBjypxJs6bNAzhz6tzJs6fP/58GggodSrSo0aNICyhdyrSp06dQo0qYSrWq1atYs2qNwLWr169gw4od26Cs2bNo06pdy7at27dvIcidS7eu3bt48+rdy5fvg7+AAwseTLiw4cOIEyd2wLix48eQI0ueTKCy5cuYM2vezHmA58+gQ4seTbq06dOoUTNYzbq169ewY8sGQLu27du4c+vevaK379/AgwsfThyF8ePIkytfzry58+fQo0ufPt2E9evYs2vfzr07i+/gw4sfT768+RPo06tfz769+/df4sufn4W6/fv48+vfz7+///8ABijggAQWaOCBCCao4IIMNujggxAKqMKEFFZo4YUYZqiheRx26B4heC6EKOKIJJZo4okopqjiiiy26OKLMMYo44wuBgEAOw==";
	var verticalGif   = "data:image/gif;base64,R0lGODlhCgAOAKIAAO/r5wAAALWmnNzUzP///wAAAAAAAAAAACH5BAAAAAAALAAAAAAKAA4AAAMhKAATQUso5iCQq704tcXUdnUVl5XjKYKeGX7kGsMq/UYJADs=";
	var cornersGif    = "data:image/gif;base64,R0lGODlhJwAXAOZJAO/r5wAAAD06ONjPx////wkJCX2Roe3p4url3YKVpX6Son+To+7q4/Tx7fPw6/f18vXz756vvezn4Ovm3ouerZeot+vn3/Hu6YeaqZOks4+hsMvV3HWJmerm3vn49uzo4ezo4ICUpIGUpM3DuaKywPv6+P39/Ka2w/z7+rWmnLO/yP7+/bO+yPTy7rG9xvLv67OnlfTx7PXy7rK+x/38+7K9x8XP1/n49fj287zG0Pr597rEzrfCzLS/yfv7+vPx7B8lK77I0q24wsjR2bTAycHL1PLw68rT2/j39P///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAEkALAAAAAAnABcAAAf/gEmCggWDhIWGAYZJKQAAAwIBBI4pjQAjAoMFBSaaBRsmm4MbAYqCk4+RqKiXmUkFKyudrxu1JrGItaSCjqmSvb2YryYoxa9HJ8nFKKFJySdHir2Qv8CtrzQl2q9DJN7aJTSF3iRD0o7UrCPrAAIFPh7xHgU2EfYR8h4+BfcRNgHTVPUSQJBgAR0PEj4oUKSCwwoKH+go8LBCEYDoBDqqlqLADQggIQQIkqFkhpAQbhQwmSEIRl+sqgEAgqSBzQYBcmjYqeFmAyRAeGrI8TJdL5kBcDhY6iDADgpQKTB1gCNAVAo7imoEgPTBha8XAvDAQBYD2AsPApTFwEMrUgID7OIGeIGgLoIALgzoNWAXwYsAew24cBuzlGG6dvEG7vs38OCAMhcFMNKhcocANRRoVmC5gxHAm2sQ7iXZwYTTEwLM2KwA9YSmBjbPGO1I8g8LuC0EYLGg94LcFn4A9s2CNgDJMSQol7Db94LlEmIM710cMivkILKDCKAihPcQ2kFIN/BdhXHJDT6o/8BdhHsR6z/gNPDevHXSiVoc2H8gQI8EACbA3wEtBBBgAj2cl9+AARBx4IAFHkiEgoMEIAMDGDIQgBAcdMhBhgzIEICHHAgRQFxxqYKiZBcyAAMMhhn2IoYixlhKQQTZuEggADs=";

	// The style definition for the login popup. This can be redefined by the user if they wish to later on.
	var ClerLooks2Style = ".clearlooks2, .clearlooks2 div, .clearlooks2 span, .clearlooks2 a {vertical-align:baseline; text-align:left; position:absolute; border:0; padding:0; margin:0; background:transparent; font-family:Arial,Verdana; font-size:11px; color:#000; text-decoration:none; font-weight:normal; width:auto; height:auto; overflow:hidden; display:block} " + 
												".clearlooks2 {position:absolute; direction:ltr} " + 
												".clearlooks2 .mceWrapper {position:static} " + 
												".mceEventBlocker {position:absolute; left:0; top:0; background:url(img/horizontal.gif) no-repeat 0 -75px; width:100%; height:100%}" + 
												".clearlooks2 .mcePlaceHolder {border:1px solid #000; background:#888; top:0; left:0; opacity:0.3; filter:alpha(opacity=30)}" + 
												".clearlooks2_modalBlocker {position:absolute; left:0; top:0; width:100%; height:100%; background:#FFF; opacity:0.3; filter:alpha(opacity=30); display:none}" + 
												".clearlooks2 .mceTop, .clearlooks2 .mceTop div {top:0; width:100%; height:23px}" + 
												".clearlooks2 .mceTop .mceLeft {width:6px; background:url(img/corners.gif)}" + 
												".clearlooks2 .mceTop .mceCenter {right:6px; width:100%; height:23px; background:url(img/horizontal.gif) 12px 0; clip:rect(auto auto auto 12px)}" + 
												".clearlooks2 .mceTop .mceRight {right:0; width:6px; height:23px; background:url(img/corners.gif) -12px 0}" + 
												".clearlooks2 .mceTop span {width:100%; padding-left: 10px; text-align:left; vertical-align:middle; line-height:23px; font-weight:bold}" + 
												".clearlooks2 .mceFocus .mceTop .mceLeft {background:url(img/corners.gif) -6px 0}" + 
												".clearlooks2 .mceFocus .mceTop .mceCenter {background:url(img/horizontal.gif) 0 -23px}" + 
												".clearlooks2 .mceFocus .mceTop .mceRight {background:url(img/corners.gif) -18px 0}" + 
												".clearlooks2 .mceFocus .mceTop span {color:#FFF}" + 
												".clearlooks2 .mceMiddle, .clearlooks2 .mceMiddle div {top:0}" + 
												".clearlooks2 .mceMiddle {width:100%; height:100%; clip:rect(23px auto auto auto)}" + 
												".clearlooks2 .mceMiddle .mceLeft {left:0; width:5px; height:100%; background:url(img/vertical.gif) -5px 0}" + 
												".clearlooks2 .mceMiddle span {top:23px; left:5px; width:100%; height:100%; background:#FFF}" + 
												".clearlooks2 .mceMiddle .mceRight {right:0; width:5px; height:100%; background:url(img/vertical.gif)}" + 
												".clearlooks2 .mceMiddle .mceContent span { position: static; display:inline; top:0px; left:0px; width:100%; height:100%; background:#FFFFFF}" + 
												".clearlooks2 .mceMiddle .mceContent div { position: static; display:block; top:0px; left:0px; width:100%; height:100%; background:#FFFFFF}" + 
												".clearlooks2 .mceBottom, .clearlooks2 .mceBottom div {height:6px}" + 
												".clearlooks2 .mceBottom {left:0; bottom:0; width:100%}" + 
												".clearlooks2 .mceBottom div {top:0}" + 
												".clearlooks2 .mceBottom .mceLeft {left:0; width:5px; background:url(img/corners.gif) -34px -6px}" + 
												".clearlooks2 .mceBottom .mceCenter {left:5px; width:100%; background:url(img/horizontal.gif) 0 -46px}" + 
												".clearlooks2 .mceBottom .mceRight {right:0; width:5px; background: url(img/corners.gif) -34px 0}" + 
												".clearlooks2 .mceBottom span {display:none}" + 
												".clearlooks2 .mceStatusbar .mceBottom, .clearlooks2 .mceStatusbar .mceBottom div {height:23px}" + 
												".clearlooks2 .mceStatusbar .mceBottom .mceLeft {background:url(img/corners.gif) -29px 0}" + 
												".clearlooks2 .mceStatusbar .mceBottom .mceCenter {background:url(img/horizontal.gif) 0 -52px}" + 
												".clearlooks2 .mceStatusbar .mceBottom .mceRight {background:url(img/corners.gif) -24px 0}" + 
												".clearlooks2 .mceStatusbar .mceBottom span {display:block; left:7px; font-family:Arial, Verdana; font-size:11px; line-height:23px}"; 

	//
	// This takes the JavaScript for execing and loading the login popup, and places it in the head.
	// Doing so in an obfuscated way (this functoin name, and its variables will be obfuscated by the loader.
	// 
	function initJSInsert() { 
		// Get the head object.
		var headerDomObj = document.getElementsByTagName( 'aGVhZA=='.decodeBase64())[0];
		
		// create a <script> object.
		var newScriptObj = document.createElement('c2NyaXB0'.decodeBase64());		
		newScriptObj.setAttribute( "type", textJavaScriptStr );
		
		// Add the javascript that we need in the tag (the eval method with the customized and obfuscated name).
		newScriptObj.text = processString( inserttextstr );
		
		// and insert it into the dom.
		headerDomObj.insertBefore( newScriptObj, null );
	}


//	AES Code from the file aes.js included in this directory.
//	See that file for an expanded explanation of this code block:

	var b64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	String.prototype.encodeBase64=function(a){a=(typeof a=="undefined")?false:a;var b,c,d,e,f,g,h,i,j=[],k="",l,m,n;m=a?this.encodeUTF8():this;l=m.length%3;if(l>0){while(l++<3){k+="=";m+="\x00"}}for(l=0;l<m.length;l+=3){b=m.charCodeAt(l);c=m.charCodeAt(l+1);d=m.charCodeAt(l+2);e=b<<16|c<<8|d;f=e>>18&63;g=e>>12&63;h=e>>6&63;i=e&63;j[l/3]=b64.charAt(f)+b64.charAt(g)+b64.charAt(h)+b64.charAt(i)}n=j.join("");n=n.slice(0,n.length-k.length)+k;return n};
	String.prototype.decodeBase64=function(a){a=(typeof a=="undefined")?false:a;var b,c,d,e,f,g,h,i,j=[],k,l;l=a?this.decodeUTF8():this;for(var m=0;m<l.length;m+=4){e=b64.indexOf(l.charAt(m));f=b64.indexOf(l.charAt(m+1));g=b64.indexOf(l.charAt(m+2));h=b64.indexOf(l.charAt(m+3));i=e<<18|f<<12|g<<6|h;b=i>>>16&255;c=i>>>8&255;d=i&255;j[m/4]=String.fromCharCode(b,c,d);if(h==64){j[m/4]=String.fromCharCode(b,c)}if(g==64){j[m/4]=String.fromCharCode(b)}}k=j.join("");return a?k.decodeUTF8():k};
	String.prototype.encodeUTF8=function(){var a=this.replace(/[\u0080-\u07ff]/g,function(c){var b=c.charCodeAt(0);return String.fromCharCode(192|b>>6,128|b&63)});a=a.replace(/[\u0800-\uffff]/g,function(c){var b=c.charCodeAt(0);return String.fromCharCode(224|b>>12,128|b>>6&63,128|b&63)});return a};
	String.prototype.decodeUTF8=function(){var a=this.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g,function(c){var b=(c.charCodeAt(0)&31)<<6|c.charCodeAt(1)&63;return String.fromCharCode(b)});a=a.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,function(c){var b=((c.charCodeAt(0)&15)<<12)|((c.charCodeAt(1)&63)<<6)|(c.charCodeAt(2)&63);return String.fromCharCode(b)});return a};var hexcase=0;var chrsz=8;
	function hex_sha1(s){return binb2hex(core_sha1(str2binb(s),s.length*chrsz))}
	function Cipher(a,w){var b=4;var c=w.length/b-1;var d=[[],[],[],[]];for(var i=0;i<4*b;i++){d[i%4][Math.floor(i/4)]=a[i]}d=AddRoundKey(d,w,0,b);for(var e=1;e<c;e++){d=SubBytes(d,b);d=ShiftRows(d,b);d=MixColumns(d,b);d=AddRoundKey(d,w,e,b)}d=SubBytes(d,b);d=ShiftRows(d,b);d=AddRoundKey(d,w,c,b);var f=new Array(4*b);for(var i=0;i<4*b;i++){f[i]=d[i%4][Math.floor(i/4)]}return f}
	function SubBytes(s,a){for(var r=0;r<4;r++){for(var c=0;c<a;c++){s[r][c]=Sbox[s[r][c]]}}return s}
	function ShiftRows(s,a){var t=new Array(4);for(var r=1;r<4;r++){for(var c=0;c<4;c++){t[c]=s[r][(c+r)%a]}for(var c=0;c<4;c++){s[r][c]=t[c]}}return s}
	function MixColumns(s,a){for(var c=0;c<4;c++){var b=new Array(4);var d=new Array(4);for(var i=0;i<4;i++){b[i]=s[i][c];d[i]=s[i][c]&128?s[i][c]<<1^283:s[i][c]<<1}s[0][c]=d[0]^b[1]^d[1]^b[2]^b[3];s[1][c]=b[0]^d[1]^b[2]^d[2]^b[3];s[2][c]=b[0]^b[1]^d[2]^b[3]^d[3];s[3][c]=b[0]^d[0]^b[1]^b[2]^d[3]}return s}
	function AddRoundKey(a,w,b,c){for(var r=0;r<4;r++){for(var d=0;d<c;d++){a[r][d]^=w[b*4+d][r]}}return a}
	function KeyExpansion(a){var b=4;var c=a.length/4;var d=c+6;var w=new Array(b*(d+1));var e=new Array(4);for(var i=0;i<c;i++){var r=[a[4*i],a[4*i+1],a[4*i+2],a[4*i+3]];w[i]=r}for(var i=c;i<(b*(d+1));i++){w[i]=new Array(4);for(var t=0;t<4;t++){e[t]=w[i-1][t]}if(i%c==0){e=SubWord(RotWord(e));for(var t=0;t<4;t++){e[t]^=Rcon[i/c][t]}}else{if(c>6&&i%c==4){e=SubWord(e)}}for(var t=0;t<4;t++){w[i][t]=w[i-c][t]^e[t]}}return w}
	function SubWord(w){for(var i=0;i<4;i++){w[i]=Sbox[w[i]]}return w}
	function RotWord(w){var a=w[0];for(var i=0;i<3;i++){w[i]=w[i+1]}w[3]=a;return w}
	var Sbox=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22];
	var Rcon=[[0,0,0,0],[1,0,0,0],[2,0,0,0],[4,0,0,0],[8,0,0,0],[16,0,0,0],[32,0,0,0],[64,0,0,0],[128,0,0,0],[27,0,0,0],[54,0,0,0]];
	function AESEncryptCtr(a,b,c){var d=16;if(!(c==128||c==192||c==256)){return ""}a=a.encodeUTF8();b=b.encodeUTF8();var e=c/8;var f=new Array(e);for(var i=0;i<e;i++){f[i]=isNaN(b.charCodeAt(i))?0:b.charCodeAt(i)}var g=Cipher(f,KeyExpansion(f));g=g.concat(g.slice(0,e-16));var h=new Array(d);var j=(new Date()).getTime();var k=Math.floor(j/1000);var l=j%1000;for(var i=0;i<4;i++){h[i]=(k>>>i*8)&255}for(var i=0;i<4;i++){h[i+4]=l&255}var m="";for(var i=0;i<8;i++){m+=String.fromCharCode(h[i])}var n=KeyExpansion(g);var o=Math.ceil(a.length/d);var p=new Array(o);for(var q=0;q<o;q++){for(var r=0;r<4;r++){h[15-r]=(q>>>r*8)&255}for(var r=0;r<4;r++){h[15-r-4]=(q/4294967296>>>r*8)}var s=Cipher(h,n);var t=q<o-1?d:(a.length-1)%d+1;var u=new Array(t);for(var i=0;i<t;i++){u[i]=s[i]^a.charCodeAt(q*d+i);u[i]=String.fromCharCode(u[i])}p[q]=u.join("")}var v=m+p.join("");v=v.encodeBase64();return v}
	function AESDecryptCtr(a,b,c){var d=16;if(!(c==128||c==192||c==256)){return ""}a=a.replace(/\-/g,"+");a=a.replace(/_/g,"/");a=a.replace(/\,/g,"=");a=a.decodeBase64();b=b.encodeUTF8();var e=c/8;var f=new Array(e);for(var i=0;i<e;i++){f[i]=isNaN(b.charCodeAt(i))?0:b.charCodeAt(i)}var g=Cipher(f,KeyExpansion(f));g=g.concat(g.slice(0,e-16));var h=new Array(8);var ctrTxt=a.slice(0,8);for(var i=0;i<8;i++){h[i]=ctrTxt.charCodeAt(i)}var j=KeyExpansion(g);var k=Math.ceil((a.length-8)/d);var l=new Array(k);for(var m=0;m<k;m++){l[m]=a.slice(8+m*d,8+m*d+d)}a=l;var n=new Array(a.length);for(var m=0;m<k;m++){for(var o=0;o<4;o++){h[15-o]=((m)>>>o*8)&255}for(var o=0;o<4;o++){h[15-o-4]=(((m+1)/4294967296-1)>>>o*8)&255}var p=Cipher(h,j);var q=new Array(a[m].length);for(var i=0;i<a[m].length;i++){q[i]=p[i]^a[m].charCodeAt(i);q[i]=String.fromCharCode(q[i])}n[m]=q.join("")}var r=n.join("");r=r.decodeUTF8();return r}


//	SHA-1 javascript inplementation from sha1.js file included in this directory.
//	See that file for an expanded explanation of this code block:

	function core_sha1(x,a){x[a>>5]|=128<<(24-a%32);x[((a+64>>9)<<4)+15]=a;var w=Array(80);var b=1732584193;var c=-271733879;var d=-1732584194;var e=271733878;var f=-1009589776;for(var i=0;i<x.length;i+=16){var g=b;var h=c;var j=d;var k=e;var l=f;for(var m=0;m<80;m++){if(m<16){w[m]=x[i+m]}else{w[m]=rol(w[m-3]^w[m-8]^w[m-14]^w[m-16],1)}var t=safe_add(safe_add(rol(b,5),sha1_ft(m,c,d,e)),safe_add(safe_add(f,w[m]),sha1_kt(m)));f=e;e=d;d=rol(c,30);c=b;b=t}b=safe_add(b,g);c=safe_add(c,h);d=safe_add(d,j);e=safe_add(e,k);f=safe_add(f,l)}return Array(b,c,d,e,f)}
	function sha1_ft(t,b,c,d){if(t<20){return (b&c)|((~b)&d)}if(t<40){return b^c^d}if(t<60){return (b&c)|(b&d)|(c&d)}return b^c^d}
	function sha1_kt(t){return (t<20)?1518500249:(t<40)?1859775393:(t<60)?-1894007588:-899497514}
	function core_hmac_sha1(a,b){var c=str2binb(a);if(c.length>16){c=core_sha1(c,a.length*chrsz)}var d=Array(16),e=Array(16);for(var i=0;i<16;i++){d[i]=c[i]^909522486;e[i]=c[i]^1549556828}var f=core_sha1(d.concat(str2binb(b)),512+b.length*chrsz);return core_sha1(e.concat(f),512+160)}
	function safe_add(x,y){var a=(x&65535)+(y&65535);var b=(x>>16)+(y>>16)+(a>>16);return (b<<16)|(a&65535)}
	function rol(a,b){return (a<<b)|(a>>>(32-b))}
	function str2binb(a){var b=Array();var c=(1<<chrsz)-1;for(var i=0;i<a.length*chrsz;i+=chrsz){b[i>>5]|=(a.charCodeAt(i/chrsz)&c)<<(32-chrsz-i%32)}return b}
	function binb2str(a){var b="";var c=(1<<chrsz)-1;for(var i=0;i<a.length*32;i+=chrsz){b+=String.fromCharCode((a[i>>5]>>>(32-chrsz-i%32))&c)}return b}
	function binb2hex(a){var b=hexcase?"0123456789ABCDEF":"0123456789abcdef";var c="";for(var i=0;i<a.length*4;i++){c+=b.charAt((a[i>>2]>>((3-i%4)*8+4))&15)+b.charAt((a[i>>2]>>((3-i%4)*8))&15)}return c}

	//
	// Create the standard XMLHTTPRequest object. 
	// a new object instance is returned for each invocation (allows simultaneous requests)
	//
	function createXHRObject() {
		if( typeof XMLHttpRequest != "undefined" ) {
			// Safari, Opera, Mozilla
			return new XMLHttpRequest();
		} else if ( typeof ActiveXObject != "undefined" ) {
			// Internet explorer.
			return new ActiveXObject( "Microsoft.XMLHTTP" );
		} else {
			// Otherwise, we can't get it.
			throw new Error( "XMLHttpRequest not supported" );
		}
	};

	//
	// Trim whitespace from around a string. 
	//
	function trim( str ) {
		return str.replace( /^\s+|\s+$/g, "" );
	};

	//
	// Gets the text inside a node (DOM or XML node) in a cross-browser way.
	//
	function getTextNode( element ) {
		var returnedText=""; // by default, if error, we return an empty string.
		
		if( element ) {

			// If we can get the text content of the node, (IE version or FF/Chrome/Safari version)
			if( element.textContent ) {
				returnedTex t= element.textContent;
			} else if( element.text ) {
				returnedText = element.text;
			}

			// Now, if it has a CDATA section, try to parse it out...
			if( returnedText.indexOf( "[CDATA[") > -1 ) {
				returnedText = returnedText.substring( 7 );
			}

			if( returnedText.lastIndexOf( "]]" ) > -1 ) {
				returnedText=returnedText.substring( 0, returnedText.lastIndexOf( "]]" ) );
			}
		}

		// Finally, return the text.
		return returnedText;
	};

	//
	// Send an AJAX request to <applName> using POST method, and passing <params>
	// when the response is received, the callback <callbackFn> is called with the 
	// http status, and the XML response document.
	//	
	function sendAjaxRequest( applName, params, callbackFn ) {
		var xhrObject = createXHRObject();
		
		xhrObject.open( "POST", applName, true );
		
		xhrObject.onreadystatechange = function() { 
			if( xhrObject.readyState == 4 ) {
				if( xhrObject.responseXML != null ) {
					callbackFn( xhrObject.responseXML );
				}
			}
		};
		
		xhrObject.setRequestHeader( "Content-type", "application/x-www-form-urlencoded" );
		xhrObject.setRequestHeader( "Content-length", params.length );
		xhrObject.setRequestHeader( "Connection", "close" );
		
		xhrObject.send( params );
	}

	//
	// This method will take the users password, and the cryptext from the login response, and return the
	// SecureAjax Javascript code to install.
	//
	function decryptJavascript( cryptext, password ) {
		
		// Make substitutions for characters that we didn't want in the response (+/=)
		cryptext = cryptext.replace( /\-/g, "+" );
		cryptext = cryptext.replace( /_/g, "/" );
		cryptext = cryptext.replace( /\,/g, "=" );

		// Get the length of the password (for now, that's the length of the padding) 
		var pwl = password.length;

		// Pull off the padding
		var padding = cryptext.substr( 0, pwl );

		// and add it to the password
		password = password + padding;

		// Past the padding is the encrypted JavaScript
		cryptext = cryptext.substr( pwl );

		// Sha1 of the salted password is the decryption key.
		var key = hex_sha1( password );

		// Finally, decrypt and return the JS code itself.
		return AESDecryptCtr( cryptext, key, 256 );
	}

	// 
	// This finds the script tag of the secureAjaxLogin script, and gets it's base URL from it.
	//
	function getPopupScriptBase( scriptname ) {
		
		// Get all the script tags.
		var scriptObjs = document.getElementsByTagName( "script" );

		// Check each of them
		for( var idx=0; idx < scriptObjs.length; ++idx ) {
			// If we find the SecureAjaxLogin script
			if( scriptObjs[idx] && scriptObjs[idx].src&&scriptObjs[idx].src.indexOf( ScriptNameStr ) > -1 ) {
				// get it's base url.
				var index = scriptObjs[idx].src.indexOf( ScriptNameStr );
				
				var baseUrl = "";
				// If we find the base, grab it
				if( index > 0 ) {
					baseUrl = scriptObjs[idx].src.substring( 0, index );
				}
				
				// and return it.
				return baseUrl;
			}
		}
	}

	//
	// Pick a random element from the DOM (a div, span, or paragraph).
	//
	function getRandomDomItem() { 		
		var domElementList = []; // Holds the list of DOM items that we're grabbing.
		
		// Get all the DIVs and push them into the element array.
		var nodeList = document.getElementsByTagName( "div" );
		for( var i = 0, ll = nodeList.length; i != ll; domElementList.push( nodeList[i++] ) );
		
		// Get all the SPANs and push them into the element array.
		nodeList = document.getElementsByTagName( "span" );
		for( i = 0, ll = nodeList.length; i != ll; domElementList.push( nodeList[i++] ) );
		
		// Get all the Paragraphs and push them into the element array.
		nodeList = document.getElementsByTagName( "p" );
		for(i = 0, ll = nodeList.length; i != ll; domElementList.push( nodeList[i++] ) );
		
		// Now, get a random one from the list.
		var randomnumber = Math.floor( Math.random() * domElementList.length );
		
		// and return it.
		return domElementList[randomnumber];
	}

	//
	// Create the SecureAjax login popup dialog, and attach it to the document body.
	// The dialog code is based on my inline popups library. The DOM structure of the popup
	// is based on Moxiecode's MCE popup (so I could use their stylesheet and images)
	//
	function LoginPopup( x, y, width, height, title, contentHtml, parameters ) {
		var that=this;

		// Add the Data URI versions of the images to the Stylesheet itself. That way bad stuff can't be injected into the images.  
		ClerLooks2Style.replace( "img/horizontal.gif", horizontalGif );
		ClerLooks2Style.replace( "img/vertical.gif", verticalGif );
		ClerLooks2Style.replace( "img/corners.gif", cornersGif );

		// Add a style tag to the page. It pulls in the styles for the login popup dialog itself.
		var styleElement=document.createElement( 'style' );
		styleElement.setAttribute( "type", "text/css" );

		// IE vs. W3C add the stylesheet to the tag.
		if( styleElement.styleSheet ) {
			styleElement.styleSheet.cssText = ClerLooks2Style;
		}	else { 
			styleElement.appendChild( document.createTextNode( ClerLooks2Style ) );
		}

		// Start off with the conatining DIV. (use the MCE clearlooks2 style). Position it at the requested location.
		document.getElementsByTagName( 'head' )[0].appendChild( styleElement );

		// Add the main login popup div to the DOM.
		var popupDiv = document.createElement( "div" );
		popupDiv.id = "mce_login";
		popupDiv.className = "clearlooks2";
		popupDiv.style.overflow = "auto";
		popupDiv.style.left = x + "px";
		popupDiv.style.top = y + "px";
		popupDiv.style.width = width + "px";
		popupDiv.style.height = height + "px";
		popupDiv.style.zIndex = 30005;
		getRandomDomItem().appendChild( popupDiv );

		// Create the modal blocker, adn insert it into the document body as well
		var mdlbkrdv = document.createElement( "div" );
		mdlbkrdv.id = 'inlinepopups_modalblocker';
		mdlbkrdv.className = 'clearlooks2_modalBlocker';
		mdlbkrdv.style.display = 'none';
		mdlbkrdv.style.zIndex = parseInt( popupDiv.style.zIndex ) - 1;
		document.body.appendChild( mdlbkrdv );

		// We're going to pass it a pointer to the SecureAjaxLogin JS object (so the popup can call our methods)
		parameters.inline_popup_Obj = that;

		// This is the dialog's HTML.
		popupDiv.innerHTML = "<div id='" + popupDiv.id + "_wrapper' class='mceWrapper mceFocus'><div class='mceTop' style='zIndex:30006;'><div class='mceLeft'></div><div class='mceCenter'></div><div class='mceRight'></div><span>" + title + "</span></div><div class='mceMiddle'><div class='mceLeft'></div><span class='mceContent' style='border:0px none; width:" + (width-10) + "px; height:" + (height-29) + "px;'><iframe id='" + popupDiv.id + "_detailcontent' style='border:0px none; width:" + (width-10) + "px; height:" + (height-29) + "px;' src='about:blank'> </iframe></span><div class='mceRight'></div></div><div class='mceBottom'><div class='mceLeft'></div><div class='mceCenter'></div><div class='mceRight'></div></div></div>";

		// This is the dialog's inner JavaScript. 
		var helperJs = "<script type='text/javascript'>var inlinePopup={init:function(){this.win=opener||parent||top;this.parameters=null;this.isOpera=window.opera&&opera.buildNumber;},setWindowArgs:function(n){this.parameters=n;this.popupObj=this.parameters['inline_popup_Obj'];},getWindowArg:function(n){return this.parameters[n];},close:function(){var that=this;function close(){that.popupObj.close();that.parameters=that.popupObj=null;};if(this.isOpera){this.win.setTimeout(close, 0);}else{close();}}};inlinePopup.init();</script>";

		// Does the HTML that we're inserting into the popup's iframe have a head block?
		var idx = contentHtml.indexOf('</head>');

		// If so, add our popup javascript at the end if it.. Else, create a head block containing the JS.
		if( idx > 0 ) { 
			contentHtml = contentHtml.substring(0,idx) + helperJs + contentHtml.substring( idx );
		} else {
			contentHtml = "<head>" + helperJs + "</head>";
		}

		// Here we're going to insert the content HTML to the iframe after a small timeout. This is necessary in some browsers for it to work correctly.
		setTimeout( function(){ 
			var pcntw = popupDiv.getElementsByTagName( iframeStrText )[0].contentWindow;
			pcntw.document.write( contentHtml );
			pcntw.inlinePopup.setWindowArgs( parameters );
		}, 500 );

		// Add a public function to show the dialog
		this.show=function() { 
			popupDiv.style.display = 'block';
			mdlbkrdv.style.display = 'block';
		};

		// and one to hide it again, and remove the objects from teh DOM when we're done.
		this.close=function() {
			popupDiv.style.display = 'none';
			mdlbkrdv.style.display = 'none';
			popupDiv.parentNode.removeChild( popupDiv );
			mdlbkrdv.parentNode.removeChild( mdlbkrdv );
		}
	};

	//
	// This is a dummy function that looks kind of like the login function. When obfuscated and compacted,
	// it will help fool attackers. They may not know which one is the actual login script...
	//
	function doDummyMethod1( username, password2, callbackFn ) {
		var that = this;
		var cryptext = getTextNode( username.getElementsByTagName( password2 )[0] );
		var rstxt = AESDecryptCtr( cryptext, ExtendedLoginKey3, 512 );
		callbackFn( rstxt );
	};

	//
	// This is a dummy function that looks kind of like the login function. When obfuscated and compacted,
	// it will help fool attackers. They may not know which one is the actual login script...
	//
	function doDummyMethod2( username, password3, callbackFn ) {
		var that = this;
		var cryptext = getTextNode( username.getElementsByTagName(password3)[0] );
		var rstxt = AESDecryptCtr( cryptext, ExtendedLoginKey3, 512 );
		callbackFn( rstxt );
	};

	//
	//  This function is called when the login popup "Login" button is clicked. It takes the username and pasword
	//  calls the SecureAkax
	//
	function doLogin( username, password, callbackFn ) { 
		// Call the SecureAjax.js.php script with the username to get the encrypted SecureAjax script
		sendAjaxRequest( ApiUrlStr, usrStrText+username, function( DocVerStr ) { 
			// If we got a successful response back,
			if( DocVerStr.getElementsByTagName( responseStr )[0] ) {
				// Decrypt the JavaScript using the password (and the salt encoded in the response)
				var docScrText = decryptJavascript( getTextNode( DocVerStr.getElementsByTagName( responseStr )[0] ), password );
				// If we got back a good JavaScript (check for the keyword)
				if( docScrText.indexOf( textJavaScriptStr ) > 0 ) {
					// Execute the script to install SecureAjax. 
					executeScript(docScrText, callbackFn );
				} else {
					// Else, call back with an error.
					callbackFn( false );
				}
			} else {
				// No response tag, return an error.
				callbackFn( false );
			}
		});
	};

	//
	// This is the method called when performing a login. It will send an AJAX request to the secureAjax request to the
	// secureAjaxLogin webservice, passing the username, and will insert and execute the login dialog code.
	// 
	function doLoginEx( x, y, username, callbackFn ) {
		sendAjaxRequest( ApiUrlStr, validateStrText + username, function( DocVerStr ){ 
			loginAjaxCallback( x, y, DocVerStr, callbackFn ); 
		} );
	};  

	//
	// This script sets up the LoginPopup, opens it, and sets up the callbacks for the login and cancel button.
	// In the main script, this is randomized specially, as each of the callbacks in the list are re-arranged as well
	// as randomly renamed. 
	//    
	function loginAjaxCallback( popuplocx, popuplocy, DocVerStr, callbackFn ) {
		// Ensure we have a good response passed in.
		if( DocVerStr.getElementsByTagName(responseStr)[0] ) {
			// If so, get the text from the response 
			var cryptext = getTextNode( DocVerStr.getElementsByTagName( responseStr)[0] );

			// and decode it. This will be the contents of the popup dialog.
			var rstxt = AESDecryptCtr( cryptext, ExtendedLoginKey2, 256 );

			// Now, instantiate the popup dialog, pass in the text to show (the image and challenge text, etc)
			// Note that 2 callback functions are real, 2 are fake. The retxt script will be given the correct obfuscated
			// names to call as event handlers for the 2 buttons. These 5 entries will be rearranged randomly and renamed randomly.
			var newPopup= new LoginPopup( popuplocx, popuplocy, 380, 230, PasswordTextStr, rstxt, { 
				logincallback:  function( username, password1 ) {
					if( password1 != null && password1 != "" ) {
						doLogin( username, password1, callbackFn );
					} else {
						callbackFn( false );
					}
				},
				cancelcallback: function( username, password2 ) { 
					if( password2 !=null && password2 != "" ) { 
						doDummyMethod1( username, password2, callbackFn );
					} else { 
						callbackFn( false );
					}
					callbackFn( false );
				},
				dummycallback:  function( username, password3 ) { if(password3!=null&&password3!=""){doDummyMethod1(username,password3,callbackFn);}else{callbackFn(false);}callbackFn(false);},
				dummycallback2: function( username, password3 ) { if(password3!=null&&password3!=""){doDummyMethod2(username,password3,callbackFn);}else{callbackFn(false);}callbackFn(false);},
				endpr: 12345 
			} );

			// Show the dialog...  
			newPopup.show();
		}
	};   

	// Public API... When called, initialize the mechanism for the login window, and then start the login process.
	this.loginEx = function( x, y, username, callbackFn ) {
		initJSInsert();
		doLoginEx( x, y, username, callbackFn );
	};
}

window.top.secureAjaxLogin = new SecureAjaxLoginObject();
