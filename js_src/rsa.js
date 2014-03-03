/**
 	
    RSA, a suite of routines for performing RSA public-key computations in
    JavaScript.
 	
    Copyright 1998-2005 David Shapiro.
    
    Feb 2009, PKCS padding added by Brad Broerman, bbroerman@bbroerman.net
	 
    You may use, re-use, abuse, copy, and modify this code to your liking, but
    please keep this header.
 	
    Thanks!
 	
    Dave Shapiro
    dave@ohdave.com
 	
*/

function d2h(d) {return d.toString(16);}
function h2d(h) {return parseInt(h,16);} 

function RSAKeyPair(encryptionExponent, decryptionExponent, modulus)
{
	this.e = biFromHex(encryptionExponent);
	this.d = biFromHex(decryptionExponent);
	this.m = biFromHex(modulus);
	
	// Keybits needs to be a multiple of 16.
	this.keybits = biNumBits(this.m) * 2;
	if( this.keybits % 16 != 0 )
	    this.keybits = ( Math.floor(this.keybits / 16) + 1 ) * 16
	
	this.keyLen = this.keybits / 8;

    // This makes sure the key length is even.	
	if( this.keyLen % 2 != 0 )
	    this.keyLen++;
	
	this.chunkSize = Math.floor(this.keyLen/2) - 12;
	this.barrett = new BarrettMu(this.m);
}

function pkcs1unpad2(d,n) 
{
    var b = new Array();     
    var offset = 0;
    for(idx = 0; idx < d.length; ++idx) 
        b[idx] = d.charCodeAt(idx);

    var i = 0;
    
    while(i < b.length && b[i] == "0".charCodeAt(0))
        ++i;

    if( i == 0 )
    {
        offset = 1;
    }
        
    if(b.length-i-offset != n-1 || b[i] != "2".charCodeAt(0))
        return null;
        
    ++i;
    
    while(b[i] != "0".charCodeAt(0))
      if(++i >= b.length) 
         return null;
         
    var ret = "";
    
    while(++i < b.length)
        ret += String.fromCharCode(b[i]);
        
    ret = ret.substring(0, ret.length-1);

    return ret;
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s,kl) 
{
    var ba = new Array();
     
    var i = s.length - 1;
    var n = kl;
    
    ba[--n] = "0".charCodeAt(0);

    while(i >= 0 && n > 0) 
        ba[--n] = s.charCodeAt(i--);
        
    ba[--n] = "0".charCodeAt(0);
    
    var x = new Array();
    
    while(n > 2) 
    { 
        var randomnumber = Math.floor(Math.random()*16) + 1;
        ba[--n] = d2h(randomnumber).charCodeAt(0);
    }
    
    ba[--n] = "2".charCodeAt(0);
    ba[--n] = "0".charCodeAt(0);
    
    var ret = "";
    
    while(++i < ba.length)
        ret += String.fromCharCode(ba[i]);
        
    return ret;    
}

function doEncryptOperation(key, s)
{
    if( key.keyLen < s.length + 11) 
    {
        alert("Message too long for RSA");
        return null;
    }
    
    var paddedMessage = pkcs1pad2(s, key.keyLen); 
    
	var block = biFromHex(paddedMessage);

    var crypt = key.barrett.powMod(block, key.e);
    
    return biToHex(crypt);
}

function doDecryptOperation(key, c)
{
	var crypt = biFromHex(c);

    var paddedBlock = key.barrett.powMod(crypt, key.d);
    
    var s = biToHex(paddedBlock); 
    
    var message = pkcs1unpad2(s, key.keyLen); 
    
    return message
}

function encryptedString(key, s)
{
	var a = new Array();
	var sl = s.length;
	var i = 0;
	while (i < sl) 
	{
		a[i] = s.charCodeAt(i);
		i++;
	}

	while (a.length % key.chunkSize != 0) 
	{
		a[i++] = 0;
	}

	var al = a.length;
	var result = "";
	var j, k, block;
	for (i = 0; i < al; i += key.chunkSize) 
	{
		block = "";
		for (k = i; k < i + key.chunkSize; ++j) 
		{
			block += d2h(a[k++]);
		}
		
		text = doEncryptOperation(key, block);        		
		result += text + " ";
	}
	
	return result.substring(0, result.length - 1); // Remove last space.
}

function decryptedString(key, s)
{
	var blocks = s.split(" ");
	var result = "";
	var i, j, block;
	
	block = "";
	for (i = 0; i < blocks.length; ++i) 
	{
	   block += doDecryptOperation(key, blocks[i]);
    }
	
	for (j = 0; j <= block.length;j += 2) 
	{
	    result += String.fromCharCode(h2d(block.substring(j,j+2)));
    }
    	
	// Remove trailing nulls, if any.
	while( result.length > 0 && result.charCodeAt(result.length - 1) == 0) 
	{
		result = result.substring(0, result.length - 1);
	}
	
	return result;
}
