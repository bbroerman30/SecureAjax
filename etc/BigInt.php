<?php
// BigInt, a suite of routines for performing multiple-precision arithmetic in
// PHP.
//
// Ported to PHP by Brad Broerman, June 2012
// based on the original Javascript, Copyright 1998-2005 David Shapiro.
//
// isProbablePrime, nextPrime, inverse, gcd, and helper functions ported to PHP by Brad Broerman
// based on the original Javascript implementation Copyright (c) 2005 Tom Wu which was released
// under a BSD license.
//
//
// You may use, re-use, abuse,
// copy, and modify this code to your liking, but please keep this header.
// Thanks!
//
// Dave Shapiro
// dave@ohdave.com
//
// Tom Wu
// tjw@cs.Stanford.EDU
//
// Brad Broerman
// bbroerman@bbroerman.net
//
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
// IMPORTANT THING: Be sure to set maxDigits according to your precision
// needs. Use the setMaxDigits() function to do this. See comments below.
//
// Tweaked by Ian Bunning
// Alterations:
// Fix bug in function biFromHex(s) to allow
// parsing of strings of length != 0 (mod 4)
//
// Changes made by Dave Shapiro as of 12/30/2004:
//
// The BigInt() constructor doesn't take a string anymore. If you want to
// create a BigInt from a string, use biFromDecimal() for base-10
// representations, biFromHex() for base-16 representations, or
// biFromString() for base-2-to-36 representations.
//
// biFromArray() has been removed. Use biCopy() instead, passing a BigInt
// instead of an array.
//
// The BigInt() constructor now only constructs a zeroed-out array.
// Alternatively, if you pass <true>, it won't construct any array. See the
// biCopy() method for an example of this.
//
// Be sure to set maxDigits depending on your precision needs. The default
// zeroed-out array ZERO_ARRAY is constructed inside the setMaxDigits()
// function. So use this function to set the variable. DON'T JUST SET THE
// VALUE. USE THE FUNCTION.
//
// Max number = 10^16 - 2 = 9999999999999998;
// 2^53 = 9007199254740992;

class BigInt {
  protected $digits = array();
  protected $isNeg = false;
  
  protected static $maxInteger = PHP_INT_MAX;
  protected static $maxDigits = 0;
  protected static $ZERO_ARRAY = null;
  public static $bigZero = null;
  public static $bigOne = null;
    
  // The maximum number of digits in base 10 you can convert to an
  // integer without PHP throwing up on you.
  protected static $dpl10 = 9;
  protected static $lr10 = null;
  protected static $biRadixBase = 2;
  protected static $biRadixBits = 16;
  protected static $bitsPerDigit = 16;
  protected static $biRadix = 65536;
  protected static $biHalfRadix = null;
  protected static $biRadixSquared = null;
  protected static $maxDigitVal = null;
  
  
  protected static $highBitMasks = array( 0x0000, 0x8000, 0xC000, 0xE000, 0xF000, 0xF800,
                                          0xFC00, 0xFE00, 0xFF00, 0xFF80, 0xFFC0, 0xFFE0,
                                          0xFFF0, 0xFFF8, 0xFFFC, 0xFFFE, 0xFFFF );
                                   
  protected static $hexatrigesimalToChar = array( '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                                                  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                                                  'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                                                  'u', 'v', 'w', 'x', 'y', 'z' );
  
  protected static $hexToChar = array( '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' );
  
  protected static $lowBitMasks = array( 0x0000, 0x0001, 0x0003, 0x0007, 0x000F, 0x001F,
                                         0x003F, 0x007F, 0x00FF, 0x01FF, 0x03FF, 0x07FF,
                                         0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF );
                                         
  protected static $lowprimes = array( 2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,
                                       109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,
                                       229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,
                                       353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,
                                       479,487,491,499,503,509 );


  // maxDigits:
  // Change this to accommodate your largest number size. Use setMaxDigits()
  // to change it!
  //
  // In general, if you're working with numbers of size N bits, you'll need 2*N
  // bits of storage. Each digit holds 16 bits. So, a 1024-bit key will need
  //
  // 1024 * 2 / 16 = 128 digits of storage.
  //
  public static function setMaxDigits( $value ) {
    self::$maxDigits = $value;
    self::$ZERO_ARRAY = array( );
    for( $iza = 0; $iza < self::$maxDigits; $iza++ ) self::$ZERO_ARRAY[$iza] = 0;
    self::$bigZero = new BigInt();
    self::$bigOne = new BigInt();
    self::$bigOne->digits[0] = 1;
  }
                                           
  public function __construct( $flag = false ) {
    //
    // Set our statics up (just in case they aren't already)...
    //
    self::$biRadix = 65536;
    
    if( self::$biHalfRadix == null ) {
      self::$biHalfRadix = self::shrz(self::$biRadix,1);
    }
    
    if( self::$biRadixSquared == null ) {
      self::$biRadixSquared = self::$biRadix * self::$biRadix;
    }
    
    if( self::$maxDigitVal == null ) {
      self::$maxDigitVal = self::$biRadix - 1;
    }
    
    if( self::$lr10 = null ) {
      self::$lr10 = self::fromNumber(1000000000000000);
    }

    //
    // Now, set the instance variables.
    //
    if( is_bool( $flag ) && $flag == true ) {
      $this->digits = null;
    }
    else {
      $this->digits = self::$ZERO_ARRAY;
    }
    $this->isNeg = false;
  }

  public static function fromDecimal( $s ) {
    $result = false;
    
    $isNeg = ( substr($s,0,1) == '-' );
    $i = $isNeg ? 1 : 0;

    // Skip leading zeros.
    while( $i < strlen( $s ) && substr( $s, $i, 1) == '0' )
    ++$i;

    if( $i == strlen( $s ) ) {
      $result = new BigInt();
    } else {
      $digitCount = strlen($s) - $i;
      $fgl = $digitCount % self::$dpl10;
      if( $fgl == 0 ) $fgl = self::$dpl10;
      $result = self::fromNumber( (int)substr( $s, $i, $fgl) );
      $i += $fgl;
      while( $i < strlen($s) ) {
        $result = self::add( self::multiply( $result, self::$lr10 ),
        self::fromNumber( (int)substr( $s, $i, self::$dpl10 ) ) );
        $i += self::$dpl10;
      }
      $result->isNeg = $isNeg;
    }
    
    return $result;
  }

  public static function fromHex( $s ) {
    $result = new BigInt();
    $sl = strlen( $s );

    for( $i = $sl, $j = 0; $i > 0; $i -= 4, ++$j) {
      $result->digits[j] = self::hexToDigit( substr( $s, Math.max( $i - 4, 0 ), Math.min( $i, 4 ) ) );
    }

    return result;
  }

  public static function fromString( $s, $radix = 10) {
    $isNeg = ( substr( $s, 0 ) == '-' );
    $istop = $isNeg ? 1 : 0;
    $result = new BigInt();
    $place = new BigInt();
      
    $place->digits[0] = 1; // radix^0
    for( $i = strlen($s) - 1; $i >= $istop; $i-- ) {
      $c = ord( substr( $s, $i, 1 ) );
      $digit = self::charToHex( $c );
      $biDigit = self::biMultiplyDigit( $place, $digit );
      $result = self::add( $result, $biDigit );
      $place = self::biMultiplyDigit( $place, $radix );
    }
    $result->isNeg = $isNeg;
    return $result;
  }

  public static function fromNumber( $i ) {
    $result = new BigInt();
    $result->isNeg = $i < 0;
    $i = abs($i);

    $j = 0;
    while( $i > 0 ) {
      $result->digits[$j++] = $i & self::$maxDigitVal;
      $i >>= self::$biRadixBits;
    }

    return $result;
  }
  
  public static function copy( $bi ) {
    $result = new BigInt(true);
    $result->digits = $bi->digits;
    $result->isNeg = $bi->isNeg;
    
    return $result;
  }
  

  function negate() {
    $result = self::copy( $this );
    $result->isNeg = !$result->isNeg;
 
    return $result;
  }

  // 2 <= radix <= 36
  public function toString( $radix ) {
    $b = new BigInt();
    $b->digits[0] = $radix;

    $qr = self::divideModulo( $this, $b );
     
    $result = self::$hexatrigesimalToChar[ $qr[1]->digits[0] ];

    while( self::compare( $qr[0], self::$bigZero) == 1 ) {
      $qr = self::divideModulo( $qr[0], $b );
      $result .= self::$hexatrigesimalToChar[ $qr[1]->digits[0] ];
    }

    return ( $this->isNeg ? "-" : "") . self::reverseStr( $result );
  }

  public function toDecimal( ) {
    $b = new BigInt();
    $b->digits[0] = 10;

    $qr = self::divideModulo( $this, $b );
    $result = '' . $qr[1]->digits[0];

    while( self::compare( $qr[0], self::$bigZero) == 1 ) {
      $qr = self::divideModulo( $qr[0], $b );
      $result .= '' . $qr[1]->digits[0];
    }

    return ( $this->isNeg ? "-" : "") . self::reverseStr( $result );
  }

  public function toHex( ) {
    $result = "";
    $n = $this->highIndex( );
    for( $i = $this->highIndex( ); $i > -1; --$i) {
      $result .= $this->digitToHex( $this->digits[$i] );
    }
    return $result;
  }

  public function dump( ) {
    $tmp = ( $this->isNeg ? "-" : "" );

    foreach( $this->digits as $digit ) {
      $tmp .= " " . (intval($digit)>0?$digit:"0");
    }
    
    return $tmp;
  }

  public function abs() {
    $result = self::copy($this);
    $result->isNeg = false;
    
    return $result;
  }

  public function sigNum() {
    if( $this->isNeg ) return -1;
    else if( $this->highIndex() < 0 || ( $this->highIndex() == 0 && $this->digits[0] <= 0 ) ) return 0;
    else return 1;
  }

  public function highIndex( ) {
    $result = count($this->digits) - 1;
    while( $result > 0 && $this->digits[$result] == 0)
      --$result;
    return $result;
  }

  public function biNumBits( ) {
    $n = $this->highIndex( );
    $d = $this->digits[$n];
    $m = ($n + 1) * self::$bitsPerDigit;
    $result = 0;

    for ($result = $m; $result > $m - self::$bitsPerDigit; --$result) {
      if (($d & 0x8000) != 0)
      break;
      $d <<= 1;
    }
    return $result;
  }
  
  public function getLowestSetBit() {
    for( $i=0; $i <= $this->highIndex(); ++$i) {
      if( $this->digits[$i] != 0 ) {
        return $i * self::$bitsPerDigit + self::lbit( $this->digits[$i] );
      }
    }
  
    if ( $this->isNeg )
      return count($this->digits) * self::$bitsPerDigit;
  
    return -1;
  }

  public function isEven( ) {
    return ( ( $this->highIndex() > 0 ) ? ( $this->digits[0] & 1 ) : $this->isNeg ) == 0;
  }
  
  public function isNeg( ) {
    return $this->isNeg;
  }
  
  public function getDigit( $i ) {
    return $this->digits[ $i ];
  }
  
  public function setDigit( $i, $v ) {
    $this->digits[$i] = $v;
  }

  // (public) test primality with certainty >= 1-.5^t
  public function isProbablePrime( $t ) {
    $i = 0;
    $lplim = ( 1 << 26 ) / self::$lowprimes[ count( self::$lowprimes ) - 1 ];
    $x = $this->abs();
    
    if( $this->highIndex() == 0 && $this->digits[0] <= self::$lowprimes[ count(self::$lowprimes) - 1 ]) {
      for( $i=0; $i < count(self::$lowprimes); ++$i) {
        if ( $x->getDigit(0) == self::$lowprimes[$i] )
          return true;
      }
      return false;
    }
  
    if( $x->isEven() )
      return false;
  
    $i = 1;
    while( $i < count(self::$lowprimes) ) {
      $m = self::$lowprimes[$i];
      $j = $i + 1;

      while( $j < count(self::$lowprimes) && $m < $lplim ) {
        $m *= self::$lowprimes[$j++];
      }

      $m = intval( self::toDecimal( self::modulo( $x, self::fromNumber( $m ) ) ) );

      while( $i < $j ) {
        if( $m % self::$lowprimes[$i++] == 0 ) {
          return false;
        }
      }
    }
   
    return self::millerRabin( $x, $t );
  }

  public static function add( $x, $y ) {
    $result = false;
       
    if( $x->isNeg != $y->isNeg ) {
      $y->isNeg = !$y->isNeg;
      $result = self::subtract( $x, $y );
      $y->isNeg = !$y->isNeg;
    } else {
      $result = new BigInt();
      $c = 0;
      $n;
      for( $i = 0; $i < count($x->digits); ++$i) {
        $n = $x->digits[$i] + $y->digits[$i] + $c;
        $result->digits[$i] = $n & 0xffff;
        $c = ( $n >= self::$biRadix )?1:0;
      }
      $result->isNeg = $x->isNeg;
    }
    
    return $result;
  }

  public static function subtract( $x, $y ) {
    $result = null;
    
    if( $x->isNeg != $y->isNeg ) {
      $y->isNeg = !$y->isNeg;
      $result = self::add( $x, $y );
      $y->isNeg = !$y->isNeg;
    } else {
      $result = new BigInt();
      $n = 0;
      $c = 0;
      for( $i = 0; $i < count( $x->digits ); ++$i ) {
        $n = $x->digits[$i] - $y->digits[$i] + $c;
        $result->digits[$i] = $n & 0xffff;
        // Stupid non-conforming modulus operation.
        if( $result->digits[$i] < 0) $result->digits[$i] += self::$biRadix;
        $c = 0 - (($n < 0)?1:0);
      }
      
      // Fix up the negative sign, if any.
      if( $c == -1 ) {
        $c = 0;
        for( $i = 0; $i < count($x->digits); ++$i) {
          $n = 0 - $result->digits[$i] + $c;
          $result->digits[$i] = $n & 0xffff;
          // Stupid non-conforming modulus operation.
          if( $result->digits[$i] < 0) $result->digits[$i] += self::$biRadix;
          $c = 0 - (($n < 0)?1:0);
        }
        // Result is opposite sign of arguments.
        $result->isNeg = !$x->isNeg;
      } else {
        // Result is same sign.
        $result->isNeg = $x->isNeg;
      }
    }
    
    return $result;
  }

  public static function multiply( $x, $y ) {
    $result = new BigInt();
    $c = 0;
    $n = $x->highIndex( );
    $t = $y->highIndex( );
    $u =0;
    $uv = 0;
    $k = 0;
 
    for( $i = 0; $i <= $t; ++$i ) {
      $c = 0;
      $k = $i;

      for( $j = 0; $j <= $n; ++$j, ++$k ) {
        $uv = $result->digits[$k] + $x->digits[$j] * $y->digits[$i] + $c;
        $result->digits[$k] = $uv & self::$maxDigitVal;
        $c = self::shrz( $uv, self::$biRadixBits );
      }
      $result->digits[ $i + $n + 1 ] = $c;
    }

    // Someone give me a logical xor, please.
    $result->isNeg = $x->isNeg != $y->isNeg;
    return $result;
  }

  public static function shiftLeft( $x, $n ) {
    
    $digitCount = floor( $n / self::$bitsPerDigit );
    $result = new BigInt();

    self::arrayCopy( $x->digits, 0, $result->digits, $digitCount, count($result->digits) - $digitCount );

    $bits = $n % self::$bitsPerDigit;
    $rightBits = self::$bitsPerDigit - $bits;

    for( $i = count($result->digits) - 1, $i1 = $i - 1; $i > 0; --$i, --$i1) {
      $result->digits[$i] = (($result->digits[$i] << $bits) & self::$maxDigitVal) | self::shrz( ($result->digits[$i1] & static::$highBitMasks[$bits]), $rightBits );
    }
    
    $result->digits[0] = (($result->digits[$i] << $bits) & self::$maxDigitVal);
    
    $result->isNeg = $x->isNeg;

    return $result;
  }

  public static function shiftRight( $x, $n ) {
    $digitCount = floor($n / self::$bitsPerDigit);
    $result = new BigInt();

    self::arrayCopy( $x->digits, $digitCount, $result->digits, 0, count($x->digits) - $digitCount );

    $bits = $n % self::$bitsPerDigit;
    $leftBits = self::$bitsPerDigit - $bits;

    for( $i = 0, $i1 = $i + 1; $i < count($result->digits) - 1; ++$i, ++$i1) {
      $result->digits[$i] = self::shrz($result->digits[$i], $bits) | (($result->digits[$i1] & self::$lowBitMasks[$bits]) << $leftBits);
    }
    $result->digits[ count($result->digits) - 1 ] = self::shrz( $result->digits[ count($result->digits) - 1 ], $bits );

    $result->isNeg = $x->isNeg;
    return $result;
  }

  public static function multiplyByRadixPower( $x, $n ) {
    $result = new BigInt();
    self::arrayCopy( $x->digits, 0, $result->digits, $n, count($result->digits) - $n );
    return $result;
  }

  public static function divideByRadixPower( $x, $n ) {
    $result = new BigInt();
    self::arrayCopy( $x->digits, $n, $result->digits, 0, count( $result->digits) - $n );
    return $result;
  }

  public static function moduloByRadixPower( $x, $n ) {
    $result = new BigInt();
    self::arrayCopy( $x->digits, 0, $result->digits, 0, $n );
    return $result;
  }

  public static function compare( $x, $y ) {
    if( $x->isNeg != $y->isNeg ) {
      return 1 - 2 * (($x->isNeg)?1:0);
    }
    for( $i = count($x->digits) - 1; $i >= 0; --$i) {
      if( $x->digits[$i] != $y->digits[$i]) {
        if( $x->isNeg ) {
          return 1 - 2 * (($x->digits[$i] > $y->digits[$i])?1:0);
        } else {
          return 1 - 2 * (($x->digits[$i] < $y->digits[$i])?1:0);
        }
      }
    }
    return 0;
  }

  public static function divideModulo( $left, $right ) {
    $x = self::copy($left);
    $y = self::copy($right);
    $nb = $x->biNumBits();
    $tb = $y->biNumBits();
    
    $origYIsNeg = $y->isNeg;
    $q=0;
    $r=0;

    if( $nb < $tb ) {
      // |x| < |y|
      if( $x->isNeg ) {
        $q = self::copy(self::$bigOne);
        $q->isNeg = !$y->isNeg;
        $x->isNeg = false;
        $y->isNeg = false;
        $r = self::subtract($y, $x);
        // Restore signs, 'cause they're references.
        $x->isNeg = true;
        $y->isNeg = $origYIsNeg;
      } else {
        $q = new BigInt();
        $r = self::copy($x);
      }
      return Array($q, $r);
    }

    $q = new BigInt();
    $r = $x;
    
    // Normalize Y.
    $t = ceil( $tb / self::$bitsPerDigit ) - 1;
     
    $lambda = 0;
    while( $y->digits[$t] < self::$biHalfRadix ) {
      $y = self::shiftLeft( $y, 1 );
      ++$lambda;
      ++$tb;
      $t = ceil( $tb / self::$bitsPerDigit ) - 1;
    }

    // Shift r over to keep the quotient constant. We'll shift the
    // remainder back at the end.
    $r = self::shiftLeft( $r, $lambda );
        
    $nb += $lambda; // Update the bit count for x.
    $n = ceil( $nb / self::$bitsPerDigit ) - 1;

    $b = self::multiplyByRadixPower( $y, $n - $t );
    
    while( self::compare( $r, $b ) != -1 ) {
      ++$q->digits[$n - $t];
      $r = self::subtract($r, $b);
    }
   
    for( $i = $n; $i > $t; --$i ) {
      $ri = ($i >= count($r->digits) || $i < 0) ? 0 : $r->digits[$i];
      $ri1 = ($i - 1 >= count($r->digits) || ($i - 1) < 0) ? 0 : $r->digits[$i - 1];
      $ri2 = ($i - 2 >= count($r->digits) || ($i - 2) < 0) ? 0 : $r->digits[$i - 2];
      $yt = ($t >= count($y->digits) || $t < 0) ? 0 : $y->digits[$t];
      $yt1 = ($t - 1 >= count($y->digits) || ($t - 1) < 0) ? 0 : $y->digits[$t - 1];
      if( $ri == $yt ) {
        $q->digits[$i - $t - 1] = self::$maxDigitVal;
      } else {
        $q->digits[$i - $t - 1] = floor(($ri * self::$biRadix + $ri1) / $yt);
      }

      $c1 = $q->digits[$i - $t - 1] * (($yt * self::$biRadix) + $yt1);
      $c2 = ($ri * self::$biRadixSquared) + (($ri1 * self::$biRadix) + $ri2);
      while( $c1 > $c2 ) {
        --$q->digits[$i - $t - 1];
        $c1 = $q->digits[$i - $t - 1] * (($yt * self::$biRadix) | $yt1);
        $c2 = ($ri * self::$biRadix * self::$biRadix) + (($ri1 * self::$biRadix) + $ri2);
      }

      $b = self::multiplyByRadixPower($y, $i - $t - 1);
      $r = self::subtract($r, self::biMultiplyDigit($b, $q->digits[$i - $t - 1]));
      
      if( $r->isNeg ) {
        $r = self::add($r, $b);
        --$q->digits[$i - $t - 1];
      }
    }
    
    $r = self::shiftRight($r, $lambda);
    
    // Fiddle with the signs and stuff to make sure that 0 <= r < y.
    $q->isNeg = $x->isNeg != $origYIsNeg;
    if ($x->isNeg) {
      if ($origYIsNeg) {
        $q = self::add($q, self::$bigOne);
      } else {
        $q = self::subtract($q, self::$bigOne);
      }
      $y = self::shiftRight($y, $lambda);
      $r = self::subtract($y, $r);
    }
    
    // Check for the unbelievably stupid degenerate case of r == -0.
    if ($r->digits[0] == 0 && $r->highIndex( ) == 0)
    $r->isNeg = false;

    return array($q, $r);
  }

  public static function divide($x, $y) {
    $res = self::divideModulo($x, $y);
    return $res[0];
  }

  public static function modulo($x, $y) {
    $res = self::divideModulo($x, $y);
    return $res[1];
  }

  public static function multiplyMod($x, $y, $m) {
    return self::modulo(self::multiply($x, $y), $m);
  }

  public static function pow( $x, $y ) {
    $result = self::$bigOne;
    $a = $x;
    while (true) {
      if( ($y & 1) != 0)
        $result = self::multiply($result, $a);
        
      $y >>= 1;
      if( $y <= 0 )
        break;
        
      $a = self::multiply($a, $a);
    }
    return $result;
  }
  
  public static function powMod( $x, $y, $m ) {
    $result = self::$bigOne;
    $a = BigInt::copy($x);
    $k = BigInt::copy($y);
  
    while (true) {
      if( ($k->digits[0] & 1) != 0 )
        $result = self::multiplyMod($result, $a, $m);
      
     $k = self::shiftRight($k, 1);
    
      if($k->digits[0] == 0 && $k->highIndex( ) == 0)
        break;
      
      $a = self::multiplyMod($a, $a, $m);
    }
  
    return $result;
  }
  
  public static function gcd( $p, $a ) {
    $x = ($p->isNeg)?$p->negate():self::copy($p);
    $y = ($a->isNeg)?$a->negate():self::copy($a);
  
    if(self::compare($x,$y) < 0) {
      $t = $x;
      $x = $y;
      $y = $t;
    }
    
    $i = $x->getLowestSetBit();
    $g = $y->getLowestSetBit();
    
    if($g < 0) return $x;
    if($i < $g) $g = $i;
    if($g > 0) {
      $x = self::shiftRight($x,$g);
      $y = self::shiftRight($y,$g);
    }
  
    while($x->signum() > 0) {
      if(($i = $x->getLowestSetBit()) > 0) $x=self::shiftRight($x,$i);
      if(($i = $y->getLowestSetBit()) > 0) $y=self::shiftRight($y,$i);
      if(self::compare($x,$y) >= 0) {
        $x = self::subtract($x,$y);
        $x = self::shiftRight($x,1);
      } else {
        $y = self::subtract($y,$x);
        $y = self::shiftRight( $y, 1 );
      }
    }
    if($g > 0) $y=self::shiftLeft($y,$g);
    return $y;
  }

  // (public) 1/this % m (HAC 14.61)
  public static function invertMod( $p, $m ) {
    $ac = $m->isEven();
  
    if( ( $p->isEven() && $ac ) || $m->signum() == 0)
      return self::$bigZero;
  
    $u = self::copy($m);
    $v = self::copy($p);
  
    $a = self::copy(self::$bigOne);
    $b = self::copy(self::$bigZero);
    $c = self::copy(self::$bigZero);
    $d = self::copy(self::$bigOne);
  
    while( $u->signum() != 0) {
      while( $u->isEven() ) {
        $u = self::shiftRight($u,1);
        if( $ac ) {
          if( !$a->isEven() || !$b->isEven() ) { $a = self::add($a, $p); $b = self::subtract($b, $m); }
          $a = self::shiftRight( $a, 1 );
        }
        else if(!$b->isEven()) $b = self::subtract($b, $m);
        $b = self::shiftRight( $b, 1 );
      }
      while( $v->isEven() ) {
        $v = self::shiftRight( $v, 1 );
        if($ac) {
          if(!$c->isEven() || !$d->isEven()) { $c = self::add($c, $p); $d = self::subtract( $d, $m ); }
          $c = self::shiftRight( $c, 1 );
        }
        else if(!$d->isEven()) $d = self::subtract($d,$m);
        $d = self::shiftRight( $d, 1 );
      }
      if( self::compare($u,$v) >= 0 ) {
        $u = self::subtract($u, $v);
        if($ac) $a = self::subtract($a,$c);
        $b = self::subtract($b,$d);
      }
      else {
        $v = self::subtract( $v, $u);
        if($ac) $c = self::subtract($c,$a);
        $d = self::subtract($d,$b);
      }
    }
    if(self::compare($v,self::$bigOne) != 0) return self::$bigZero;
    if(self::compare($d,$m) >= 0) return self::subtract($d,$m);
    if($d->signum() < 0) $d = self::add($d,$m); else return $d;
    if($d->signum() < 0) return self::add($d,$m); else return $d;
  }
  
  public static function nextPrime( $val )
  {
    $result = new BigInt();
  
    $result = self::add( $val, self::$bigOne );
    while( !$result->isProbablePrime( 5 ) )
      $result = self::add( $result, self::$bigOne );
      
    return $result;
  }

  protected static function biMultiplyDigit( $x, $y ) {
    $result = new BigInt();
    
    $n = $x->highIndex( );
    
    $c = 0;
    for( $j = 0; $j <= $n; ++$j ) {
      $uv = $result->digits[$j] + $x->digits[$j] * $y + $c;
            
      $result->digits[$j] = $uv & self::$maxDigitVal;
      
      $c = self::shrz( $uv, self::$biRadixBits );
    }
    
    $result->digits[1 + $n] = $c;
        
    return $result;
  }

  protected static function arrayCopy( $src, $srcStart, &$dest, $destStart, $n ) {
    $m = min($srcStart + $n, count($src) );
    for( $i = $srcStart, $j = $destStart; $i < $m; ++$i, ++$j) {
      $dest[$j] = $src[$i];
    }
  }
  
  private static function lbit( $x ) {
    if( $x == 0 ) return -1;
    $r = 0;
    if( ($x & 0xffff) == 0) { $x >>= 16; $r += 16; }
    if( ($x & 0x00ff) == 0) { $x >>= 8; $r += 8; }
    if( ($x & 0x000f) == 0) { $x >>= 4; $r += 4; }
    if( ($x & 0x0003) == 0) { $x >>= 2; $r += 2; }
    if( ($x & 0x0001) == 0) ++$r;
    return $r;
  }

  // true if probably prime (HAC 4.24, Miller-Rabin)
  private static function millerRabin($p, $t) {

    $n1 = self::subtract($p, self::$bigOne);
  
    $k = $n1->getLowestSetBit();
 
    if($k <= 0) {
      return false;
    }
  
    $r = self::shiftRight($n1, $k);
  
    $t = ( $t + 1 ) >> 1;
  
    if( $t > count(self::$lowprimes) ) {
      $t = count(self::$lowprimes);
    }
    
    for($i = 0; $i < $t; ++$i) {
      $a = BigInt::fromNumber( self::$lowprimes[$i] );
    
      $y = self::powMod( $a, $r, $p );
    
      if( self::compare( $y, self::$bigOne ) != 0 && self::compare( $y, $n1 ) != 0 ) {
     
        $b2 = self::fromNumber( 2 );
    
        for( $j = 1; $j < $k && self::compare( $y, $n1) != 0; ++$j ) {
          $y = self::powMod( $y, $b2, $p );
          if( self::compare( $y, self::$bigOne ) == 0) {
            return false;
          }
        }
        
        if( self::compare($y, $n1) != 0) {
          return false;
        }
      }
    }
    
    return true;
  }
    
     
  protected static function reverseStr( $s ) {
    $result = "";
    for( $i = strlen($s) - 1; $i > -1; --$i) {
      $result .= substr($s, $i, 1);
    }
    
    return $result;
  }
  
  protected function digitToHex( $n ) {
    $mask = 0xf;
    $result = "";
    for( $i = 0; $i < 4; ++$i ) {
      $result .= self::$hexToChar[ $n & $mask ];
      $n = self::shrz( $n, 4 );
    }
    return self::reverseStr( $result );
  }


  protected static function charToHex( $c ) {
    $ZERO = 48;
    $NINE = $ZERO + 9;
    $littleA = 97;
    $littleZ = $littleA + 25;
    $bigA = 65;
    $bigZ = 65 + 25;
    $result;

    if( $c >= $ZERO && $c <= $NINE) {
      $result = $c - $ZERO;
    } else if( $c >= $bigA && $c <= $bigZ ) {
      $result = 10 + $c - $bigA;
    } else if( $c >= $littleA && $c <= $littleZ ) {
      $result = 10 + $c - $littleA;
    } else {
      $result = 0;
    }
    return $result;
  }

  protected static function hexToDigit( $s ) {
    $result = 0;
    $sl = min( strlen($s), 4);
    for( $i = 0; $i < $sl; ++$i) {
      $result <<= 4;
      $result |= self::charToHex( ord(substr($s, $i, 1)) );
    }
    return result;
  }

  protected static function shrz($a,$b) {
    $orig = decbin( $a );
    if( strlen( $orig ) > $b ) {
      $bin = str_pad( substr( $orig, 0, strlen( $orig ) - $b ), 64, '0', STR_PAD_LEFT );
    } else {
      $bin = "0";
    }
    
    $o = bindec($bin);
    return $o;
  }

}

// Initially set out Max Digits to 20.
BigInt::setMaxDigits( 30 );


class BarretMu {
  protected $modulus = null;
  protected $k = null;
  protected $mu = null;
  protected $bkplus1 = null;
  
  public function __construct( $m ) {
    $this->modulus = BigInt::copy( $m );
    $this->k = $this->modulus->highIndex( ) + 1;
    
    $b2k = new BigInt();
    $b2k->setDigit(2 * $this->k, 1); // b2k = b^(2k)
    $this->mu = BigInt::divide( $b2k, $this->modulus );
    
    $this->bkplus1 = new BigInt();
    $this->bkplus1->setDigit($this->k + 1, 1); // bkplus1 = b^(k+1)
  }
  
  public function modulo( $x ) {
    $q1 = BigInt::divideByRadixPower($x, $this->k - 1);
    $q2 = BigInt::multiply($q1, $this->mu);
    $q3 = BigInt::divideByRadixPower($q2, $this->k + 1);
    $r1 = BigInt::moduloByRadixPower($x, $this->k + 1);
    $r2term = BigInt::multiply($q3, $this->modulus);
    $r2 = BigInt::moduloByRadixPower($r2term, $this->k + 1);
    $r = BigInt::subtract($r1, $r2);
  
    if ($r->isNeg()) {
      $r = BigInt::add( $r, $this->bkplus1);
    }
    
    $rgtem = BigInt::compare( $r, $this->modulus) >= 0;
    while ($rgtem) {
      $r = BigInt::subtract( $r, $this->modulus );
      $rgtem = BigInt::compare( $r, $this->modulus ) >= 0;
    }
    
    return $r;
  }

  public function multiplyMod( $x, $y )
  {
    $xy = BigInt::multiply($x, $y);
    return $this->modulo($xy);
  }

  public function powMod($x, $y)
  {
    $result = BigInt::copy( BigInt::$bigOne );
    $a =  BigInt::copy( $x);
    $k =  BigInt::copy( $yi);
    while (true) {
      if( ($k->getDigit(0) & 1) != 0) $result = $this->multiplyMod($result, $a);
      $k = BigInt::shiftRight($k, 1);
      if ($k->getDigit(0) == 0 && $k->highIndex($k) == 0) break;
      $a = $this->multiplyMod($a, $a);
    }
    return $result;
  }
}
?>
