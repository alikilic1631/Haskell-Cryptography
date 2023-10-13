module Crypto ( gcd, smallestCoPrimeOf, phi, computeCoeffs, inverse
              , modPow, genKeys, rsaEncrypt, rsaDecrypt, toInt, toChar
              , add, subtract, ecbEncrypt, ecbDecrypt
              , cbcEncrypt, cbcDecrypt ) where

import Data.Char

import Prelude hiding (gcd, subtract)

{-
The advantage of symmetric encryption schemes like AES is that they are efficient
and we can encrypt data of arbitrary size. The problem is how to share the key.
The flaw of the RSA is that it is slow and we can only encrypt data of size lower
than the RSA modulus n, usually around 1024 bits (64 bits for this exercise!).

We usually encrypt messages with a private encryption scheme like AES-256 with
a symmetric key k. The key k of fixed size 256 bits for example is then exchanged
via the aymmetric RSA.
-}

-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

-- | Returns the greatest common divisor of its two arguments
gcd :: Int -> Int -> Int
gcd m n
  | n == 0    = m
  | otherwise = gcd n (m`mod`n) 


-- | Euler Totient function
phi :: Int -> Int
phi m = length[x | x <- [1..m], gcd m x == 1]

{-|
Calculates (u, v, d) the gcd (d) and Bezout coefficients (u and v)
such that au + bv = d
-}
computeCoeffs :: Int -> Int -> (Int, Int)
computeCoeffs a b  
  | b == 0    = (1,0)
  | otherwise = (v,(u-(q*v)))
  where
    q     = a `div` b
    r     = a `mod` b
    (u,v) = computeCoeffs b r
  


-- | Inverse of a modulo m
inverse :: Int -> Int -> Int
inverse a m = u`mod`m
  where 
    (u) = fst (computeCoeffs a m)

  

-- | Calculates (a^k mod m)
modPow :: Int -> Int -> Int -> Int
modPow a k m
  | k == 0    = 1`mod`m
  | even k    = (modPow a_new j m)`mod`m 
  | otherwise = a*(modPow a (k-1) m)`mod`m
  where
    j = k`div`2
    a_new = (a*a)`mod`m



-- | Returns the smallest integer that is coprime with phi
-- | Helper function is called "helper_function". 
-- |It increments a arbitrary variable "b" and uses recursion to increase b by one.
smallestCoPrimeOf :: Int -> Int
smallestCoPrimeOf a = helper_function a 2
  where helper_function :: Int -> Int -> Int
        helper_function a b 
          | gcd a b == 1 = b
          | otherwise    = helper_function a (b+1)
      

{-|
Generates keys pairs (public, private) = ((e, n), (d, n))
given two "large" distinct primes, p and q
-}
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys p q = ((e,n),(d,n))
  where 
    n = p*q
    product = (p-1)*(q-1)
    e = smallestCoPrimeOf(product)
    d = inverse e product
    
  

-- | This function performs RSA encryption
rsaEncrypt :: Int        -- ^ value to encrypt
           -> (Int, Int) -- ^ public key
           -> Int
rsaEncrypt x (e,n) = modPow x e n

-- | This function performs RSA decryption
rsaDecrypt :: Int        -- ^ value to decrypt
           -> (Int, Int) -- ^ public key
           -> Int
rsaDecrypt c (d,n) = modPow c d n

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- | Returns position of a letter in the alphabet
toInt :: Char -> Int
toInt x = ord x - ord 'a'

-- | Returns the n^th letter
toChar :: Int -> Char
toChar x = chr(x + ord 'a')

-- | "adds" two letters
add :: Char -> Char -> Char
add a b = toChar((toInt a + toInt b)`mod`26)
  
-- | "subtracts" two letters
subtract :: Char -> Char -> Char
subtract a b = toChar((toInt a - toInt b)`mod`26) 

-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- | ecb (electronic codebook) encryption with block size of a letter
ecbEncrypt :: Char -> [Char] -> [Char]
ecbEncrypt _ [] = []
ecbEncrypt k (c:cs) = (add c k): ecbEncrypt k cs

-- | ecb (electronic codebook) decryption with a block size of a letter
ecbDecrypt :: Char -> [Char] -> [Char]
ecbDecrypt _ [] = []
ecbDecrypt k (c:cs) = (subtract c k): ecbDecrypt k cs


-- | cbc (cipherblock chaining) encryption with block size of a letter
cbcEncrypt :: Char   -- ^ public key
           -> Char   -- ^ initialisation vector `iv`
           -> [Char] -- ^ message `m`
           -> [Char]
cbcEncrypt k v []   = []
cbcEncrypt k v (c:cs) = enc_c: cbcEncrypt k enc_c cs
  where 
    enc_c = add (add k v) c 
  

-- | cbc (cipherblock chaining) decryption with block size of a letter
cbcDecrypt :: Char   -- ^ private key
           -> Char   -- ^ initialisation vector `iv`
           -> [Char] -- ^ message `m`
           -> [Char]
cbcDecrypt k v []   = [] 
cbcDecrypt k v (c:cs) = subtract (subtract c k) v : cbcDecrypt k c cs
  
