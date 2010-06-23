{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Pubkey.Base64 where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char (ord, chr, isAscii, isAlphaNum, isUpper, isLower, isDigit)
import Network.DomainAuth.Utils

decode :: L.ByteString -> L.ByteString
decode = dec . L.filter valid
  where
    valid c = isAscii c
              && (isAlphaNum c || (c `elem` "+/="))

dec :: L.ByteString -> L.ByteString
dec bs
    | L.null bs             = ""
    | len == 4 && c3 == '=' = L.take 1 (dec' x1 x2  0  0)
    | len == 4 && c4 == '=' = L.take 2 (dec' x1 x2 x3  0)
    | len >= 4              =           dec' x1 x2 x3 x4  +++ dec bs'
    | otherwise             = error "dec"
  where
    len = L.length bs
    c1 = bs !!! 0
    c2 = bs !!! 1
    c3 = bs !!! 2
    c4 = bs !!! 3
    x1 = fromChar c1
    x2 = fromChar c2
    x3 = fromChar c3
    x4 = fromChar c4
    bs' = L.drop 4 bs

dec' :: Int -> Int -> Int -> Int -> L.ByteString
dec' x1 x2 x3 x4 = L.pack [d1,d2,d3]
  where
    d1 = chr  ((x1 `shiftL` 2)           .|. (x2 `shiftR` 4))
    d2 = chr (((x2 `shiftL` 4) .&. 0xF0) .|. (x3 `shiftR` 2))
    d3 = chr (((x3 `shiftL` 6) .&. 0xC0) .|. x4)

fromChar :: Char -> Int
fromChar c
 | isUpper c = ord c - ord 'A'
 | isLower c = ord c - ord 'a' + 26
 | isDigit c = ord c - ord '0' + 52
 | c == '+'  = 62
 | c == '/'  = 63
 | otherwise = error ("fromChar: Can't happen: Bad input: " ++ show c)

splits :: Int -> [a] -> [[a]]
splits _ [] = []
splits n xs = case splitAt n xs of
                  (ys, zs) -> ys:splits n zs
