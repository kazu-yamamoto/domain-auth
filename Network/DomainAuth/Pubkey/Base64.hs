{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Pubkey.Base64 (
    decode
  , decode'
  ) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as BL
import Data.Word
import Network.DomainAuth.Utils

isBase64 :: Word8 -> Bool
isBase64 c = isAlphaNum c || (c `elem` [cPlus,cSlash,cEqual])

decode :: ByteString -> ByteString
decode = BL.toStrict . decode'

decode' :: ByteString -> BL.ByteString
decode' = BB.toLazyByteString . dec . BS.filter isBase64

dec :: ByteString -> Builder
dec bs
    | BS.null bs               = empty
    | len == 4 && c3 == cEqual = dec1' x1 x2
    | len == 4 && c4 == cEqual = dec2' x1 x2 x3
    | len >= 4                 = dec' x1 x2 x3 x4 +++ dec bs'
    | otherwise                = error "dec"
  where
    len = BS.length bs
    c1 = bs !!! 0
    c2 = bs !!! 1
    c3 = bs !!! 2
    c4 = bs !!! 3
    x1 = fromChar c1
    x2 = fromChar c2
    x3 = fromChar c3
    x4 = fromChar c4
    bs' = BS.drop 4 bs

dec' :: Word8 -> Word8 -> Word8 -> Word8 -> Builder
dec' x1 x2 x3 x4 = BB.word8 d1 <> BB.word8 d2 <> BB.word8 d3
  where
    d1 =  (x1 `shiftL` 2)           .|. (x2 `shiftR` 4)
    d2 = ((x2 `shiftL` 4) .&. 0xF0) .|. (x3 `shiftR` 2)
    d3 = ((x3 `shiftL` 6) .&. 0xC0) .|. x4

dec1' :: Word8 -> Word8 -> Builder
dec1' x1 x2 = BB.word8 d1
  where
    d1 =  (x1 `shiftL` 2)           .|. (x2 `shiftR` 4)

dec2' :: Word8 -> Word8 -> Word8 -> Builder
dec2' x1 x2 x3 = BB.word8 d1 <> BB.word8 d2
  where
    d1 =  (x1 `shiftL` 2)           .|. (x2 `shiftR` 4)
    d2 = ((x2 `shiftL` 4) .&. 0xF0) .|. (x3 `shiftR` 2)

fromChar :: Word8 -> Word8
fromChar c
 | isUpper c   = c - cA
 | isLower c   = c - cSmallA + 26
 | isDigit c   = c - cZero   + 52
 | c == cPlus  = 62
 | c == cSlash = 63
 | otherwise = error ("fromChar: Can't happen: Bad input: " ++ show c)

{-
splits :: Int -> [a] -> [[a]]
splits _ [] = []
splits n xs = case splitAt n xs of
                  (ys, zs) -> ys:splits n zs
-}
