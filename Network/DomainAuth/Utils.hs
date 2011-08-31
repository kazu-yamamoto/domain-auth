{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Utils where

import Blaze.ByteString.Builder
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS (lines)
import Data.Monoid
import Data.Word

crlf :: Builder
crlf = fromByteString "\r\n"

(+++) :: Monoid a => a -> a -> a
(+++) = mappend

empty :: Monoid a => a
empty = mempty

(!!!) :: ByteString -> Int -> Word8
(!!!) = BS.index

----------------------------------------------------------------

appendCRLF :: Builder -> Builder -> Builder
appendCRLF x y = x +++ crlf +++ y

appendCRLF' :: ByteString -> Builder -> Builder
appendCRLF' x = appendCRLF (fromByteString x)

appendCRLFWith :: (a -> ByteString) -> a -> Builder -> Builder
appendCRLFWith modify x y = fromByteString (modify x) +++ crlf +++ y

concatCRLF :: [ByteString] -> Builder
concatCRLF = foldr appendCRLF' empty

concatCRLFWith :: (a -> ByteString) -> [a] -> Builder
concatCRLFWith modify = foldr (appendCRLFWith modify) empty

----------------------------------------------------------------

{-|
  Replaces multiple WPSs to a single SP.
-}
reduceWSP :: Cook
reduceWSP "" = ""
reduceWSP bs
  | isSpace (BS.head bs) = inSP bs
  | otherwise           = outSP bs

inSP :: Cook
inSP "" = ""
inSP bs = " " +++ outSP bs'
  where
    (_,bs') = BS.span isSpace bs

outSP :: Cook
outSP "" = ""
outSP bs = nonSP +++ inSP bs'
  where
    (nonSP,bs') = BS.break isSpace bs

----------------------------------------------------------------

type FWSRemover = ByteString -> ByteString

removeFWS :: FWSRemover
removeFWS = BS.filter (not.isSpace)

----------------------------------------------------------------

type Cook = ByteString -> ByteString

removeTrailingWSP :: Cook
removeTrailingWSP bs
  | slowPath  = BS.reverse . BS.dropWhile isSpace . BS.reverse $ bs  -- xxx
  | otherwise = bs
  where
    slowPath = hasTrailingWSP bs

hasTrailingWSP :: ByteString -> Bool
hasTrailingWSP bs
    | len == 0  = False
    | otherwise = isSpace lastChar
  where
    len = BS.length bs
    lastChar = bs !!! (len - 1)

----------------------------------------------------------------

chop :: ByteString -> ByteString
chop "" = ""
chop bs
  | BS.last bs == 13 = BS.init bs -- 13 == '\r'
  | otherwise        = bs

blines :: ByteString -> [ByteString]
blines = map chop . BS.lines

----------------------------------------------------------------

break' :: Word8 -> ByteString -> (ByteString,ByteString)
break' c bs = (f,s)
  where
    (f,s') = BS.break (==c) bs
    s = if s' == ""
        then ""
        else BS.tail s'

----------------------------------------------------------------

isAlphaNum, isUpper, isLower, isDigit, isSpace :: Word8 -> Bool
isAlphaNum c = isUpper c || isLower c || isDigit c
isDigit c = 48 <= c && c <= 57
isUpper c = 65 <= c && c <= 90
isLower c = 97 <= c && c <= 122
isSpace c = c `elem` [cSP,cTB,cLF,cCR]

cCR, cLF, cSP, cTB :: Word8
cCR = 13
cLF = 10
cSP = 32
cTB =  9

cPlus,cSlash,cEqual,cSmallA,cA,cZero :: Word8
cPlus  = 43
cSlash = 47
cEqual = 61
cSmallA = 97
cA = 65
cZero = 48

cColon,cSemiColon :: Word8
cColon = 58
cSemiColon = 59
