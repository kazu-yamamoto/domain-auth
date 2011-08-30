{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Utils where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Char

crlf :: ByteString
crlf = "\r\n"

(+++) :: ByteString -> ByteString -> ByteString
(+++) = BS.append

(!!!) :: ByteString -> Int -> Char
(!!!) = BS.index

----------------------------------------------------------------

appendCRLF :: ByteString -> ByteString -> ByteString
appendCRLF x y = x +++ crlf +++ y

appendCRLFWith :: (a -> ByteString) -> a -> ByteString -> ByteString
appendCRLFWith modify x y = modify x +++ crlf +++ y

concatCRLF :: [ByteString] -> ByteString
concatCRLF = foldr appendCRLF ""

concatCRLFWith :: (a -> ByteString) -> [a] -> ByteString
concatCRLFWith modify = foldr (appendCRLFWith modify) ""

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
  | BS.last bs == '\r' = BS.init bs
  | otherwise         = bs

blines :: ByteString -> [ByteString]
blines = map chop . BS.lines

----------------------------------------------------------------

break' :: Char -> ByteString -> (ByteString,ByteString)
break' c bs = (f,s)
  where
    (f,s') = BS.break (==c) bs
    s = if s' == ""
        then ""
        else BS.tail s'
