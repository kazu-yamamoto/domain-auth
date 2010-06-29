{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Utils where

import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Data.Int

crlf :: L.ByteString
crlf = "\r\n"

(+++) :: L.ByteString -> L.ByteString -> L.ByteString
(+++) = L.append

(!!!) :: L.ByteString -> Int64 -> Char
(!!!) = L.index

----------------------------------------------------------------

appendCRLF :: L.ByteString -> L.ByteString -> L.ByteString
appendCRLF x y = x +++ crlf +++ y

appendCRLFWith :: (a -> L.ByteString) -> a -> L.ByteString -> L.ByteString
appendCRLFWith modify x y = modify x +++ crlf +++ y

concatCRLF :: [L.ByteString] -> L.ByteString
concatCRLF = foldr appendCRLF ""

concatCRLFWith :: (a -> L.ByteString) -> [a] -> L.ByteString
concatCRLFWith modify = foldr (appendCRLFWith modify) ""

----------------------------------------------------------------

{-|
  Replaces multiple WPSs to a single SP.
-}
reduceWSP :: Cook
reduceWSP "" = ""
reduceWSP bs
  | isSpace (L.head bs) = inSP bs
  | otherwise           = outSP bs

inSP :: Cook
inSP "" = ""
inSP bs = " " +++ outSP bs'
  where
    (_,bs') = L.span isSpace bs

outSP :: Cook
outSP "" = ""
outSP bs = nonSP +++ inSP bs'
  where
    (nonSP,bs') = L.break isSpace bs

----------------------------------------------------------------

type FWSRemover = L.ByteString -> L.ByteString

removeFWS :: FWSRemover
removeFWS = L.filter (not.isSpace)

----------------------------------------------------------------

type Cook = L.ByteString -> L.ByteString

removeTrailingWSP :: Cook
removeTrailingWSP bs
  | slowPath  = L.reverse . L.dropWhile isSpace . L.reverse $ bs  -- xxx
  | otherwise = bs
  where
    slowPath = hasTrailingWSP bs

hasTrailingWSP :: L.ByteString -> Bool
hasTrailingWSP bs
    | len == 0  = False
    | otherwise = isSpace lastChar
  where
    len = L.length bs
    lastChar = bs !!! (len - 1)

----------------------------------------------------------------

chop :: L.ByteString -> L.ByteString
chop "" = ""
chop bs
  | L.last bs == '\r' = L.init bs
  | otherwise         = bs

blines :: L.ByteString -> [L.ByteString]
blines = map chop . L.lines
