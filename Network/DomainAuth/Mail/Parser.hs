{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Mail.Parser where

import Control.Applicative
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Data.Int
import Network.DomainAuth.Mail.Types
import Network.DomainAuth.Mail.XMail
import Network.DomainAuth.Utils

----------------------------------------------------------------

-- | Obtain 'Mail' from a file.
readMail :: FilePath -> IO Mail
readMail file = getMail <$> L.readFile file

----------------------------------------------------------------

-- | Obtain 'Mail' from 'RawMail'.
getMail :: RawMail -> Mail
getMail bs = finalizeMail $ pushBody rbdy xmail
  where
    (rhdr,rbdy) = splitHeaderBody bs
    rflds = splitFields rhdr
    xmail = foldl push initialXMail rflds
    push m fld = let (k,v) = parseField fld
                 in pushField k v m

----------------------------------------------------------------

splitHeaderBody :: RawMail -> (RawHeader,RawBody)
splitHeaderBody bs = case mcnt of
    Nothing  -> (bs,"")
    Just cnt -> check (L.splitAt cnt bs)
  where
    mcnt = findEOH bs 0
    check (hdr,bdy) = (hdr, dropSep bdy)
    dropSep bdy
      | len == 0 = ""
      | len == 1 = ""
      | otherwise = if b1 == '\r' then bdy3 else bdy2
      where
        len = L.length bdy
        b1 = L.head bdy
        bdy2 = L.tail bdy
        bdy3 = L.tail bdy2

findEOH :: RawMail -> Int64 -> Maybe Int64
findEOH "" _ = Nothing
findEOH bs cnt
  | b0 == '\n' && bs1 /= "" && b1 == '\n' = Just (cnt + 1)
  | b0 == '\n' && bs1 /= "" && b1 == '\r'
               && bs2 /= "" && b2 == '\n' = Just (cnt + 1)
  | otherwise                             = findEOH bs1 (cnt + 1)
  where
    b0  = L.head bs
    bs1 = L.tail bs
    b1  = L.head bs1
    bs2 = L.tail bs1
    b2  = L.head bs2

----------------------------------------------------------------

splitFields :: RawHeader -> [RawField]
splitFields "" = []
splitFields bs = fld : splitFields bs''
  where
    -- split before '\n' for efficiency
    (fld,bs') = L.splitAt (findFieldEnd bs 0 - 1) bs
    bs'' = L.tail bs'

findFieldEnd :: RawMail -> Int64 -> Int64
findFieldEnd bs cnt
    | bs == ""   = cnt
    | b  == '\n' = begOfLine bs' (cnt + 1)
    | otherwise  = findFieldEnd bs' (cnt + 1)
  where
    b   = L.head bs
    bs' = L.tail bs

begOfLine :: RawMail -> Int64 -> Int64
begOfLine bs cnt
    | bs == ""      = cnt
    | isContinued b = findFieldEnd bs' (cnt + 1)
    | otherwise     = cnt
  where
    b   = L.head bs
    bs' = L.tail bs

isContinued :: Char -> Bool
isContinued c = c `elem` " \t"

----------------------------------------------------------------

parseField :: RawField -> (RawFieldKey,RawFieldValue)
parseField bs = (k,v')
  where
    (k,v) = break' ':' bs
    -- Sendmail drops ' ' after ':'.
    v' = if v /= "" && L.head v == ' '
         then L.tail v
         else v

----------------------------------------------------------------

{-|
  Parsing field value of tag=value.
-}
-- This breaks spaces in the note tag.
parseTaggedValue :: RawFieldValue -> [(L.ByteString,L.ByteString)]
parseTaggedValue xs = vss
  where
    v = L.filter (not.isSpace) xs
    vs = filter (/= "") $ L.split ';' v
    vss = map (break' '=') vs
