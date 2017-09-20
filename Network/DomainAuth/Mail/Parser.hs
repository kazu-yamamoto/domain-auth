{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Mail.Parser where

import qualified Data.ByteString as BS
import Data.Word
import Network.DomainAuth.Mail.Types
import Network.DomainAuth.Mail.XMail
import Network.DomainAuth.Utils

-- $setup
-- >>> :set -XOverloadedStrings

----------------------------------------------------------------

-- | Obtain 'Mail' from a file.
--
-- >>> let out1 = finalizeMail $ pushBody "body" $ pushField "to" "val" $ pushField "from" "val" initialXMail
-- >>> getMail "from: val\nto: val\n\nbody" == out1
-- True
-- >>> let out2 = finalizeMail $ pushBody "body" $ pushField "to" "val" $ pushField "from" "val\tval" initialXMail
-- >>> getMail "from: val\tval\nto: val\n\nbody" == out2
-- True
-- >>> let out3 = finalizeMail $ pushBody "" $ pushField "to" "val" $ pushField "from" "val" initialXMail
-- >>> getMail "from: val\nto: val\n" == out3
-- True
readMail :: FilePath -> IO Mail
readMail file = getMail <$> BS.readFile file

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
    Just cnt -> check (BS.splitAt cnt bs)
  where
    mcnt = findEOH bs 0
    check (hdr,bdy) = (hdr, dropSep bdy)
    dropSep bdy
      | len == 0 = ""
      | len == 1 = ""
      | otherwise = if b1 == cCR then bdy3 else bdy2
      where
        len = BS.length bdy
        b1 = BS.head bdy
        bdy2 = BS.tail bdy
        bdy3 = BS.tail bdy2

findEOH :: RawMail -> Int -> Maybe Int
findEOH "" _ = Nothing
findEOH bs cnt
  | b0 == cLF && bs1 /= "" && b1 == cLF = Just (cnt + 1)
  | b0 == cLF && bs1 /= "" && b1 == cCR
              && bs2 /= "" && b2 == cLF = Just (cnt + 1)
  | otherwise                           = findEOH bs1 (cnt + 1)
  where
    b0  = BS.head bs
    bs1 = BS.tail bs
    b1  = BS.head bs1
    bs2 = BS.tail bs1
    b2  = BS.head bs2

----------------------------------------------------------------

splitFields :: RawHeader -> [RawField]
splitFields "" = []
splitFields bs = fld : splitFields bs''
  where
    -- split before cLF for efficiency
    (fld,bs') = BS.splitAt (findFieldEnd bs 0 - 1) bs
    bs'' = BS.tail bs'

findFieldEnd :: RawMail -> Int -> Int
findFieldEnd bs cnt
    | bs == ""   = cnt
    | b  == cLF = begOfLine bs' (cnt + 1)
    | otherwise  = findFieldEnd bs' (cnt + 1)
  where
    b   = BS.head bs
    bs' = BS.tail bs

begOfLine :: RawMail -> Int -> Int
begOfLine bs cnt
    | bs == ""      = cnt
    | isContinued b = findFieldEnd bs' (cnt + 1)
    | otherwise     = cnt
  where
    b   = BS.head bs
    bs' = BS.tail bs

isContinued :: Word8 -> Bool
isContinued = isSpace

----------------------------------------------------------------

parseField :: RawField -> (RawFieldKey,RawFieldValue)
parseField bs = (k,v')
  where
    (k,v) = break' cColon bs
    -- Sendmail drops ' ' after ':'.
    v' = if v /= "" && BS.head v == cSP
         then BS.tail v
         else v

----------------------------------------------------------------
-- This breaks spaces in the note tag.

-- | Parsing field value of tag=value.
--
-- >>> parseTaggedValue " k = rsa ; p= MIGfMA0G; n=A 1024 bit key;"
-- [("k","rsa"),("p","MIGfMA0G"),("n","A1024bitkey")]
-- >>> parseTaggedValue " k = \nrsa ;\n p= MIGfMA0G;\n n=A 1024 bit key"
-- [("k","rsa"),("p","MIGfMA0G"),("n","A1024bitkey")]
parseTaggedValue :: RawFieldValue -> [(BS.ByteString,BS.ByteString)]
parseTaggedValue xs = vss
  where
    v = BS.filter (not.isSpace) xs
    vs = filter (/= "") $ BS.split cSemiColon v
    vss = map (break' cEqual) vs
