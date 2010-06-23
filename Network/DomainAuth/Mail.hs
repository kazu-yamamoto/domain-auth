{-# LANGUAGE CPP, OverloadedStrings #-}

module Network.DomainAuth.Mail (
    XMail, Mail(..), Header
  , Field, FieldKey, FieldValue, CanonFieldKey
  , Body, BodyChunk, RawMail
  , getMail
  , readMail
  , initialMail
  , pushField
  , pushBody
  , finalizeMail
  , lookupField
  , fieldsAfter
  , fieldsAfterWith
  , canonicalizeKey
  , parseTaggedValue
  ) where

import Control.Applicative
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Data.Int
import System.IO
import Network.DomainAuth.Utils

----------------------------------------------------------------

type Field = L.ByteString
type FieldKey = L.ByteString
type FieldValue = L.ByteString
type CanonFieldKey = L.ByteString
type Body = L.ByteString
type BodyChunk = L.ByteString

type SearchKey = L.ByteString
data IField  = IField {
    fieldKey :: FieldKey
  , fieldValue :: FieldValue
  } deriving (Eq,Show)

composeField :: IField -> L.ByteString
composeField fld = fieldKey fld +++ ": " +++ fieldValue fld

----------------------------------------------------------------

data XMail = XMail {
    xmailHeader :: Header
  , xmailBody :: [BodyChunk]
  } deriving (Eq,Show)

data Mail = Mail {
    mailHeader :: Header
  , mailBody :: Body
  } deriving (Eq,Show)

initialMail :: XMail
initialMail = XMail (Header []) []

type IHeader = [(SearchKey,IField)]

data Header = Header IHeader deriving (Eq,Show)

fromHeader :: Header -> IHeader
fromHeader (Header kvs) = kvs

----------------------------------------------------------------

canonicalizeKey :: FieldKey -> CanonFieldKey
canonicalizeKey = L.map toLower

----------------------------------------------------------------

pushField :: FieldKey -> FieldValue -> XMail -> XMail
pushField key val xmail = xmail {
    xmailHeader = push (skey,field) (xmailHeader xmail)
  }
  where
    push kv (Header kvs) = Header (kv:kvs)
    skey = canonicalizeKey key
    field = IField key val

pushBody :: BodyChunk -> XMail -> XMail
pushBody bc xmail = xmail {
    xmailBody = bc : xmailBody xmail
  }

finalizeMail :: XMail -> Mail
finalizeMail xmail = Mail {
    mailHeader = Header . reverse . fromHeader . xmailHeader $ xmail
  , mailBody = foldl (flip (+++)) "" $ xmailBody xmail
  }

lookupField :: FieldKey -> Mail -> Maybe FieldValue
lookupField key mail = fieldValue <$> lookup skey hdr
  where
    skey = canonicalizeKey key
    hdr = fromHeader (mailHeader mail)

----------------------------------------------------------------

type RawMail = L.ByteString
type RawHeader = L.ByteString
type RawBody = L.ByteString
type RawField = L.ByteString

readMail :: FilePath -> IO Mail
readMail file = getMail <$> readFile8 file
  where
    readFile8 fl = do
        h <- openFile fl ReadMode
#if __GLASGOW_HASKELL__ >= 611
        hSetEncoding h latin1
#endif
        L.hGetContents h

getMail :: RawMail -> Mail
getMail bs = finalizeMail $ pushBody rbdy xmail
  where
    (rhdr,rbdy) = splitHeaderBody bs
    rflds = splitFields rhdr
    xmail = foldl push initialMail rflds
    push m fld = let (k,v) = parseField fld
                 in pushField k v m

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

splitHeaderBody :: RawMail -> (RawHeader,RawBody)
splitHeaderBody bs = case mcnt of
    Nothing  -> (bs,"")
    Just cnt -> check (L.splitAt cnt bs)
  where
    mcnt = findEOH bs 0
    check (hdr,bdy) = if bdy == ""
                      then (hdr, bdy)
                      else (hdr, L.tail bdy) -- xxx need to check Sendmail

findEOH :: RawMail -> Int64 -> Maybe Int64
findEOH "" _ = Nothing
findEOH bs cnt
  | b == '\n' && bs' /= "" && L.head bs' == '\n' = Just (cnt + 1)
  | otherwise                                    = findEOH bs' (cnt + 1)
  where
    b   = L.head bs
    bs' = L.tail bs

fieldsAfter :: FieldKey -> Header -> [Field]
fieldsAfter key hdr = map (composeField . snd) . fieldsAfter' (canonicalizeKey key) $ fromHeader hdr

fieldsAfterWith :: FieldKey -> (CanonFieldKey -> Bool) -> Header -> [Field]
fieldsAfterWith key func hdr = map (composeField . snd) . filter predicate . fieldsAfter' (canonicalizeKey key) $ fromHeader hdr
  where
    predicate (k,_) = func k

fieldsAfter' :: FieldKey -> IHeader -> IHeader
fieldsAfter' _ [] = []
fieldsAfter' key ((k,_):kfs)
  | key == k  = kfs
  | otherwise = fieldsAfter' key kfs

----------------------------------------------------------------

parseField :: Field -> (FieldKey,FieldValue)
parseField bs = (k,v')
  where
    (k,v) = break' ':' bs
    -- Sendmail drops ' ' after ':'.
    v' = if v /= "" && L.head v == ' '
         then L.tail v
         else v


-- This breaks spaces in the note tag.
parseTaggedValue :: FieldValue -> [(L.ByteString,L.ByteString)]
parseTaggedValue xs = vss
  where
    v = L.filter (not.isSpace) xs
    vs = filter (/= "") $ L.split ';' v
    vss = map (break' '=') vs

break' :: Char -> L.ByteString -> (L.ByteString,L.ByteString)
break' c bs = (f,s)
  where
    (f,s') = L.break (==c) bs
    s = if s' == ""
        then ""
        else L.tail s'

