{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.Mail where

import Control.Applicative hiding (empty)
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Data.Int
import Data.List
import Data.Foldable as F (foldr)
import Data.Sequence (Seq, fromList, viewr, ViewR(..), empty)
import Network.DomainAuth.Utils

----------------------------------------------------------------

data Mail = Mail {
    mailHeader :: Header
  , mailBody :: Body
  } deriving (Eq,Show)

type Header = [Field]

data Field  = Field {
    fieldSearchKey :: CanonFieldKey
  , fieldKey       :: FieldKey
  , fieldValue     :: FieldValue
  } deriving (Eq,Show)

type CanonFieldKey = L.ByteString
type FieldKey = L.ByteString
type FieldValue = [L.ByteString]

toRaw :: FieldValue -> RawFieldValue
toRaw = L.concat

type Body = Seq L.ByteString

composeField :: Field -> L.ByteString
composeField fld = L.concat $ fieldKey fld : ": " : fieldValue fld

----------------------------------------------------------------

canonicalizeKey :: FieldKey -> CanonFieldKey
canonicalizeKey = L.map toLower

----------------------------------------------------------------

data XMail = XMail {
    xmailHeader :: Header
  , xmailBody :: [RawBodyChunk]
  } deriving (Eq,Show)

type RawBodyChunk = L.ByteString

initialXMail :: XMail
initialXMail = XMail [] []

pushField :: RawFieldKey -> RawFieldValue -> XMail -> XMail
pushField key val xmail = xmail {
    xmailHeader = fld : xmailHeader xmail
  }
  where
    fld = Field ckey key (blines val)
    ckey = canonicalizeKey key

pushBody :: RawBodyChunk -> XMail -> XMail
pushBody bc xmail = xmail {
    xmailBody = bc : xmailBody xmail
  }

finalizeMail :: XMail -> Mail
finalizeMail xmail = Mail {
    mailHeader = reverse . xmailHeader $ xmail
  , mailBody = fromList . blines . L.concat . reverse . xmailBody $ xmail
  }

lookupField :: FieldKey -> Header -> Maybe FieldValue
lookupField key hdr = fieldValue <$> find (ckey `isKeyOf`) hdr
  where
    ckey = canonicalizeKey key

isKeyOf :: CanonFieldKey -> Field -> Bool
isKeyOf key fld = fieldSearchKey fld == key

isNotKeyOf :: CanonFieldKey -> Field -> Bool
isNotKeyOf key fld = fieldSearchKey fld /= key

----------------------------------------------------------------

type RawMail = L.ByteString
type RawHeader = L.ByteString
type RawBody = L.ByteString
type RawField = L.ByteString
type RawFieldKey = L.ByteString
type RawFieldValue = L.ByteString

readMail :: FilePath -> IO Mail
readMail file = getMail <$> L.readFile file

getMail :: RawMail -> Mail
getMail bs = finalizeMail $ pushBody rbdy xmail
  where
    (rhdr,rbdy) = splitHeaderBody bs
    rflds = splitFields rhdr
    xmail = foldl push initialXMail rflds
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

fieldsAfter :: FieldKey -> Header -> Header
fieldsAfter key hdr = safeTail flds
  where
    flds = dropWhile (ckey `isNotKeyOf`) hdr
    ckey = canonicalizeKey key
    safeTail [] = []
    safeTail xs = tail xs

----------------------------------------------------------------

{-
  RFC 4871 is ambiguous, so implement only normal case.
-}

fieldsWith :: [CanonFieldKey] -> Header -> Header
fieldsWith [] _ = []
fieldsWith _ [] = []
fieldsWith (k:ks) is
  | fs == []  = fieldsWith (k:ks) (tail is')
  | otherwise = take len (reverse fs) ++ fieldsWith ks' is'
  where
    (fs,is') = span (\fld -> fieldSearchKey fld == k) is
    (kx,ks') = span (==k) ks
    len = length kx + 1 -- including k

----------------------------------------------------------------

parseField :: RawField -> (RawFieldKey,RawFieldValue)
parseField bs = (k,v')
  where
    (k,v) = break' ':' bs
    -- Sendmail drops ' ' after ':'.
    v' = if v /= "" && L.head v == ' '
         then L.tail v
         else v

-- This breaks spaces in the note tag.
parseTaggedValue :: RawFieldValue -> [(L.ByteString,L.ByteString)]
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

----------------------------------------------------------------

removeTrailingEmptyLine :: Body -> Body
removeTrailingEmptyLine = dropWhileR (=="")

-- dropWhileR is buggy, sigh.
dropWhileR :: (a -> Bool) -> Seq a -> Seq a
dropWhileR p xs = case viewr xs of
    EmptyR        -> empty
    xs' :> x
      | p x       -> dropWhileR p xs'
      | otherwise -> xs

fromBody :: Body -> L.ByteString
fromBody = fromBodyWith id

fromBodyWith :: (L.ByteString -> L.ByteString) -> Body -> L.ByteString
fromBodyWith modify = F.foldr func ""
  where
    func x y = modify x +++ crlf +++ y
