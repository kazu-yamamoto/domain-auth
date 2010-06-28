{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Verify (
    verifyDKIM, prepareDKIM
  , deleteAfterB -- just for test
  ) where

import Codec.Crypto.RSA
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Data.Int
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.Mail
import Network.DomainAuth.Utils

import Debug.Trace

----------------------------------------------------------------

prepareDKIM :: DKIM -> Mail -> L.ByteString
prepareDKIM dkim mail = cmail
  where
    dkimVal = maybe "" (foldr func "") $ lookupField dkimFieldKey (mailHeader mail)
    -- xxx ": " for SIMPLE
    dkimSig = dkimFieldKey +++ ":" +++ canon (deleteAfterB dkimVal)
    hCanon = dkimHeaderCanon dkim
    header' = (foldr func "" $ map (canonDkimFieldValue hCanon) fields)
          +++ dkimSig
    fields  = fieldsForDKIM dkimFieldKey (dkimFields dkim) (mailHeader mail)
--    body'   = canonDkimBody (dkimBodyCanon dkim) (mailBody mail) -- to be in verified
    func x y = x +++ crlf +++ y
    cmail = header'

----------------------------------------------------------------

{-
  The spec of RFC4871 is complicated and imperfect.
  Let's remove chars after "b=" assuming no SP between "b" and "=".
-}

deleteAfterB :: L.ByteString -> L.ByteString
deleteAfterB bs = fst $ L.splitAt pos' bs
  where
    pos = findB bs 0
    pos' = trackLFSP bs pos

findB :: L.ByteString -> Int64 -> Int64
findB "" pos = pos
findB bs pos
  | c == 'b' && len >= 2 && c' == '=' = pos
  | otherwise                         = findB bs' (pos + 1)
  where
    c = L.head bs
    bs' = L.tail bs
    c' = L.head bs'
    len = L.length bs

trackLFSP :: L.ByteString -> Int64 -> Int64
trackLFSP "" pos = pos
trackLFSP bs pos
  | isSpace c = trackLFSP bs (pos - 1)
  | otherwise = pos
  where
    c = bs `L.index` (pos - 1)

----------------------------------------------------------------

canonDkimFieldValue :: DkimCanonAlgo -> Field -> L.ByteString
canonDkimFieldValue DKIM_SIMPLE fld = fieldKey fld +++ ": " +++ value fld
  where
    value = foldr func "" . fieldValue
    func x y = x +++ crlf +++ y
canonDkimFieldValue DKIM_RELAXED fld = fieldSearchKey fld +++ ":" +++ value fld
  where
    value = canon . L.concat . fieldValue

canon :: L.ByteString -> L.ByteString
canon = L.dropWhile isSpace . removeTrailingWSP . reduceWSP

----------------------------------------------------------------

canonDkimBody :: DkimCanonAlgo -> Body -> L.ByteString
canonDkimBody DKIM_SIMPLE bd  = canonDkimBodyCore id removeTrailingEmptyLine bd
canonDkimBody DKIM_RELAXED bd = canonDkimBodyCore relax removeTrailingEmptyLine bd
  where
    relax = removeTrailingWSP . reduceWSP

canonDkimBodyCore :: Cook -> (Body -> Body) -> Body -> L.ByteString
canonDkimBodyCore remFWS remTEL = fromBodyWith remFWS . remTEL

----------------------------------------------------------------

verifyDKIM :: PublicKey -> L.ByteString -> L.ByteString -> Bool
verifyDKIM pub sig mail = rsassa_pkcs1_v1_5_verify ha_SHA256 pub (trace (L.unpack mail) mail) sig --- xxx chose SHA
