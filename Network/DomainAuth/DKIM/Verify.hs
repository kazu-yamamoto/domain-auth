{-# LANGUAGE OverloadedStrings #-}
module Network.DomainAuth.DKIM.Verify (
    verifyDKIM, prepareDKIM
  , deleteAfterB -- just for test
  ) where

import Codec.Crypto.RSA
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Int
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.Mail
import Network.DomainAuth.Utils
import Data.Digest.Pure.SHA

----------------------------------------------------------------

prepareDKIM :: DKIM -> Mail -> L.ByteString
prepareDKIM dkim mail = bytestringDigest $ sha256 body'
  where
--    dkimVal = fromMaybe "" $ lookupField dkimFieldKey mail
--    dkimSig = dkimFieldKey +++ ":" +++ canonDkimFieldValue DKIM_RELAXED (deleteAfterB dkimVal)
    {- xxx
    fold with (+++crlf)
       skey +++ ":" +++ canonDkimFieldValue
    +++ dkimSig
    -}
--    fields  = fieldsForDKIM dkimFieldKey (dkimFields dkim) (mailHeader mail)
    body'   = canonDkimBody (dkimBodyCanon dkim) (mailBody mail)

----------------------------------------------------------------

{-
  The spec of RFC4871 is complicated and imperfect.
  Let's remove chars after "b=" assuming no SP between "b" and "=".
-}

deleteAfterB :: L.ByteString -> L.ByteString
deleteAfterB bs = fst $ L.splitAt pos bs
  where
    pos = findB bs 0

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

----------------------------------------------------------------

-- xxx read RPF again!
    {-
canonDkimFieldValue :: DkimCanonAlgo -> FieldValue -> FieldValue
canonDkimFieldValue DKIM_SIMPLE  _ = "" -- does not support
canonDkimFieldValue DKIM_RELAXED bs = canon bs
  where
    canon = removeTrailingWSP . reduceWSP . L.dropWhile isSpace
-}

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
--verifyDKIM pub sig mail = rsassa_pkcs1_v1_5_verify ha_SHA256 pub mail sig --- xxx chose SHA
verifyDKIM _ sig mail = sig == mail
