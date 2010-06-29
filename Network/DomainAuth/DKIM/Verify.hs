{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Verify (
    verifyDKIM, prepareDKIM
  ) where

import Codec.Crypto.RSA
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.DKIM.Btag
import Network.DomainAuth.Mail
import Network.DomainAuth.Utils

----------------------------------------------------------------

prepareDKIM :: DKIM -> Mail -> L.ByteString
prepareDKIM dkim mail = cmail
  where
    dkimVal = maybe "" (foldr func "") $ lookupField dkimFieldKey (mailHeader mail)
    -- xxx ": " for SIMPLE
--    dkimSig = dkimFieldKey +++ ":" +++ canon (deleteAfterB dkimVal) +++ ";" --- xx
    dkimSig = dkimFieldKey +++ ":" +++ canon (removeBtagValue dkimVal)
    hCanon = dkimHeaderCanon dkim
    header' = foldr (func . canonDkimFieldValue hCanon) "" fields +++ dkimSig
    fields  = fieldsWith (dkimFields dkim) $ fieldsAfter dkimFieldKey (mailHeader mail)
--    body'   = canonDkimBody (dkimBodyCanon dkim) (mailBody mail) -- to be in verified
    func x y = x +++ crlf +++ y
    cmail = header'

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
verifyDKIM pub sig mail = rsassa_pkcs1_v1_5_verify ha_SHA256 pub mail sig --- xxx chose SHA
