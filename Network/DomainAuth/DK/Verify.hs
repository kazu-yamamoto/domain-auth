{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DK.Verify (
    verifyDK, prepareDK
  ) where

import Codec.Crypto.RSA
import qualified Data.ByteString.Lazy.Char8 as L
import qualified Data.Map as M
import Network.DomainAuth.DK.Types
import Network.DomainAuth.Mail
import Network.DomainAuth.Utils

----------------------------------------------------------------

-- xxx when body' is empty dont' add crlf
prepareDK :: DK -> Mail -> L.ByteString
prepareDK dk mail = cmail
  where
    header' = canonDkHeader dk (mailHeader mail)
    body'   = canonDkBody (dkCanonAlgo dk) (mailBody mail)
    cmail   = if body' == "" then header' else header' +++ crlf +++ body'

----------------------------------------------------------------

canonDkHeader :: DK -> Header -> L.ByteString
canonDkHeader dk hdr = canonDkHeader' calgo flds
  where
    calgo = dkCanonAlgo dk
    hFields = dkFields dk
    flds = prepareDkHeader hFields hdr

canonDkHeader' :: DkCanonAlgo -> Header -> L.ByteString
canonDkHeader' DK_NOFWS  = canonDkHeaderCore fromField
  where
    fromField fld = L.concat $ fieldKey fld : ":" : map removeFWS (fieldValue fld)
canonDkHeader' DK_SIMPLE = canonDkHeaderCore fromField
  where
    fromField fld = L.concat $ fieldKey fld : ": " : fieldValue fld

canonDkHeaderCore :: (Field -> L.ByteString) -> Header -> L.ByteString
canonDkHeaderCore fromField = foldr (op . fromField) ""
  where
    a `op` b = a +++ crlf +++ b

prepareDkHeader :: Maybe DkFields -> Header -> Header
prepareDkHeader Nothing hdr = fieldsAfter dkFieldKey hdr
prepareDkHeader (Just hFields) hdr = filter isInHTag $ fieldsAfter dkFieldKey hdr
  where
    isInHTag fld = M.member (fieldSearchKey fld) hFields

----------------------------------------------------------------

canonDkBody :: DkCanonAlgo -> Body -> L.ByteString
canonDkBody DK_SIMPLE bd = fromBody . removeTrailingEmptyLine $ bd
canonDkBody DK_NOFWS  bd = fromBodyWith removeFWS . removeTrailingEmptyLine $ bd

----------------------------------------------------------------

verifyDK :: PublicKey -> L.ByteString -> L.ByteString -> Bool
verifyDK pub sig mail = rsassa_pkcs1_v1_5_verify ha_SHA1 pub mail sig
