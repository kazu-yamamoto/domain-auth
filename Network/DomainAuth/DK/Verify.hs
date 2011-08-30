{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DK.Verify (
    verifyDK, prepareDK
  ) where

import Codec.Crypto.RSA
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L
import qualified Data.Map as M
import Network.DomainAuth.DK.Types
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B
import Network.DomainAuth.Utils

----------------------------------------------------------------

prepareDK :: DK -> Mail -> ByteString
prepareDK dk mail = cmail
  where
    header' = canonDkHeader dk (mailHeader mail)
    body'   = canonDkBody (dkCanonAlgo dk) (mailBody mail)
    cmail   = if body' == "" then header' else header' `appendCRLF` body'

----------------------------------------------------------------

canonDkHeader :: DK -> Header -> ByteString
canonDkHeader dk hdr = concatCRLFWith (canonDkField calgo) flds
  where
    calgo = dkCanonAlgo dk
    hFields = dkFields dk
    flds = prepareDkHeader hFields hdr

canonDkField :: DkCanonAlgo -> Field -> ByteString
canonDkField DK_SIMPLE fld = fieldKey fld +++ ": " +++ fieldValueFolded fld
canonDkField DK_NOFWS  fld = fieldKey fld +++ ":" +++ removeFWS (fieldValueUnfolded fld)

prepareDkHeader :: Maybe DkFields -> Header -> Header
prepareDkHeader Nothing hdr = fieldsAfter dkFieldKey hdr
prepareDkHeader (Just hFields) hdr = filter isInHTag $ fieldsAfter dkFieldKey hdr
  where
    isInHTag fld = M.member (fieldSearchKey fld) hFields

----------------------------------------------------------------

canonDkBody :: DkCanonAlgo -> Body -> ByteString
canonDkBody DK_SIMPLE = fromBody . removeTrailingEmptyLine
canonDkBody DK_NOFWS  = fromBodyWith removeFWS . removeTrailingEmptyLine

----------------------------------------------------------------

verifyDK :: Mail -> DK -> PublicKey -> Bool
verifyDK mail dk pub = rsassa_pkcs1_v1_5_verify ha_SHA1 pub cmail sig
  where
    sig = L.fromChunks [B.decode (dkSignature dk)]
    cmail = L.fromChunks [prepareDK dk mail]
