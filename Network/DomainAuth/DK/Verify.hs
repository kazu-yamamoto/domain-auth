{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DK.Verify (
    verifyDK, prepareDK
  ) where

import Blaze.ByteString.Builder
import Crypto.Hash
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map as M
import Network.DomainAuth.DK.Types
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B
import Network.DomainAuth.Utils

----------------------------------------------------------------

prepareDK :: DK -> Mail -> Builder
prepareDK dk mail = cmail
  where
    header' = canonDkHeader dk (mailHeader mail)
    body'   = canonDkBody (dkCanonAlgo dk) (mailBody mail)
    cmail   = if isEmpty (mailBody mail) then
                  header'
              else
                  header' `appendCRLF` body'

----------------------------------------------------------------

canonDkHeader :: DK -> Header -> Builder
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

canonDkBody :: DkCanonAlgo -> Body -> Builder
canonDkBody DK_SIMPLE = fromBody . removeTrailingEmptyLine
canonDkBody DK_NOFWS  = fromBodyWith removeFWS . removeTrailingEmptyLine

----------------------------------------------------------------

verifyDK :: Mail -> DK -> PublicKey -> Bool
verifyDK mail dk pub = verify (Just SHA1) pub cmail sig
  where
    sig = BL.toStrict $ B.decode . dkSignature $ dk
    cmail = toByteString (prepareDK dk mail)
