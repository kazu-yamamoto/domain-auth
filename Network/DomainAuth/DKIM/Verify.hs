{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Verify (
    verifyDKIM, prepareDKIM
  ) where

import Blaze.ByteString.Builder
import Codec.Crypto.RSA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.Digest.Pure.SHA
import Network.DomainAuth.DKIM.Btag
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B
import Network.DomainAuth.Utils

----------------------------------------------------------------

prepareDKIM :: DKIM -> Mail -> Builder
prepareDKIM dkim mail = header
  where
    dkimField:fields = fieldsFrom dkimFieldKey (mailHeader mail)
    hCanon = canonDkimField (dkimHeaderCanon dkim)
    canon = fromByteString . removeBtagValue . hCanon
    targets = fieldsWith (dkimFields dkim) fields
    header = concatCRLFWith hCanon targets +++ canon dkimField

----------------------------------------------------------------

canonDkimField :: DkimCanonAlgo -> Field -> ByteString
canonDkimField DKIM_SIMPLE fld  = fieldKey fld +++ ": " +++ fieldValueFolded fld
canonDkimField DKIM_RELAXED fld = fieldSearchKey fld +++ ":" +++ canon fld
  where
    canon = BS.dropWhile isSpace . removeTrailingWSP . reduceWSP . BS.concat . fieldValue

----------------------------------------------------------------

canonDkimBody :: DkimCanonAlgo -> Body -> Builder
canonDkimBody DKIM_SIMPLE  = fromBody . removeTrailingEmptyLine
canonDkimBody DKIM_RELAXED = fromBodyWith relax . removeTrailingEmptyLine
  where
    relax = removeTrailingWSP . reduceWSP

----------------------------------------------------------------

verifyDKIM :: Mail -> DKIM -> PublicKey -> Bool
verifyDKIM mail dkim pub = bodyHash1 mail == bodyHash2 dkim &&
                           rsassa_pkcs1_v1_5_verify hashfunc pub cmail sig
  where
    hashfunc = hashAlgo1 (dkimSigAlgo dkim)
    hashfunc2 = hashAlgo2 (dkimSigAlgo dkim)
    sig = B.decode . dkimSignature $ dkim
    cmail = toLazyByteString (prepareDKIM dkim mail)
    bodyHash1 = hashfunc2 . toLazyByteString . canonDkimBody (dkimBodyCanon dkim) . mailBody
    bodyHash2 = B.decode . dkimBodyHash

hashAlgo1 :: DkimSigAlgo -> HashInfo
hashAlgo1 RSA_SHA1   = hashSHA1
hashAlgo1 RSA_SHA256 = hashSHA256

hashAlgo2 :: DkimSigAlgo -> BL.ByteString -> BL.ByteString
hashAlgo2 RSA_SHA1   = bytestringDigest . sha1
hashAlgo2 RSA_SHA256 = bytestringDigest . sha256
