{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Verify (
    verifyDKIM, prepareDKIM
  ) where

import Codec.Crypto.RSA
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Data.Digest.Pure.SHA
import Network.DomainAuth.DKIM.Btag
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.Mail
import qualified Network.DomainAuth.Pubkey.Base64 as B
import Network.DomainAuth.Utils

----------------------------------------------------------------

prepareDKIM :: DKIM -> Mail -> L.ByteString
prepareDKIM dkim mail = header
  where
    dkimField:fields = fieldsFrom dkimFieldKey (mailHeader mail)
    hCanon = canonDkimField (dkimHeaderCanon dkim)
    canon = removeBtagValue . hCanon
    targets = fieldsWith (dkimFields dkim) fields
    header = concatCRLFWith hCanon targets +++ canon dkimField

----------------------------------------------------------------

canonDkimField :: DkimCanonAlgo -> Field -> L.ByteString
canonDkimField DKIM_SIMPLE fld  = fieldKey fld +++ ": " +++ fieldValueFolded fld
canonDkimField DKIM_RELAXED fld = fieldSearchKey fld +++ ":" +++ canon fld
  where
    canon = L.dropWhile isSpace . removeTrailingWSP . reduceWSP . L.concat . fieldValue

----------------------------------------------------------------

canonDkimBody :: DkimCanonAlgo -> Body -> L.ByteString
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
    sig = B.decode (dkimSignature dkim)
    cmail = prepareDKIM dkim mail
    bodyHash1 = hashfunc2 . canonDkimBody (dkimBodyCanon dkim) . mailBody
    bodyHash2 = B.decode . dkimBodyHash

hashAlgo1 :: DkimSigAlgo -> HashInfo
hashAlgo1 RSA_SHA1   = ha_SHA1
hashAlgo1 RSA_SHA256 = ha_SHA256

hashAlgo2 :: DkimSigAlgo -> L.ByteString -> L.ByteString
hashAlgo2 RSA_SHA1   = bytestringDigest . sha1
hashAlgo2 RSA_SHA256 = bytestringDigest . sha256


