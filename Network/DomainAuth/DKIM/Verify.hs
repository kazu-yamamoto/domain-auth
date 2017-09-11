{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Verify (
    verifyDKIM, prepareDKIM
  ) where

import Blaze.ByteString.Builder
import Crypto.Hash
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Data.ByteArray
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
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
                           verify' (dkimSigAlgo dkim) pub cmail sig
  where
    sig = BL.toStrict $ B.decode . dkimSignature $ dkim
    cmail = toByteString $ prepareDKIM dkim mail
    bodyHash1 = hashAlgo2 (dkimSigAlgo dkim) . toByteString . canonDkimBody (dkimBodyCanon dkim) . mailBody
    bodyHash2 = BL.toStrict . B.decode . dkimBodyHash

verify' :: DkimSigAlgo-> PublicKey -> ByteString -> ByteString -> Bool
verify' RSA_SHA1   = verify (Just SHA1)
verify' RSA_SHA256 = verify (Just SHA256)

hashAlgo2 :: ByteArray c => DkimSigAlgo -> ByteString -> c
hashAlgo2 RSA_SHA1   = convert . (hash :: ByteString -> Digest SHA1)
hashAlgo2 RSA_SHA256 = convert . (hash :: ByteString -> Digest SHA256)

