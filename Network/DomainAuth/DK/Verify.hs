{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DK.Verify (
    verifyDK, prepareDK, dkFieldKey
  ) where

import Codec.Crypto.RSA
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import qualified Data.Map as M
import Network.DomainAuth.DK.Types
import Network.DomainAuth.Mail
import Network.DomainAuth.Utils

----------------------------------------------------------------

dkFieldKey :: CanonFieldKey
dkFieldKey = "domainkey-signature"

----------------------------------------------------------------

prepareDK :: DK -> Mail -> L.ByteString
prepareDK dk mail = header' +++ crlf +++ body'
  where
    header' = canonDkHeader dk (mailHeader mail)
    body'   = canonDkBody (dkCanonAlgo dk) (mailBody mail)

----------------------------------------------------------------

canonDkHeader :: DK -> Header -> L.ByteString
canonDkHeader dk hdr = canonDkHeader' calgo flds
  where
    calgo = dkCanonAlgo dk
    hFields = dkFields dk
    flds = prepareDkHeader hFields hdr

prepareDkHeader :: Maybe DkFields -> Header -> [Field]
prepareDkHeader Nothing hdr = fieldsAfter dkFieldKey hdr
prepareDkHeader (Just hFields) hdr = fieldsAfterWith dkFieldKey isInHTag hdr
  where
    isInHTag k = M.member k hFields

canonDkHeader' :: DkCanonAlgo -> [Field] -> L.ByteString
canonDkHeader' DK_NOFWS  = canonDkHeaderCore removeFWS
canonDkHeader' DK_SIMPLE = canonDkHeaderCore removeLF
  where
    removeLF = L.init

canonDkHeaderCore :: FWSRemover -> [Field] -> L.ByteString
canonDkHeaderCore remover = foldr (op . remover) ""
  where
    a `op` b = a +++ crlf +++ b

----------------------------------------------------------------

canonDkBody :: DkCanonAlgo -> Body -> L.ByteString
canonDkBody DK_SIMPLE bs
  | slowPath bs = canonDkBodyCore id removeTrailingEmptyLine bs
  | otherwise   = canonDkBodyCore id id bs
canonDkBody DK_NOFWS bs
  | slowPath bs = canonDkBodyCore removeFWS removeTrailingEmptyLine bs
  | otherwise   = canonDkBodyCore removeFWS id bs

canonDkBodyCore :: FWSRemover -> TRLRemover -> Body -> L.ByteString
canonDkBodyCore remFWS remTEL = foldr op "" . remTEL . L.lines
  where
    a `op` b = remFWS a +++ crlf +++ b

----------------------------------------------------------------

type FWSRemover = L.ByteString -> L.ByteString

removeFWS :: FWSRemover
removeFWS = L.filter (not.isSpace)

type TRLRemover = [L.ByteString] -> [L.ByteString]

removeTrailingEmptyLine :: TRLRemover
removeTrailingEmptyLine = reverse . dropWhile (=="") . reverse

slowPath :: L.ByteString -> Bool
slowPath bs = bs !!! (len - 1) == '\n'
           && bs !!! (len - 2) == '\n'
  where
    len = L.length bs

----------------------------------------------------------------

verifyDK :: PublicKey -> L.ByteString -> L.ByteString -> Bool
verifyDK pub sig mail = rsassa_pkcs1_v1_5_verify ha_SHA1 pub mail sig
