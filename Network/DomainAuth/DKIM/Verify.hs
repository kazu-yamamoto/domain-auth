{-# LANGUAGE OverloadedStrings #-}

module Network.DomainAuth.DKIM.Verify (
    verifyDKIM, prepareDKIM, dkimFieldKey
  ) where

import Codec.Crypto.RSA
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.Mail
import Network.DomainAuth.Utils

----------------------------------------------------------------

dkimFieldKey :: CanonFieldKey
dkimFieldKey = "dkim-signature"

----------------------------------------------------------------

prepareDKIM :: DKIM -> Mail -> L.ByteString
prepareDKIM dkim mail = header' +++ crlf +++ body'
  where
    header' = canonDkimHeader dkim (mailHeader mail)
    body'   = canonDkimBody (dkimBodyCanon dkim) (mailBody mail)

----------------------------------------------------------------

canonDkimHeader :: DKIM -> Header -> L.ByteString
canonDkimHeader dkim hdr = canonDkimHeader' calgo flds
  where
    calgo = dkimHeaderCanon dkim
    hFields = dkimFields dkim
    flds = prepareDkimHeader hFields hdr

prepareDkimHeader = undefined
{-
prepareDkimHeader :: Maybe [L.ByteString] -> Header -> [Field]
prepareDkimHeader Nothing hdr = fieldsAfter dkimFieldkimey hdr
prepareDkimHeader (Just hFields) hdr = fieldsAfterWith dkimFieldkimey isInHTag hdr
  where
    isInHTag k = M.member k hFields
-}

canonDkimHeader' :: DkimCanonAlgo -> [Field] -> L.ByteString
canonDkimHeader' DKIM_RELAXED  = canonDkimHeaderCore removeFWS
canonDkimHeader' DKIM_SIMPLE = canonDkimHeaderCore removeLF
  where
    removeLF = L.init

canonDkimHeaderCore :: FWSRemover -> [Field] -> L.ByteString
canonDkimHeaderCore remover = foldr (op . remover) ""
  where
    a `op` b = a +++ crlf +++ b

----------------------------------------------------------------

canonDkimBody :: DkimCanonAlgo -> Body -> L.ByteString
canonDkimBody DKIM_SIMPLE bs
  | slowPath bs = canonDkimBodyCore id removeTrailingEmptyLine bs
  | otherwise   = canonDkimBodyCore id id bs
canonDkimBody DKIM_RELAXED bs
  | slowPath bs = canonDkimBodyCore removeFWS removeTrailingEmptyLine bs
  | otherwise   = canonDkimBodyCore removeFWS id bs

canonDkimBodyCore :: FWSRemover -> TRLRemover -> Body -> L.ByteString
canonDkimBodyCore remFWS remTEL = foldr op "" . remTEL . L.lines
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

verifyDKIM :: PublicKey -> L.ByteString -> L.ByteString -> Bool
verifyDKIM pub sig mail = rsassa_pkcs1_v1_5_verify ha_SHA1 pub mail sig
