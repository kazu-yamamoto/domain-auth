{-# LANGUAGE OverloadedStrings #-}

{-|
  A library for DKIM (<http://www.ietf.org/rfc/rfc4071>).
  Currently, only receiver side is implemented.
-}

module Network.DomainAuth.DKIM (
  -- * Documentation
  -- ** Authentication with DKIM
    runDKIM, runDKIM'
  -- ** Parsing DKIM-Signature:
  , parseDKIM
  , DKIM, dkimDomain, dkimSelector
  -- ** Field key for DKIM-Signature:
  , dkimFieldKey
  ) where

import qualified Data.ByteString as BS
import Network.DNS as DNS (Resolver)
import Network.DomainAuth.DKIM.Parser
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.DKIM.Verify
import Network.DomainAuth.Mail
import Network.DomainAuth.Pubkey.RSAPub
import Network.DomainAuth.Types

{-|
  Verifying 'Mail' with DKIM.
-}
runDKIM :: Resolver -> Mail -> IO DAResult
runDKIM resolver mail = dkim1
  where
    dkim1       = maybe (return DANone)      dkim2 $ lookupField dkimFieldKey (mailHeader mail)
    dkim2 dkimv = maybe (return DAPermError) dkim3 $ parseDKIM (fieldValueUnfolded dkimv)
    dkim3       = runDKIM' resolver mail

{-|
  Verifying 'Mail' with DKIM. The value of DKIM-Signature:
  should be parsed beforehand.
-}
runDKIM' :: Resolver -> Mail -> DKIM -> IO DAResult
runDKIM' resolver mail dkim = maybe DATempError (verify mail dkim) <$> pub
  where
    pub = lookupPublicKey resolver dom
    dom = dkimSelector dkim +++ "._domainkey." +++ dkimDomain dkim
    verify m d p = if verifyDKIM m d p then DAPass else DAFail
    (+++) = BS.append
